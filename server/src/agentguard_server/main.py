from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import logging
import threading
from pathlib import Path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentguard_server.api.routes import router
from agentguard_server.api.dashboard import router as dashboard_router
from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.db.session import dispose_engine, get_session_factory
from agentguard_server.provenance import read_version
from agentguard_server.services.anchoring import run_anchor_cycle

app = FastAPI(title="AgentGuard", version=read_version())
app.include_router(router)
app.include_router(dashboard_router)
app.mount("/ui/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="ui-static")
logger = logging.getLogger("agentguard.server")


class RequestTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Reject oversized bodies while they are received, before full buffering."""

    def __init__(self, app: ASGIApp, limit: int) -> None:
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length and content_length.isdigit() and int(content_length) > self.limit:
            await self._too_large(send)
            return
        seen = 0

        async def limited_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.limit:
                    raise RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestTooLarge:
            await self._too_large(send)

    async def _too_large(self, send: Send) -> None:
        body = b'{"detail":"request body too large"}'
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


app.add_middleware(RequestSizeLimitMiddleware, limit=get_settings().request_max_bytes)
_anchor_stop = threading.Event()
_anchor_thread: threading.Thread | None = None


def _anchor_loop() -> None:
    settings = get_settings()
    while not _anchor_stop.wait(min(settings.anchor_interval_seconds, 5)):
        db = get_session_factory()()
        try:
            run_anchor_cycle(db, settings=settings)
        except Exception as exc:
            logger.error("anchor_cycle_failed reason=%s", type(exc).__name__)
        finally:
            db.close()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    if request.url.path.startswith("/ui"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def safe_internal_error(request: Request, exc: Exception):
    route = request.scope.get("route")
    route_path = getattr(route, "path", "<unmatched>")
    logger.error("internal_error method=%s route=%s exception=%s", request.method, route_path, type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "internal server error"})


@app.on_event("startup")
def validate_security_configuration() -> None:
    try:
        validate_configuration(get_settings())
    except Exception as exc:
        logger.error("configuration_invalid reason=%s", type(exc).__name__)
        raise RuntimeError("invalid AgentGuard startup configuration") from exc
    global _anchor_thread
    if get_settings().anchor_enabled:
        _anchor_stop.clear()
        _anchor_thread = threading.Thread(target=_anchor_loop, name="agentguard-anchor", daemon=True)
        _anchor_thread.start()


@app.on_event("shutdown")
def graceful_shutdown() -> None:
    logger.info("shutdown_started")
    _anchor_stop.set()
    if _anchor_thread is not None:
        _anchor_thread.join(timeout=get_settings().shutdown_timeout_seconds)
    dispose_engine()
    logger.info("shutdown_complete")

