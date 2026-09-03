"""V12 live acceptance against the running PostgreSQL/FastAPI stack."""

from datetime import datetime, timezone
import os
import re
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import Tenant
from agentguard_server.services.auth import create_api_key, create_tenant, revoke_api_key


@pytest.fixture()
def v12_live_context():
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V12 live acceptance")
    engine = create_engine(database_url, future=True, pool_pre_ping=True)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    tenant_ids = []
    try:
        tenant_a = create_tenant(db, f"v12-a-{uuid4().hex[:12]}", "V12 temporary tenant A")
        tenant_b = create_tenant(db, f"v12-b-{uuid4().hex[:12]}", "V12 temporary tenant B")
        tenant_ids.extend([tenant_a.id, tenant_b.id])
        pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
        scopes = ["dashboard:access", "ingest:write", "traces:read", "analysis:run", "incidents:read", "incidents:manage"]
        _, key_a = create_api_key(db, tenant_a, scopes, "v12-a", pepper)
        _, key_b = create_api_key(db, tenant_b, scopes, "v12-b", pepper)
        yield {"db": db, "a": tenant_a, "b": tenant_b, "key_a": key_a, "key_b": key_b}
    finally:
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
        db.commit()
        db.close()
        engine.dispose()


def _csrf(body: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert match
    return match.group(1)


def _events(trace_id: str, workflow: str) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    return [
        {"event_type": "trace.started", "event_id": f"start-{trace_id}", "occurred_at": now, "data": {"trace_id": trace_id, "workflow_name": workflow, "status": "running"}},
        {"event_type": "span.started", "event_id": f"span-{trace_id}", "occurred_at": now, "data": {"trace_id": trace_id, "span_id": f"span-{trace_id}", "span_type": "tool", "name": "tool"}},
        {"event_type": "span.ended", "event_id": f"end-span-{trace_id}", "occurred_at": now, "data": {"trace_id": trace_id, "span_id": f"span-{trace_id}", "status": "error", "error_type": "TimeoutError"}},
        {"event_type": "trace.ended", "event_id": f"end-{trace_id}", "occurred_at": now, "data": {"trace_id": trace_id, "status": "error"}},
    ]


def test_live_dashboard_session_csrf_xss_tenant_boundary_and_incident_action(v12_live_context):
    ctx = v12_live_context
    base_url = os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000")
    with httpx.Client(base_url=base_url, follow_redirects=False, timeout=10,
                      headers={"Authorization": f"Bearer {ctx['key_a']}"}) as api_a, httpx.Client(
                          base_url=base_url, follow_redirects=False, timeout=10,
                          headers={"Authorization": f"Bearer {ctx['key_b']}"}) as api_b:
        login = api_a.post("/ui/login", data={"api_key": ctx["key_a"], "next": "/ui"})
        assert login.status_code == 303 and login.headers["location"] == "/ui"
        assert ctx["key_a"] not in login.text
        cookie = login.headers.get("set-cookie", "").lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
        home = api_a.get("/ui")
        assert home.status_code == 200
        assert home.headers["Cache-Control"] == "no-store"
        assert "script-src 'self'" in home.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in home.headers["Content-Security-Policy"]
        assert ctx["key_a"] not in home.text

        trace_a = f"v12-a-{uuid4().hex}"
        trace_b = f"v12-b-{uuid4().hex}"
        assert api_a.post("/v1/ingest", json={"events": _events(trace_a, "timeout-workflow")}).status_code == 202
        assert api_b.post("/v1/ingest", json={"events": _events(trace_b, "<script>alert(1)</script>")}).status_code == 202
        analysis = api_a.post(f"/v1/traces/{trace_a}/analysis", json={"mode": "deterministic"})
        assert analysis.status_code == 200
        incidents = api_a.get("/v1/incidents")
        assert incidents.status_code == 200 and incidents.json()
        incident_id = incidents.json()[0]["id"]

        assert api_a.get(f"/ui/traces/{trace_b}").status_code == 404
        assert api_a.post(f"/ui/incidents/{incident_id}/acknowledge", data={}).status_code == 403
        csrf = _csrf(api_a.get("/ui").text)
        changed = api_a.post(f"/ui/incidents/{incident_id}/acknowledge", data={"csrf_token": csrf})
        assert changed.status_code == 303
        assert api_a.get(f"/v1/incidents/{incident_id}").json()["status"] == "ACKNOWLEDGED"

        login_b = api_b.post("/ui/login", data={"api_key": ctx["key_b"]})
        assert login_b.status_code == 303
        rendered = api_b.get("/ui/traces").text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
        assert "<script>alert(1)</script>" not in rendered

        revoke_api_key(ctx["db"], ctx["key_a"].split("_")[1])
        assert api_a.get("/ui", follow_redirects=False).status_code == 303
