"""Bounded OIDC relying-party protocol helpers.

Only trusted operator configuration chooses the issuer. Browser input never
selects discovery, token, or JWKS endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode, urlparse

import httpx
from authlib.common.errors import AuthlibBaseError
from authlib.oidc.core import CodeIDToken
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings
from agentguard_server.models import OidcLoginAttempt
from agentguard_server.services.rate_limit import database_now


class OidcProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class OidcMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True)
class OidcAuthorization:
    url: str
    state: str


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    display_name: str | None
    email: str | None


_metadata_cache: dict[str, tuple[float, OidcMetadata]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


def clear_oidc_cache() -> None:
    _metadata_cache.clear()
    _jwks_cache.clear()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def safe_return_to(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "://" in value:
        return "/ui"
    return value[:512]


def _trusted_endpoint(value: str, settings: Settings) -> bool:
    parsed = urlparse(value)
    common = bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    return common and (parsed.scheme == "https" or (
        settings.environment.strip().lower() == "test"
        and parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "host.docker.internal"}
    ))


async def _bounded_json(url: str, settings: Settings, transport: httpx.AsyncBaseTransport | None) -> dict:
    timeout = httpx.Timeout(settings.oidc_http_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport) as client:
            async with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise OidcProtocolError("OIDC provider request failed")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > settings.oidc_response_max_bytes:
                        raise OidcProtocolError("OIDC provider response was too large")
    except (httpx.HTTPError, TimeoutError) as exc:
        raise OidcProtocolError("OIDC provider unavailable") from exc
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OidcProtocolError("OIDC provider returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise OidcProtocolError("OIDC provider returned invalid metadata")
    return value


async def _bounded_post_json(url: str, data: dict[str, str], settings: Settings,
                             transport: httpx.AsyncBaseTransport | None) -> dict:
    timeout = httpx.Timeout(settings.oidc_http_timeout_seconds)
    auth = httpx.BasicAuth(settings.oidc_client_id or "", settings.oidc_client_secret) if settings.oidc_client_secret else None
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=transport) as client:
            async with client.stream("POST", url, data=data, auth=auth, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise OidcProtocolError("OIDC token exchange failed")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > settings.oidc_response_max_bytes:
                        raise OidcProtocolError("OIDC token response was too large")
    except (httpx.HTTPError, TimeoutError) as exc:
        raise OidcProtocolError("OIDC provider unavailable") from exc
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OidcProtocolError("OIDC token response was invalid") from exc
    if not isinstance(value, dict):
        raise OidcProtocolError("OIDC token response was invalid")
    return value


async def discover(settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> OidcMetadata:
    issuer = (settings.oidc_issuer or "").rstrip("/")
    if not _trusted_endpoint(issuer, settings):
        raise OidcProtocolError("OIDC issuer is not trusted")
    cached = _metadata_cache.get(issuer)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    raw = await _bounded_json(f"{issuer}/.well-known/openid-configuration", settings, transport)
    if raw.get("issuer") != issuer:
        raise OidcProtocolError("OIDC issuer metadata mismatch")
    endpoints = [raw.get("authorization_endpoint"), raw.get("token_endpoint"), raw.get("jwks_uri")]
    if not all(isinstance(item, str) and _trusted_endpoint(item, settings) for item in endpoints):
        raise OidcProtocolError("OIDC metadata contains an unsafe endpoint")
    issuer_host = urlparse(issuer).hostname
    if any(urlparse(item).hostname != issuer_host for item in endpoints):
        raise OidcProtocolError("OIDC metadata endpoint host was not trusted")
    metadata = OidcMetadata(issuer, endpoints[0], endpoints[1], endpoints[2])
    _metadata_cache[issuer] = (time.monotonic() + settings.oidc_jwks_cache_seconds, metadata)
    return metadata


async def _jwks(metadata: OidcMetadata, settings: Settings, transport: httpx.AsyncBaseTransport | None,
                force_refresh: bool = False) -> dict:
    cached = _jwks_cache.get(metadata.issuer)
    if not force_refresh and cached and cached[0] > time.monotonic():
        return cached[1]
    raw_jwks = await _bounded_json(metadata.jwks_uri, settings, transport)
    keys = raw_jwks.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= settings.oidc_jwks_max_keys:
        raise OidcProtocolError("OIDC JWKS was invalid")
    if any(not isinstance(key, dict) or key.get("kty") != "RSA" for key in keys):
        raise OidcProtocolError("OIDC JWKS key type was not allowed")
    value = {"keys": keys}
    _jwks_cache[metadata.issuer] = (time.monotonic() + settings.oidc_jwks_cache_seconds, value)
    return value


async def begin_login(db: Session, settings: Settings, return_to: str | None,
                      transport: httpx.AsyncBaseTransport | None = None) -> OidcAuthorization:
    if not settings.oidc_enabled or not settings.oidc_client_id or not settings.oidc_redirect_uri:
        raise OidcProtocolError("OIDC login is unavailable")
    metadata = await discover(settings, transport)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    now = database_now(db)
    db.add(OidcLoginAttempt(
        state_hash=_hash(state), nonce_hash=_hash(nonce), code_verifier=verifier,
        return_to=safe_return_to(return_to), created_at=now,
        expires_at=now + timedelta(seconds=settings.oidc_login_attempt_lifetime_seconds),
    ))
    db.commit()
    query = urlencode({
        "response_type": "code", "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri, "scope": "openid profile email",
        "state": state, "nonce": nonce, "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return OidcAuthorization(f"{metadata.authorization_endpoint}?{query}", state)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


async def complete_login(db: Session, settings: Settings, state: str | None, browser_state: str | None, code: str | None,
                         transport: httpx.AsyncBaseTransport | None = None) -> tuple[VerifiedIdentity, str]:
    if (not state or len(state) > 512 or not browser_state or len(browser_state) > 512
            or not secrets.compare_digest(state, browser_state) or not code or len(code) > 4096):
        raise OidcProtocolError("OIDC callback was invalid")
    attempt = db.scalar(select(OidcLoginAttempt).where(
        OidcLoginAttempt.state_hash == _hash(state),
    ).with_for_update())
    now = database_now(db)
    if attempt is None or attempt.used_at is not None or _utc(attempt.expires_at) <= now or not attempt.code_verifier:
        raise OidcProtocolError("OIDC state was invalid")
    verifier = attempt.code_verifier
    attempt.used_at = now
    attempt.code_verifier = None
    db.commit()

    metadata = await discover(settings, transport)
    token = await _bounded_post_json(metadata.token_endpoint, {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": settings.oidc_redirect_uri or "", "client_id": settings.oidc_client_id or "",
        "code_verifier": verifier,
    }, settings, transport)
    encoded = token.get("id_token")
    if not isinstance(encoded, str) or len(encoded) > settings.oidc_response_max_bytes:
        raise OidcProtocolError("OIDC ID token was missing")
    algorithms = [item.strip() for item in settings.oidc_allowed_algorithms.split(",") if item.strip()]
    try:
        try:
            decoded = jwt.decode(encoded, KeySet.import_key_set(await _jwks(metadata, settings, transport)), algorithms=algorithms)
        except JoseError:
            decoded = jwt.decode(encoded, KeySet.import_key_set(
                await _jwks(metadata, settings, transport, force_refresh=True)), algorithms=algorithms)
        audiences = [item.strip() for item in (settings.oidc_allowed_audiences or settings.oidc_client_id or "").split(",") if item.strip()]
        JWTClaimsRegistry(
            iss={"essential": True, "value": metadata.issuer},
            sub={"essential": True, "allow_blank": False},
            aud={"essential": True, "values": audiences},
            exp={"essential": True}, nbf={"essential": False}, iat={"essential": True},
            nonce={"essential": True, "allow_blank": False},
        ).validate(decoded.claims)
        CodeIDToken(decoded.claims, decoded.header, params={
            "client_id": settings.oidc_client_id,
            "access_token": token.get("access_token"),
        }).validate()
    except (JoseError, AuthlibBaseError, ValueError, TypeError, KeyError) as exc:
        raise OidcProtocolError("OIDC ID token validation failed") from exc
    nonce = decoded.claims.get("nonce")
    if not isinstance(nonce, str) or not secrets.compare_digest(_hash(nonce), attempt.nonce_hash):
        raise OidcProtocolError("OIDC nonce validation failed")
    subject = decoded.claims.get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise OidcProtocolError("OIDC subject was invalid")
    required_claims = {item.strip() for item in settings.oidc_required_claims.split(",") if item.strip()}
    if any(decoded.claims.get(item) in (None, "") for item in required_claims):
        raise OidcProtocolError("OIDC required claim was missing")
    name = decoded.claims.get("name")
    email = decoded.claims.get("email")
    safe_name = name[:255] if isinstance(name, str) else None
    safe_email = email[:320] if isinstance(email, str) else None
    return VerifiedIdentity(metadata.issuer, subject, safe_name, safe_email), attempt.return_to
