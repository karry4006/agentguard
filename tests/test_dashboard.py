from datetime import datetime, timezone
import os
import re
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from agentguard_server.api.routes import db_session as api_db_session
from agentguard_server.main import app
from agentguard_server.models import DashboardSession, Incident, Trace
from agentguard_server.services.auth import create_api_key, create_tenant, revoke_api_key


def _ui_client(db, key: str) -> TestClient:
    def override():
        yield db
    app.dependency_overrides[api_db_session] = override
    return TestClient(app, raise_server_exceptions=False)


def _operator(db, *scopes: str):
    tenant = create_tenant(db, f"ui-{uuid4().hex[:12]}", "UI tenant")
    _, key = create_api_key(db, tenant, {"dashboard:access", *scopes}, "ui-operator",
                             os.environ.get("AGENTGUARD_KEY_PEPPER", "test-only-agentguard-pepper"))
    return tenant, key


def _csrf(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def test_dashboard_login_stores_only_hashes_and_uses_opaque_cookie(db_session):
    _, key = _operator(db_session, "traces:read")
    client = _ui_client(db_session, key)
    try:
        response = client.post("/ui/login", data={"api_key": key, "next": "/ui"}, follow_redirects=False)
        assert response.status_code == 303
        assert key not in response.text
        cookie = client.cookies.get("agentguard_session")
        assert cookie and len(cookie) >= 32
        session = db_session.scalar(select(DashboardSession))
        assert session and session.session_token_hash != cookie
        page = client.get("/ui")
        assert page.status_code == 200
        assert "OPERATOR CONSOLE" in page.text
        assert "Cache-Control" in page.headers and page.headers["Cache-Control"] == "no-store"
    finally:
        app.dependency_overrides.clear()


def test_dashboard_requires_scope_and_session_fixation_is_rejected(db_session):
    _, key = _operator(db_session, "traces:read")
    client = _ui_client(db_session, key)
    try:
        client.cookies.set("agentguard_session", "attacker-controlled-session")
        denied = client.get("/ui", follow_redirects=False)
        assert denied.status_code == 303
        response = client.post("/ui/login", data={"api_key": key}, follow_redirects=False)
        assert response.status_code == 303
        assert client.get("/ui").status_code == 200
        no_scope_tenant = create_tenant(db_session, f"ui-{uuid4().hex[:12]}", "No dashboard tenant")
        _, no_scope_key = create_api_key(db_session, no_scope_tenant, [], "no-dashboard",
                                         os.environ.get("AGENTGUARD_KEY_PEPPER", "test-only-agentguard-pepper"))
        no_scope_client = _ui_client(db_session, no_scope_key)
        denied_login = no_scope_client.post("/ui/login", data={"api_key": no_scope_key}, follow_redirects=False)
        assert denied_login.status_code == 303
        assert denied_login.headers["location"] == "/ui/login?error=invalid_credentials"
    finally:
        app.dependency_overrides.clear()


def test_api_key_revocation_and_logout_invalidate_dashboard_session(db_session):
    _, key = _operator(db_session, "traces:read")
    client = _ui_client(db_session, key)
    try:
        client.post("/ui/login", data={"api_key": key}, follow_redirects=False)
        page = client.get("/ui")
        csrf = _csrf(page)
        session = db_session.scalar(select(DashboardSession))
        assert session
        assert client.post("/ui/logout", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
        assert db_session.get(DashboardSession, session.id).revoked_at is not None
        client.post("/ui/login", data={"api_key": key}, follow_redirects=False)
        revoke_api_key(db_session, key.split("_")[1].split("_")[0])
        assert client.get("/ui", follow_redirects=False).status_code == 303
    finally:
        app.dependency_overrides.clear()


def test_dashboard_csrf_xss_and_tenant_isolation(db_session):
    tenant_a, key_a = _operator(db_session, "traces:read", "incidents:read", "incidents:manage")
    tenant_b, key_b = _operator(db_session, "traces:read")
    trace_id = f"ui-trace-{uuid4().hex}"
    db_session.add(Trace(tenant_id=tenant_b.id, trace_id=trace_id, workflow_name="<script>alert(1)</script>",
                         status="failed", metadata_json={"payload": "<img src=x onerror=alert(1)>"},
                         started_at=datetime.now(timezone.utc), schema_version="0.1"))
    incident = Incident(tenant_id=tenant_a.id, fingerprint=uuid4().hex, fingerprint_version="v1",
                        title="<svg onload=alert(1)>", status="OPEN", severity="HIGH",
                        severity_policy_version="severity-v1", primary_category="TIMEOUT", dimensions={},
                        occurrence_count=0, affected_trace_count=0, first_seen_at=datetime.now(timezone.utc),
                        last_seen_at=datetime.now(timezone.utc), created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc))
    db_session.add(incident)
    db_session.commit()
    client_a = _ui_client(db_session, key_a)
    client_b = _ui_client(db_session, key_b)
    try:
        client_a.post("/ui/login", data={"api_key": key_a}, follow_redirects=False)
        assert client_a.get(f"/ui/traces/{trace_id}").status_code == 404
        client_b.post("/ui/login", data={"api_key": key_b}, follow_redirects=False)
        rendered = client_b.get("/ui/traces").text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
        assert "<script>alert(1)</script>" not in rendered
        missing_csrf = client_a.post(f"/ui/incidents/{incident.id}/acknowledge", data={})
        assert missing_csrf.status_code == 403
        assert db_session.get(Incident, incident.id).status == "OPEN"
        csrf = _csrf(client_a.get("/ui"))
        changed = client_a.post(f"/ui/incidents/{incident.id}/acknowledge", data={"csrf_token": csrf}, follow_redirects=False)
        assert changed.status_code == 303
        assert db_session.get(Incident, incident.id).status == "ACKNOWLEDGED"
    finally:
        app.dependency_overrides.clear()


def test_dashboard_security_headers_and_get_does_not_mutate(db_session):
    _, key = _operator(db_session, "incidents:read", "incidents:manage")
    client = _ui_client(db_session, key)
    try:
        response = client.get("/ui/login")
        assert response.status_code == 200
        assert "Content-Security-Policy" in response.headers
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Permissions-Policy"]
        assert client.get("/ui/logout").status_code in {404, 405}
    finally:
        app.dependency_overrides.clear()
