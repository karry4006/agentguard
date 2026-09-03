"""V13 live OIDC, organization RBAC, and PostgreSQL acceptance."""

from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid4

import httpx
from joserfc import jwt
from joserfc.jwk import RSAKey
import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

from agentguard_server.models import (
    HumanUser, IdentityAuditEvent, OidcLoginAttempt, Organization,
    OrganizationMembership, Tenant,
)
from agentguard_server.services.auth import create_api_key, create_tenant, utc_now


class _LiveIssuerHandler(BaseHTTPRequestHandler):
    issuer = ""
    key = RSAKey.generate_key(2048, {"kid": "v13-live-k1"})
    nonce = ""
    challenge = ""
    subject = "v13-live-human"

    def _json(self, value: dict) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/openid-configuration":
            self._json({
                "issuer": self.issuer,
                "authorization_endpoint": f"{self.issuer}/authorize",
                "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks",
            })
            return
        if parsed.path == "/jwks":
            self._json({"keys": [self.key.as_dict(private=False)]})
            return
        if parsed.path == "/authorize":
            params = parse_qs(parsed.query)
            assert params["response_type"] == ["code"]
            assert params["client_id"] == ["agentguard-v13-live"]
            assert params["code_challenge_method"] == ["S256"]
            self.__class__.nonce = params["nonce"][0]
            self.__class__.challenge = params["code_challenge"][0]
            callback = params["redirect_uri"][0] + "?" + urlencode({
                "code": "v13-live-code", "state": params["state"][0],
            })
            self.send_response(302)
            self.send_header("Location", callback)
            self.end_headers()
            return
        self.send_error(404)

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if urlparse(self.path).path != "/token":
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        assert 0 < size <= 16384
        form = parse_qs(self.rfile.read(size).decode("ascii"))
        assert form["grant_type"] == ["authorization_code"]
        assert form["code"] == ["v13-live-code"]
        assert form["client_id"] == ["agentguard-v13-live"]
        verifier = form["code_verifier"][0]
        actual = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        assert actual == self.challenge
        now = int(time.time())
        encoded = jwt.encode(
            {"alg": "RS256", "kid": "v13-live-k1"},
            {"iss": self.issuer, "sub": self.subject, "aud": "agentguard-v13-live",
             "iat": now, "exp": now + 300, "nonce": self.nonce,
             "name": "<script>V13 Operator</script>"},
            self.key, algorithms=["RS256"],
        )
        self._json({"id_token": encoded, "access_token": "test-access-token", "token_type": "Bearer"})

    def log_message(self, _format, *_args):
        return


def _csrf(body: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"\s]+)"', body)
    assert match
    return match.group(1)


def _oidc_login(browser: httpx.Client, subject: str, issuer_port: int) -> httpx.Response:
    _LiveIssuerHandler.subject = subject
    authorization = browser.get("/ui/oidc/login?next=//attacker.invalid")
    assert authorization.status_code == 303
    local_authorization = authorization.headers["location"].replace(
        _LiveIssuerHandler.issuer, f"http://127.0.0.1:{issuer_port}", 1)
    provider = httpx.get(local_authorization, follow_redirects=False, timeout=10)
    assert provider.status_code == 302
    callback = urlparse(provider.headers["location"])
    return browser.get(callback.path + "?" + callback.query)


@pytest.fixture()
def v13_live_context():
    database_url = os.getenv("AGENTGUARD_TEST_DATABASE_URL", "")
    issuer = os.getenv("AGENTGUARD_TEST_OIDC_ISSUER", "")
    pepper = os.getenv("AGENTGUARD_KEY_PEPPER", "")
    if not database_url.startswith(("postgresql", "postgres")) or not issuer or not pepper:
        pytest.skip("V13 PostgreSQL, OIDC issuer, and pepper test configuration are required")
    parsed_issuer = urlparse(issuer)
    assert parsed_issuer.hostname == "host.docker.internal" and parsed_issuer.port
    _LiveIssuerHandler.issuer = issuer.rstrip("/")
    server = ThreadingHTTPServer(("0.0.0.0", parsed_issuer.port), _LiveIssuerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    engine = create_engine(database_url, future=True, pool_pre_ping=True)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    tenant_ids = []
    user_ids = []
    started = datetime.now(timezone.utc)
    try:
        tenant_a = create_tenant(db, f"v13-a-{uuid4().hex[:12]}", "V13 Organization A")
        tenant_b = create_tenant(db, f"v13-b-{uuid4().hex[:12]}", "V13 Organization B")
        tenant_ids.extend([tenant_a.id, tenant_b.id])
        now = utc_now()
        user = HumanUser(external_issuer=_LiveIssuerHandler.issuer, external_subject="v13-live-human",
                         display_name="Provisioned V13 Operator", created_at=now, updated_at=now)
        viewer = HumanUser(external_issuer=_LiveIssuerHandler.issuer, external_subject="v13-live-viewer",
                           display_name="V13 Viewer", created_at=now, updated_at=now)
        engineer = HumanUser(external_issuer=_LiveIssuerHandler.issuer, external_subject="v13-live-engineer",
                             display_name="V13 Engineer", created_at=now, updated_at=now)
        db.add_all([user, viewer, engineer])
        db.flush()
        user_ids.extend([user.id, viewer.id, engineer.id])
        org_a = Organization(tenant_id=tenant_a.id, name="V13 Organization A", created_at=now, updated_at=now)
        org_b = Organization(tenant_id=tenant_b.id, name="V13 Organization B", created_at=now, updated_at=now)
        db.add_all([org_a, org_b])
        db.flush()
        membership_a = OrganizationMembership(organization_id=org_a.id, user_id=user.id, role="ADMIN",
                                               created_at=now, updated_at=now)
        membership_b = OrganizationMembership(organization_id=org_b.id, user_id=user.id, role="VIEWER",
                                               created_at=now, updated_at=now)
        viewer_membership = OrganizationMembership(organization_id=org_a.id, user_id=viewer.id, role="VIEWER",
                                                   created_at=now, updated_at=now)
        engineer_membership = OrganizationMembership(organization_id=org_a.id, user_id=engineer.id, role="ENGINEER",
                                                     created_at=now, updated_at=now)
        db.add_all([membership_a, membership_b, viewer_membership, engineer_membership])
        machine_scopes = ["dashboard:access", "ingest:write", "traces:read"]
        _, key_a = create_api_key(db, tenant_a, machine_scopes, "v13-machine-a", pepper)
        _, key_b = create_api_key(db, tenant_b, machine_scopes, "v13-machine-b", pepper)
        db.commit()
        yield {"db": db, "a": tenant_a, "b": tenant_b, "org_a": org_a, "org_b": org_b,
               "user": user, "membership_a": membership_a, "membership_b": membership_b,
               "viewer_membership": viewer_membership, "engineer_membership": engineer_membership,
               "key_a": key_a, "key_b": key_b, "issuer_port": parsed_issuer.port}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
        db.execute(delete(HumanUser).where(
            HumanUser.external_issuer == _LiveIssuerHandler.issuer,
            HumanUser.external_subject.like("v13-%"),
        ))
        db.execute(delete(OidcLoginAttempt).where(OidcLoginAttempt.created_at >= started))
        db.commit()
        db.close()
        engine.dispose()


def _events(trace_id: str, workflow: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {"events": [
        {"event_type": "trace.started", "event_id": f"start-{workflow}", "occurred_at": now,
         "data": {"trace_id": trace_id, "workflow_name": workflow, "status": "running"}},
        {"event_type": "trace.ended", "event_id": f"end-{workflow}", "occurred_at": now,
         "data": {"trace_id": trace_id, "status": "success"}},
    ]}


def test_v13_live_oidc_multi_org_rbac_runtime_privileges_and_cleanup(v13_live_context):
    ctx = v13_live_context
    base_url = os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000")
    trace_id = f"v13-shared-{uuid4().hex}"
    with httpx.Client(base_url=base_url, follow_redirects=False, timeout=15) as browser, httpx.Client(
            base_url=base_url, follow_redirects=False, timeout=15) as viewer_browser, httpx.Client(
            base_url=base_url, follow_redirects=False, timeout=15) as engineer_browser:
        assert browser.get("/health").status_code == 200
        with httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {ctx['key_a']}"}) as api_a:
            assert api_a.post("/v1/ingest", json=_events(trace_id, "V13-A-workflow")).status_code == 202
            assert api_a.get(f"/v1/traces/{trace_id}").json()["trace"]["workflow_name"] == "V13-A-workflow"
        with httpx.Client(base_url=base_url, headers={"Authorization": f"Bearer {ctx['key_b']}"}) as api_b:
            assert api_b.post("/v1/ingest", json=_events(trace_id, "V13-B-workflow")).status_code == 202
            assert api_b.get(f"/v1/traces/{trace_id}").json()["trace"]["workflow_name"] == "V13-B-workflow"

        with httpx.Client(base_url=base_url, follow_redirects=False, timeout=15) as machine_browser:
            machine_login = machine_browser.post("/ui/login", data={"api_key": ctx["key_a"]})
            assert machine_login.status_code == 303 and machine_login.headers["location"] == "/ui"
            assert "agentguard_session" in machine_login.cookies
            assert machine_browser.get("/ui").status_code == 200
            assert machine_browser.get("/ui/organization").status_code == 403
        viewer_login = _oidc_login(viewer_browser, "v13-live-viewer", ctx["issuer_port"])
        engineer_login = _oidc_login(engineer_browser, "v13-live-engineer", ctx["issuer_port"])
        assert viewer_login.status_code == 303 and viewer_login.headers["location"] == "/ui"
        assert engineer_login.status_code == 303 and engineer_login.headers["location"] == "/ui"
        viewer_denied = viewer_browser.post(
            "/ui/incidents/00000000-0000-0000-0000-000000000001/acknowledge",
            data={"csrf_token": _csrf(viewer_browser.get("/ui").text)},
        )
        engineer_allowed = engineer_browser.post(
            "/ui/incidents/00000000-0000-0000-0000-000000000001/acknowledge",
            data={"csrf_token": _csrf(engineer_browser.get("/ui").text)},
        )
        assert viewer_denied.status_code == 403
        assert engineer_allowed.status_code == 404
        assert engineer_browser.get("/ui/organization/members").status_code == 403

        completed = _oidc_login(browser, "v13-live-human", ctx["issuer_port"])
        assert completed.status_code == 303 and completed.headers["location"] == "/ui/organization/select"
        assert "httponly" in completed.headers["set-cookie"].lower()

        selection = browser.get("/ui/organization/select")
        assert selection.status_code == 200 and "V13 Organization A" in selection.text and "V13 Organization B" in selection.text
        assert "<script>V13 Operator</script>" not in selection.text
        selected_a = browser.post("/ui/organization/select", data={
            "csrf_token": _csrf(selection.text), "organization_id": str(ctx["org_a"].id),
        })
        assert selected_a.status_code == 303
        home_a = browser.get("/ui")
        assert "V13 Organization A" in home_a.text and "ADMIN" in home_a.text
        trace_a = browser.get(f"/ui/traces/{trace_id}")
        assert trace_a.status_code == 200 and "V13-A-workflow" in trace_a.text and "V13-B-workflow" not in trace_a.text

        members = browser.get("/ui/organization/members")
        last_admin = browser.post(f"/ui/organization/members/{ctx['membership_a'].id}/role", data={
            "csrf_token": _csrf(members.text), "role": "VIEWER",
        })
        assert last_admin.status_code == 409
        disabled_viewer = browser.post(f"/ui/organization/members/{ctx['viewer_membership'].id}/disable", data={
            "csrf_token": _csrf(browser.get("/ui/organization/members").text),
        })
        assert disabled_viewer.status_code == 303
        assert viewer_browser.get("/ui").status_code == 303
        demoted_engineer = browser.post(f"/ui/organization/members/{ctx['engineer_membership'].id}/role", data={
            "csrf_token": _csrf(browser.get("/ui/organization/members").text), "role": "VIEWER",
        })
        assert demoted_engineer.status_code == 303
        stale_engineer = engineer_browser.post(
            "/ui/incidents/00000000-0000-0000-0000-000000000001/acknowledge",
            data={"csrf_token": _csrf(engineer_browser.get("/ui").text)},
        )
        assert stale_engineer.status_code == 403
        add_admin = browser.post("/ui/organization/members", data={
            "csrf_token": _csrf(members.text), "subject": "v13-second-admin",
            "display_name": "Second Admin", "role": "ADMIN",
        })
        assert add_admin.status_code == 303
        demoted = browser.post(f"/ui/organization/members/{ctx['membership_a'].id}/role", data={
            "csrf_token": _csrf(browser.get("/ui/organization/members").text), "role": "VIEWER",
        })
        assert demoted.status_code == 303
        assert browser.post("/ui/organization/members", data={}).status_code == 403

        selection = browser.get("/ui/organization/select")
        selected_b = browser.post("/ui/organization/select", data={
            "csrf_token": _csrf(selection.text), "organization_id": str(ctx["org_b"].id),
        })
        assert selected_b.status_code == 303
        trace_b = browser.get(f"/ui/traces/{trace_id}")
        assert trace_b.status_code == 200 and "V13-B-workflow" in trace_b.text and "V13-A-workflow" not in trace_b.text

    db = ctx["db"]
    assert db.scalar(text("SELECT version_num FROM alembic_version")) == "0015_archive_replica_resilience"
    role = db.execute(text("SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication FROM pg_roles WHERE rolname='agentguard_runtime'" )).one()
    assert role == (False, False, False, False)
    assert db.scalar(text("SELECT has_schema_privilege('agentguard_runtime','public','CREATE')")) is False
    assert db.scalar(text("SELECT has_database_privilege('agentguard_runtime', current_database(), 'CREATE')")) is False
    assert db.scalar(text("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE u.rolname='agentguard_runtime' AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb)")) == 0
    assert db.scalar(text("SELECT count(*) FROM pg_stat_activity WHERE usename='agentguard_runtime'")) >= 1
    assert db.scalar(select(IdentityAuditEvent).where(IdentityAuditEvent.event_type == "human_login_success")) is not None

