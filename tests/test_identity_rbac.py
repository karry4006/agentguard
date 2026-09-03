import base64
import hashlib
import json
import re
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
import pytest
from sqlalchemy import select

from agentguard_server.config import Settings, get_settings, validate_configuration
from agentguard_server import cli as server_cli
from agentguard_server.main import app
from agentguard_server.models import ApiKey, HumanUser, OidcLoginAttempt, Organization, OrganizationMembership, Tenant, Trace
from agentguard_server.services.auth import create_api_key, utc_now
from agentguard_server.services.dashboard import allow_login
from agentguard_server.services.oidc import clear_oidc_cache


def _oidc_settings(monkeypatch):
    clear_oidc_cache()
    monkeypatch.setenv("AGENTGUARD_OIDC_ENABLED", "true")
    monkeypatch.setenv("AGENTGUARD_OIDC_ISSUER", "https://idp.example")
    monkeypatch.setenv("AGENTGUARD_OIDC_CLIENT_ID", "agentguard-dashboard")
    monkeypatch.setenv("AGENTGUARD_OIDC_REDIRECT_URI", "https://agentguard.example/ui/oidc/callback")
    monkeypatch.setenv("AGENTGUARD_OIDC_ALLOWED_AUDIENCES", "agentguard-dashboard")
    monkeypatch.setenv("AGENTGUARD_DASHBOARD_LOGIN_RATE_LIMIT", "1000")
    get_settings.cache_clear()


def _validation_settings(environment: str, issuer: str, redirect: str) -> Settings:
    return Settings(
        _env_file=None,
        database_url="sqlite:///test.db",
        environment=environment,
        key_pepper="test-only-agentguard-pepper",
        integrity_key="test-only-agentguard-integrity-key-32-bytes!!",
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id="agentguard-dashboard",
        oidc_redirect_uri=redirect,
    )


def test_test_http_oidc_exception_is_narrow_and_never_applies_to_production():
    validate_configuration(_validation_settings(
        "test", "http://host.docker.internal:18765", "http://127.0.0.1:8000/ui/oidc/callback",
    ))
    with pytest.raises(ValueError):
        validate_configuration(_validation_settings(
            "production", "http://host.docker.internal:18765", "http://127.0.0.1:8000/ui/oidc/callback",
        ))
    with pytest.raises(ValueError):
        validate_configuration(_validation_settings(
            "test", "http://metadata.internal", "http://127.0.0.1:8000/ui/oidc/callback",
        ))
    with pytest.raises(ValueError):
        validate_configuration(_validation_settings(
            "test", "http://host.docker.internal:18765", "http://attacker.internal/ui/oidc/callback",
        ))


def _login_human(web: TestClient, subject: str, name: str = "Operator"):
    issuer = _TestIssuer(subject=subject, name=name)
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        authorization = web.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        return web.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
    finally:
        del app.state.oidc_transport


def _csrf(web: TestClient) -> str:
    page = web.get("/ui")
    match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', page.text)
    assert match
    return match.group(1)


class _TestIssuer:
    def __init__(self, subject="human-123", name="Alice Operator", email="alice@example.test"):
        self.key = RSAKey.generate_key(2048, {"kid": "test-k1"})
        self.subject = subject
        self.name = name
        self.email = email
        self.nonce = None
        self.challenge = None
        self.token_requests = 0
        self.claim_overrides = {}
        self.signing_key = self.key
        self.token_mode = "signed"

    def remember_authorization(self, location: str) -> tuple[str, str]:
        params = parse_qs(urlparse(location).query)
        self.nonce = params["nonce"][0]
        self.challenge = params["code_challenge"][0]
        return params["state"][0], self.nonce

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": "https://idp.example",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "jwks_uri": "https://idp.example/jwks",
            })
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if request.url.path == "/token":
            self.token_requests += 1
            form = parse_qs(request.content.decode("ascii"))
            verifier = form["code_verifier"][0]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
            assert challenge == self.challenge
            now = int(time.time())
            claims = {"iss": "https://idp.example", "sub": self.subject, "aud": "agentguard-dashboard",
                      "iat": now, "exp": now + 300, "nonce": self.nonce,
                      "name": self.name, "email": self.email}
            claims.update(self.claim_overrides)
            if self.token_mode == "none":
                head = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "test-k1"}).encode()).rstrip(b"=").decode()
                body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
                id_token = f"{head}.{body}."
            else:
                id_token = jwt.encode(
                    {"alg": "RS256", "kid": self.signing_key.as_dict().get("kid")}, claims,
                    self.signing_key, algorithms=["RS256"],
                )
            return httpx.Response(200, json={"id_token": id_token, "access_token": "discard-me", "token_type": "Bearer"})
        return httpx.Response(404)


def test_oidc_login_uses_authorization_code_pkce_state_nonce_and_safe_return(client, monkeypatch):
    _oidc_settings(monkeypatch)

    def issuer(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://idp.example/.well-known/openid-configuration"
        return httpx.Response(200, json={
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
        })

    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        response = client.get("/ui/oidc/login?next=https://attacker.example/steal", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        get_settings.cache_clear()

    assert response.status_code == 303
    target = urlparse(response.headers["location"])
    params = parse_qs(target.query)
    assert (target.scheme, target.netloc, target.path) == ("https", "idp.example", "/authorize")
    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["agentguard-dashboard"]
    assert params["redirect_uri"] == ["https://agentguard.example/ui/oidc/callback"]
    assert params["scope"] == ["openid profile email"]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["code_challenge"][0]) >= 43
    assert len(params["state"][0]) >= 32
    assert len(params["nonce"][0]) >= 32
    assert "attacker.example" not in response.headers["location"]


def test_oidc_callback_validates_signed_identity_but_denies_unknown_human(client, monkeypatch):
    _oidc_settings(monkeypatch)
    issuer = _TestIssuer()
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        authorization = client.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        response = client.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
        replay = client.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        get_settings.cache_clear()

    assert response.status_code == 403
    assert response.text == "access denied"
    assert "discard-me" not in response.text
    assert "agentguard_session" not in response.cookies
    assert replay.status_code == 403
    assert issuer.token_requests == 1


def test_oidc_callback_rejects_unknown_state_before_token_exchange(client, monkeypatch):
    _oidc_settings(monkeypatch)
    issuer = _TestIssuer()
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        response = client.get("/ui/oidc/callback?code=valid-code&state=wrong-state", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        get_settings.cache_clear()

    assert response.status_code == 403
    assert issuer.token_requests == 0


def test_provisioned_viewer_gets_human_session_read_access_but_not_mutation(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    user = HumanUser(external_issuer="https://idp.example", external_subject="viewer-123",
                     display_name="Provisioned viewer", email=None, created_at=now, updated_at=now)
    organization = Organization(tenant_id=tenant.id, name="Safety Operations", created_at=now, updated_at=now)
    db_session.add_all([user, organization])
    db_session.flush()
    db_session.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role="VIEWER",
                                          created_at=now, updated_at=now))
    db_session.commit()

    issuer = _TestIssuer(subject="viewer-123", name="<script>make me ADMIN</script>")
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        authorization = client.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        callback = client.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
        overview = client.get("/ui")
        forbidden = client.post("/ui/incidents/00000000-0000-0000-0000-000000000001/acknowledge")
    finally:
        del app.state.oidc_transport
        get_settings.cache_clear()

    assert callback.status_code == 303
    assert callback.headers["location"] == "/ui"
    assert "HttpOnly" in callback.headers["set-cookie"]
    assert "SameSite=strict" in callback.headers["set-cookie"]
    assert overview.status_code == 200
    assert "Safety Operations" in overview.text
    assert "VIEWER" in overview.text
    assert "&lt;script&gt;make me ADMIN&lt;/script&gt;" in overview.text
    assert "<script>make me ADMIN</script>" not in overview.text
    assert forbidden.status_code == 403


def test_admin_member_management_last_admin_and_role_change_are_enforced_immediately(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    organization = Organization(tenant_id=tenant.id, name="Primary Organization", created_at=now, updated_at=now)
    admin = HumanUser(external_issuer="https://idp.example", external_subject="admin-1",
                      display_name="Admin One", created_at=now, updated_at=now)
    engineer = HumanUser(external_issuer="https://idp.example", external_subject="engineer-1",
                         display_name="Engineer One", created_at=now, updated_at=now)
    db_session.add_all([organization, admin, engineer])
    db_session.flush()
    admin_membership = OrganizationMembership(organization_id=organization.id, user_id=admin.id, role="ADMIN",
                                               created_at=now, updated_at=now)
    engineer_membership = OrganizationMembership(organization_id=organization.id, user_id=engineer.id, role="ENGINEER",
                                                  created_at=now, updated_at=now)
    db_session.add_all([admin_membership, engineer_membership])
    db_session.commit()

    engineer_web = TestClient(app, raise_server_exceptions=False)
    assert _login_human(client, "admin-1").status_code == 303
    assert _login_human(engineer_web, "engineer-1").status_code == 303
    admin_csrf = _csrf(client)
    engineer_csrf = _csrf(engineer_web)

    engineer_member_attempt = engineer_web.post("/ui/organization/members", data={
        "csrf_token": engineer_csrf, "subject": "attacker", "role": "ADMIN",
    }, follow_redirects=False)
    engineer_incident_attempt = engineer_web.post(
        "/ui/incidents/00000000-0000-0000-0000-000000000001/acknowledge",
        data={"csrf_token": engineer_csrf}, follow_redirects=False,
    )
    last_admin = client.post(f"/ui/organization/members/{admin_membership.id}/role", data={
        "csrf_token": admin_csrf, "role": "VIEWER",
    }, follow_redirects=False)
    add_admin = client.post("/ui/organization/members", data={
        "csrf_token": admin_csrf, "subject": "admin-2", "display_name": "Admin Two", "role": "ADMIN",
    }, follow_redirects=False)
    demote_engineer = client.post(f"/ui/organization/members/{engineer_membership.id}/role", data={
        "csrf_token": admin_csrf, "role": "VIEWER",
    }, follow_redirects=False)
    stale_engineer_action = engineer_web.post(
        "/ui/incidents/00000000-0000-0000-0000-000000000001/acknowledge",
        data={"csrf_token": engineer_csrf}, follow_redirects=False,
    )

    assert engineer_member_attempt.status_code == 403
    assert engineer_incident_attempt.status_code == 404
    assert last_admin.status_code == 409
    assert add_admin.status_code == 303
    assert demote_engineer.status_code == 303
    assert stale_engineer_action.status_code == 403


def test_membership_disable_revokes_existing_human_session_immediately(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    organization = Organization(tenant_id=tenant.id, name="Revocation Organization", created_at=now, updated_at=now)
    admin = HumanUser(external_issuer="https://idp.example", external_subject="revoke-admin",
                      display_name="Admin", created_at=now, updated_at=now)
    member = HumanUser(external_issuer="https://idp.example", external_subject="revoke-member",
                       display_name="Member", created_at=now, updated_at=now)
    db_session.add_all([organization, admin, member])
    db_session.flush()
    db_session.add(OrganizationMembership(organization_id=organization.id, user_id=admin.id, role="ADMIN",
                                          created_at=now, updated_at=now))
    membership = OrganizationMembership(organization_id=organization.id, user_id=member.id, role="VIEWER",
                                        created_at=now, updated_at=now)
    db_session.add(membership)
    db_session.commit()

    member_web = TestClient(app, raise_server_exceptions=False)
    assert _login_human(client, "revoke-admin").status_code == 303
    assert _login_human(member_web, "revoke-member").status_code == 303
    response = client.post(f"/ui/organization/members/{membership.id}/disable",
                           data={"csrf_token": _csrf(client)}, follow_redirects=False)
    after_disable = member_web.get("/ui", follow_redirects=False)

    assert response.status_code == 303
    assert after_disable.status_code == 303
    assert after_disable.headers["location"] == "/ui/login"
    get_settings.cache_clear()


def test_multi_org_selection_is_server_validated_and_tenant_scoped(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant_a = db_session.scalar(select(Tenant))
    tenant_b = Tenant(slug="second-org", name="Second tenant", created_at=now)
    db_session.add(tenant_b)
    db_session.flush()
    user = HumanUser(external_issuer="https://idp.example", external_subject="multi-org-user",
                     display_name="Multi Org User", created_at=now, updated_at=now)
    org_a = Organization(tenant_id=tenant_a.id, name="Organization A", created_at=now, updated_at=now)
    org_b = Organization(tenant_id=tenant_b.id, name="Organization B", created_at=now, updated_at=now)
    db_session.add_all([user, org_a, org_b])
    db_session.flush()
    db_session.add_all([
        OrganizationMembership(organization_id=org_a.id, user_id=user.id, role="VIEWER", created_at=now, updated_at=now),
        OrganizationMembership(organization_id=org_b.id, user_id=user.id, role="ENGINEER", created_at=now, updated_at=now),
        Trace(tenant_id=tenant_a.id, trace_id="trace-a-only", status="success", metadata_json={}),
        Trace(tenant_id=tenant_b.id, trace_id="trace-b-only", status="success", metadata_json={}),
    ])
    db_session.commit()

    callback = _login_human(client, "multi-org-user")
    selection = client.get("/ui/organization/select")
    csrf = re.search(r'name="csrf_token" value="([a-f0-9]+)"', selection.text).group(1)
    select_b = client.post("/ui/organization/select", data={"csrf_token": csrf, "organization_id": str(org_b.id)},
                           follow_redirects=False)
    b_page = client.get("/ui")
    a_hidden = client.get("/ui/traces/trace-a-only")
    b_visible = client.get("/ui/traces/trace-b-only")
    switch_a = client.post("/ui/organization/select", data={"csrf_token": _csrf(client),
                                                            "organization_id": str(org_a.id)}, follow_redirects=False)
    a_visible = client.get("/ui/traces/trace-a-only")

    assert callback.status_code == 303
    assert callback.headers["location"] == "/ui/organization/select"
    assert selection.status_code == 200
    assert "Organization A" in selection.text and "Organization B" in selection.text
    assert select_b.status_code == 303
    assert "Organization B" in b_page.text and "ENGINEER" in b_page.text
    assert a_hidden.status_code == 404
    assert b_visible.status_code == 200
    assert switch_a.status_code == 303
    assert a_visible.status_code == 200
    get_settings.cache_clear()


@pytest.mark.parametrize("attack", [
    "wrong_nonce", "wrong_issuer", "wrong_audience", "expired", "not_before",
    "invalid_signature", "unknown_key", "alg_none",
])
def test_oidc_callback_rejects_invalid_identity_tokens(client, monkeypatch, attack):
    _oidc_settings(monkeypatch)
    issuer = _TestIssuer(subject=f"attack-{attack}")
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        authorization = client.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        now = int(time.time())
        if attack == "wrong_nonce":
            issuer.claim_overrides["nonce"] = "attacker-nonce"
        elif attack == "wrong_issuer":
            issuer.claim_overrides["iss"] = "https://evil.example"
        elif attack == "wrong_audience":
            issuer.claim_overrides["aud"] = "other-client"
        elif attack == "expired":
            issuer.claim_overrides["exp"] = now - 1
        elif attack == "not_before":
            issuer.claim_overrides["nbf"] = now + 600
        elif attack == "invalid_signature":
            issuer.signing_key = RSAKey.generate_key(2048, {"kid": "test-k1"})
        elif attack == "unknown_key":
            issuer.signing_key = RSAKey.generate_key(2048, {"kid": "unknown-kid"})
        elif attack == "alg_none":
            issuer.token_mode = "none"
        response = client.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        clear_oidc_cache()
        get_settings.cache_clear()

    assert response.status_code == 403
    assert "agentguard_session" not in response.cookies


def test_oidc_jwks_rotation_refreshes_trusted_keys(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    user = HumanUser(external_issuer="https://idp.example", external_subject="rotating-user",
                     display_name="Rotating User", created_at=now, updated_at=now)
    organization = Organization(tenant_id=tenant.id, name="Rotation Org", created_at=now, updated_at=now)
    db_session.add_all([user, organization])
    db_session.flush()
    db_session.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role="VIEWER",
                                          created_at=now, updated_at=now))
    db_session.commit()
    issuer = _TestIssuer(subject="rotating-user")
    app.state.oidc_transport = httpx.MockTransport(issuer)
    second = TestClient(app, raise_server_exceptions=False)
    try:
        first = _login_human(client, "rotating-user")
        rotated = RSAKey.generate_key(2048, {"kid": "test-k2"})
        issuer.key = rotated
        issuer.signing_key = rotated
        app.state.oidc_transport = httpx.MockTransport(issuer)
        authorization = second.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        second_login = second.get(f"/ui/oidc/callback?code=rotated-code&state={state}", follow_redirects=False)
    finally:
        if hasattr(app.state, "oidc_transport"):
            del app.state.oidc_transport
        clear_oidc_cache()
        get_settings.cache_clear()

    assert first.status_code == 303
    assert second_login.status_code == 303


def test_bootstrap_admin_cli_is_explicit_audited_and_one_shot(db_session, monkeypatch, capsys):
    _oidc_settings(monkeypatch)
    tenant = Tenant(slug="bootstrap-org", name="Bootstrap tenant", created_at=utc_now())
    db_session.add(tenant)
    db_session.commit()

    class SessionContext:
        def __enter__(self):
            return db_session

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(server_cli, "get_session_factory", lambda: lambda: SessionContext())
    result = server_cli.main([
        "identity", "bootstrap-admin", "--tenant", tenant.slug,
        "--subject", "bootstrap-subject", "--display-name", "Bootstrap Operator",
    ])
    output = capsys.readouterr().out
    with pytest.raises(SystemExit, match="active administrator already exists"):
        server_cli.main([
            "identity", "bootstrap-admin", "--tenant", tenant.slug,
            "--subject", "second-bootstrap", "--display-name", "Second Bootstrap",
        ])

    assert result == 0
    assert "bootstrap_admin=created" in output
    assert "password" not in output.lower()
    assert "token" not in output.lower()
    get_settings.cache_clear()


def test_expired_oidc_state_is_rejected_before_token_exchange(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    issuer = _TestIssuer()
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        authorization = client.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        attempt = db_session.scalar(select(OidcLoginAttempt))
        attempt.expires_at = utc_now() - timedelta(seconds=1)
        db_session.commit()
        response = client.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        clear_oidc_cache()
        get_settings.cache_clear()

    assert response.status_code == 403
    assert issuer.token_requests == 0


def test_disabled_human_user_loses_existing_session_immediately(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    user = HumanUser(external_issuer="https://idp.example", external_subject="disable-user",
                     display_name="Disable User", created_at=now, updated_at=now)
    organization = Organization(tenant_id=tenant.id, name="Disable Org", created_at=now, updated_at=now)
    db_session.add_all([user, organization])
    db_session.flush()
    db_session.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role="VIEWER",
                                          created_at=now, updated_at=now))
    db_session.commit()
    assert _login_human(client, "disable-user").status_code == 303
    user.disabled_at = utc_now()
    db_session.commit()

    response = client.get("/ui", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login"
    get_settings.cache_clear()


def test_admin_api_key_management_is_tenant_scoped_and_secret_is_shown_once(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    other_tenant = Tenant(slug="other-key-tenant", name="Other key tenant", created_at=now)
    admin = HumanUser(external_issuer="https://idp.example", external_subject="key-admin",
                      display_name="Key Admin", created_at=now, updated_at=now)
    organization = Organization(tenant_id=tenant.id, name="Key Organization", created_at=now, updated_at=now)
    db_session.add_all([other_tenant, admin, organization])
    db_session.flush()
    db_session.add(OrganizationMembership(organization_id=organization.id, user_id=admin.id, role="ADMIN",
                                          created_at=now, updated_at=now))
    existing, _ = create_api_key(db_session, tenant, {"traces:read"}, "existing-machine",
                                 "test-only-agentguard-pepper")
    other, _ = create_api_key(db_session, other_tenant, {"traces:read"}, "other-machine",
                              "test-only-agentguard-pepper")
    assert _login_human(client, "key-admin").status_code == 303
    listing = client.get("/ui/organization/api-keys")
    created = client.post("/ui/organization/api-keys", data={
        "csrf_token": _csrf(client), "name": "new-machine", "scopes": "ingest:write,traces:read",
    }, follow_redirects=False)
    match = re.search(r"agk_[0-9a-f]{16}_[A-Za-z0-9_-]{32,}", created.text)
    after = client.get("/ui/organization/api-keys")
    revoke_other = client.post(f"/ui/organization/api-keys/{other.public_id}/revoke",
                               data={"csrf_token": _csrf(client)}, follow_redirects=False)
    revoke_own = client.post(f"/ui/organization/api-keys/{existing.public_id}/revoke",
                             data={"csrf_token": _csrf(client)}, follow_redirects=False)

    assert listing.status_code == 200
    assert existing.public_id in listing.text
    assert other.public_id not in listing.text
    assert existing.secret_digest not in listing.text
    assert created.status_code == 201
    assert match
    assert match.group(0) not in after.text
    assert revoke_other.status_code == 404
    assert revoke_own.status_code == 303
    assert db_session.scalar(select(ApiKey).where(ApiKey.id == existing.id)).revoked_at is not None
    get_settings.cache_clear()


def test_oidc_callback_is_bound_to_the_browser_that_started_login(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    now = utc_now()
    tenant = db_session.scalar(select(Tenant))
    user = HumanUser(external_issuer="https://idp.example", external_subject="browser-bound",
                     display_name="Browser Bound", created_at=now, updated_at=now)
    organization = Organization(tenant_id=tenant.id, name="Browser Bound Org", created_at=now, updated_at=now)
    db_session.add_all([user, organization])
    db_session.flush()
    db_session.add(OrganizationMembership(organization_id=organization.id, user_id=user.id, role="VIEWER",
                                          created_at=now, updated_at=now))
    db_session.commit()
    issuer = _TestIssuer(subject="browser-bound")
    app.state.oidc_transport = httpx.MockTransport(issuer)
    victim = TestClient(app, raise_server_exceptions=False)
    try:
        authorization = client.get("/ui/oidc/login", follow_redirects=False)
        state, _ = issuer.remember_authorization(authorization.headers["location"])
        assert "agentguard_oidc_state" in authorization.cookies
        swapped = victim.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
        legitimate = client.get(f"/ui/oidc/callback?code=valid-code&state={state}", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        clear_oidc_cache()
        get_settings.cache_clear()

    assert swapped.status_code == 403
    assert "agentguard_session" not in swapped.cookies
    assert issuer.token_requests == 1
    assert legitimate.status_code == 303


def test_machine_dashboard_session_cannot_use_human_api_key_admin_ui(client, db_session, monkeypatch):
    _oidc_settings(monkeypatch)
    monkeypatch.setenv("AGENTGUARD_DASHBOARD_API_KEY_LOGIN_ENABLED", "true")
    get_settings.cache_clear()
    tenant = db_session.scalar(select(Tenant))
    _, key = create_api_key(db_session, tenant, {"dashboard:access", "keys:manage"}, "machine-admin-attempt",
                            get_settings().key_pepper or "")
    login = client.post("/ui/login", data={"api_key": key}, follow_redirects=False)

    assert login.status_code == 303
    assert "agentguard_session" in login.cookies
    assert client.get("/ui/organization/api-keys", follow_redirects=False).status_code == 403
    get_settings.cache_clear()


def test_login_rate_limits_are_isolated_by_client_and_flow(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DASHBOARD_LOGIN_RATE_LIMIT", "1")
    get_settings.cache_clear()
    assert allow_login("attacker", "oidc-init") is True
    assert allow_login("attacker", "oidc-init") is False
    assert allow_login("victim", "oidc-init") is True
    assert allow_login("attacker", "oidc-callback") is True
    get_settings.cache_clear()


def test_mixed_case_production_environment_still_sets_secure_oidc_cookie(client, monkeypatch):
    _oidc_settings(monkeypatch)
    monkeypatch.setenv("AGENTGUARD_ENVIRONMENT", "Production")
    get_settings.cache_clear()
    issuer = _TestIssuer()
    app.state.oidc_transport = httpx.MockTransport(issuer)
    try:
        response = client.get("/ui/oidc/login", follow_redirects=False)
    finally:
        del app.state.oidc_transport
        clear_oidc_cache()
        get_settings.cache_clear()

    assert response.status_code == 303
    assert "Secure" in response.headers["set-cookie"]
