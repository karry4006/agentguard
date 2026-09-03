"""V11 notification behavior at the public service boundary."""

from datetime import datetime, timezone
import hashlib
import hmac
import socket
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agentguard_server.config import Settings, validate_configuration
from agentguard_server.services.notifications import (
    NotificationSecurityError,
    build_notification_payload,
    classify_delivery_response,
    sign_webhook_payload,
    validate_webhook_url,
)
from agentguard_server.models import Incident
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.notifications import create_destination, create_notification_intents, create_policy, dispatch_delivery


def test_webhook_url_accepts_https_public_host_and_rejects_internal_targets():
    public_resolver = lambda host, port, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    target = validate_webhook_url("https://hooks.example.test/v1/incident", resolver=public_resolver)
    assert target.scheme == "https"
    assert target.host == "hooks.example.test"
    assert target.path == "/v1/incident"

    for value in (
        "http://127.0.0.1/hook",
        "https://localhost/hook",
        "https://169.254.169.254/latest/meta-data",
        "ftp://hooks.example.test/hook",
        "file:///etc/passwd",
        "https://postgres/hook",
    ):
        with pytest.raises(NotificationSecurityError):
            validate_webhook_url(value)


def test_webhook_url_private_test_override_is_explicit_and_safe():
    target = validate_webhook_url("http://127.0.0.1:8765/hook", allow_private_test=True, environment="test")
    assert target.host == "127.0.0.1"
    with pytest.raises(NotificationSecurityError):
        validate_webhook_url("http://127.0.0.1:8765/hook", allow_private_test=True, environment="production")


def test_notification_payload_is_minimized_and_never_copies_untrusted_content():
    incident = SimpleNamespace(
        id=uuid4(), severity="HIGH", status="OPEN", title="Timeout <script>",
        primary_category="TIMEOUT", occurrence_count=3,
        first_seen_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    payload = build_notification_payload(incident, "INCIDENT_CREATED")
    assert payload["schema_version"] == "webhook-v1"
    assert payload["incident_id"] == str(incident.id)
    assert set(payload) == {
        "schema_version", "event", "incident_id", "severity", "status", "title",
        "primary_category", "occurrence_count", "first_seen", "last_seen", "trend",
    }
    assert "script" not in str(payload).lower()


def test_webhook_signature_uses_timestamp_and_payload_bytes():
    payload = b'{"schema_version":"webhook-v1"}'
    header = sign_webhook_payload(payload, "test-only-signing-secret-32-bytes!!", timestamp=1700000000)
    expected = hmac.new(
        b"test-only-signing-secret-32-bytes!!",
        b"1700000000." + payload,
        hashlib.sha256,
    ).hexdigest()
    assert header == f"t=1700000000,v1={expected}"
    assert "integrity" not in header


def test_delivery_response_retries_only_transient_failures():
    assert classify_delivery_response(200).retryable is False
    assert classify_delivery_response(401).failure_category == "AUTHENTICATION"
    assert classify_delivery_response(404).retryable is False
    assert classify_delivery_response(429, retry_after="600").retry_after_seconds == 300
    assert classify_delivery_response(503).retryable is True


def test_production_rejects_private_webhook_override():
    settings = Settings(
        AGENTGUARD_ENVIRONMENT="production",
        AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS=True,
        AGENTGUARD_KEY_PEPPER="a-real-looking-pepper-value",
        AGENTGUARD_INTEGRITY_KEY="a-real-looking-integrity-key-value-32-bytes",
        DATABASE_URL="postgresql+psycopg://example.invalid/db",
    )
    with pytest.raises(ValueError, match="private webhook"):
        validate_configuration(settings)


def test_notification_intent_is_tenant_scoped_and_idempotent(db_session, monkeypatch):
    import agentguard_server.services.notifications as notifications
    test_settings = Settings(AGENTGUARD_ENVIRONMENT="test", AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS=True,
                             AGENTGUARD_KEY_PEPPER="test-only-agentguard-pepper",
                             AGENTGUARD_INTEGRITY_KEY="test-only-agentguard-integrity-key-32-bytes!!")
    monkeypatch.setattr(notifications, "get_settings", lambda: test_settings)
    tenant_a = create_tenant(db_session, f"notify-a-{uuid4().hex[:8]}", "Notify A")
    tenant_b = create_tenant(db_session, f"notify-b-{uuid4().hex[:8]}", "Notify B")
    destination = create_destination(db_session, tenant_a.id, name="test receiver", url="http://127.0.0.1:8765/hook")
    policy = create_policy(db_session, tenant_a.id, name="high incidents", minimum_severity="HIGH")
    incident = Incident(tenant_id=tenant_a.id, fingerprint=uuid4().hex, fingerprint_version="v1", title="TIMEOUT in tool",
                        status="OPEN", severity="HIGH", severity_policy_version="v1", first_seen_at=datetime.now(timezone.utc),
                        last_seen_at=datetime.now(timezone.utc), occurrence_count=1, affected_trace_count=1,
                        primary_category="TIMEOUT", dimensions={}, created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
    db_session.add(incident)
    db_session.commit()
    first = create_notification_intents(db_session, tenant_a.id, incident, "INCIDENT_CREATED")
    second = create_notification_intents(db_session, tenant_a.id, incident, "INCIDENT_CREATED")
    assert len(first) == 1 and second == []
    assert first[0].destination_id == destination.id and first[0].policy_id == policy.id
    assert create_notification_intents(db_session, tenant_b.id, incident, "INCIDENT_CREATED") == []


def test_durable_delivery_retries_transient_and_stops_on_auth_failure(db_session, monkeypatch):
    import agentguard_server.services.notifications as notifications
    test_settings = Settings(AGENTGUARD_ENVIRONMENT="test", AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS=True,
                             AGENTGUARD_KEY_PEPPER="test-only-agentguard-pepper",
                             AGENTGUARD_INTEGRITY_KEY="test-only-agentguard-integrity-key-32-bytes!!",
                             AGENTGUARD_NOTIFICATION_RETRY_BASE_SECONDS=1)
    monkeypatch.setattr(notifications, "get_settings", lambda: test_settings)
    tenant = create_tenant(db_session, f"delivery-{uuid4().hex[:8]}", "Delivery")
    destination = create_destination(db_session, tenant.id, name="test receiver", url="http://127.0.0.1:8765/hook")
    create_policy(db_session, tenant.id, name="high incidents")
    incident = Incident(tenant_id=tenant.id, fingerprint=uuid4().hex, fingerprint_version="v1", title="TIMEOUT in tool",
                        status="OPEN", severity="HIGH", severity_policy_version="v1", first_seen_at=datetime.now(timezone.utc),
                        last_seen_at=datetime.now(timezone.utc), occurrence_count=1, affected_trace_count=1,
                        primary_category="TIMEOUT", dimensions={}, created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc))
    db_session.add(incident)
    db_session.commit()
    delivery = create_notification_intents(db_session, tenant.id, incident, "INCIDENT_CREATED")[0]
    outcomes = iter([(503, None), (503, None), (200, None)])
    sender = lambda target, payload, headers, timeout: next(outcomes)
    first = dispatch_delivery(db_session, delivery.id, sender=sender)
    assert first.status == "RETRYING" and first.attempt_count == 1
    second = dispatch_delivery(db_session, delivery.id, sender=sender, now=first.next_retry_at)
    assert second.status == "RETRYING" and second.attempt_count == 2
    third = dispatch_delivery(db_session, delivery.id, sender=sender, now=second.next_retry_at)
    assert third.status == "DELIVERED" and third.attempt_count == 3


def test_notification_api_requires_new_scope_and_hides_secret_value(db_session, monkeypatch):
    import agentguard_server.services.notifications as notifications
    from agentguard_server.api.routes import db_session as api_db_session
    from agentguard_server.main import app
    from fastapi.testclient import TestClient
    test_settings = Settings(AGENTGUARD_ENVIRONMENT="test", AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS=True,
                             AGENTGUARD_KEY_PEPPER="test-only-agentguard-pepper",
                             AGENTGUARD_INTEGRITY_KEY="test-only-agentguard-integrity-key-32-bytes!!")
    monkeypatch.setattr(notifications, "get_settings", lambda: test_settings)
    tenant_a = create_tenant(db_session, f"api-notify-a-{uuid4().hex[:8]}", "API notify A")
    tenant_b = create_tenant(db_session, f"api-notify-b-{uuid4().hex[:8]}", "API notify B")
    import os
    configured_pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
    _, key_a = create_api_key(db_session, tenant_a, ["notifications:manage", "notifications:read"], "notify-a", configured_pepper)
    _, key_b = create_api_key(db_session, tenant_b, ["notifications:read"], "notify-b", configured_pepper)
    _, old_key = create_api_key(db_session, tenant_a, ["incidents:read"], "old-key", configured_pepper)
    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    try:
        with TestClient(app) as http:
            body = {"name": "receiver", "url": "http://127.0.0.1:8765/hook", "signing_secret_reference": "default"}
            created = http.post("/v1/notification-destinations", json=body, headers={"Authorization": f"Bearer {key_a}"})
            assert created.status_code == 201
            assert "secret" not in created.text.lower() or "default" in created.text
            assert "test-only-signing" not in created.text
            assert http.post("/v1/notification-destinations", json=body, headers={"Authorization": f"Bearer {old_key}"}).status_code == 403
            assert http.get("/v1/notification-destinations", headers={"Authorization": f"Bearer {key_b}"}).status_code == 200
            assert http.post("/v1/alert-policies", json={"name": "high"}, headers={"Authorization": f"Bearer {key_b}"}).status_code == 403
    finally:
        app.dependency_overrides.clear()
