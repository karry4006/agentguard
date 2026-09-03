"""V14 PostgreSQL-coordination semantics exercised against the local DB seam."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select

from agentguard_server.config import Settings
from agentguard_server.models import Incident, NotificationDelivery
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.notifications import (
    claim_delivery,
    create_destination,
    create_notification_intents,
    create_policy,
    dispatch_delivery,
)
from agentguard_server.services.rate_limit import rate_limiter


def _incident(db, tenant_id):
    now = datetime.now(timezone.utc)
    row = Incident(
        tenant_id=tenant_id, fingerprint=uuid4().hex, fingerprint_version="v14",
        title="V14 test incident", status="OPEN", severity="HIGH",
        severity_policy_version="v1", first_seen_at=now, last_seen_at=now,
        occurrence_count=1, affected_trace_count=1, primary_category="TIMEOUT",
        dimensions={}, created_at=now, updated_at=now,
    )
    db.add(row)
    db.commit()
    return row


def test_shared_fixed_window_is_atomic_and_tenant_scoped(db_session):
    tenant_a = create_tenant(db_session, "v14-rate-a-" + uuid4().hex[:8], "A")
    tenant_b = create_tenant(db_session, "v14-rate-b-" + uuid4().hex[:8], "B")

    decisions = [
        rate_limiter.allow_shared(db_session, tenant_a.id, "read", 2, 60)
        for _ in range(3)
    ]
    assert [allowed for allowed, _ in decisions] == [True, True, False]
    assert rate_limiter.allow_shared(db_session, tenant_b.id, "read", 2, 60)[0] is True


def test_notification_claim_is_exclusive_and_expired_lease_is_reclaimable(db_session, monkeypatch):
    settings = Settings(
        AGENTGUARD_ENVIRONMENT="test",
        AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS=True,
        AGENTGUARD_KEY_PEPPER="test-only-agentguard-pepper",
        AGENTGUARD_INTEGRITY_KEY="test-only-agentguard-integrity-key-32-bytes!!",
        AGENTGUARD_NOTIFICATION_LEASE_SECONDS=30,
    )
    import agentguard_server.services.notifications as notifications
    monkeypatch.setattr(notifications, "get_settings", lambda: settings)

    tenant = create_tenant(db_session, "v14-lease-" + uuid4().hex[:8], "Lease")
    destination = create_destination(db_session, tenant.id, name="receiver", url="http://127.0.0.1:8765/hook")
    create_policy(db_session, tenant.id, name="policy")
    delivery = create_notification_intents(
        db_session, tenant.id, _incident(db_session, tenant.id), "INCIDENT_CREATED"
    )[0]
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)

    first = claim_delivery(db_session, delivery.id, now=started, instance_id="worker-a")
    assert first is not None and first.claimed_by == "worker-a"
    first_token = first.claim_token
    assert claim_delivery(db_session, delivery.id, now=started + timedelta(seconds=1), instance_id="worker-b") is None

    reclaimed = claim_delivery(
        db_session, delivery.id, now=started + timedelta(seconds=31), instance_id="worker-b"
    )
    assert reclaimed is not None
    assert reclaimed.claimed_by == "worker-b"
    assert reclaimed.claim_token != first_token
    assert db_session.scalar(select(NotificationDelivery.id).where(
        NotificationDelivery.id == delivery.id
    )) == delivery.id


def test_circuit_breaker_state_is_shared_and_opens_after_threshold(db_session, monkeypatch):
    settings = Settings(
        AGENTGUARD_ENVIRONMENT="test",
        AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS=True,
        AGENTGUARD_KEY_PEPPER="test-only-agentguard-pepper",
        AGENTGUARD_INTEGRITY_KEY="test-only-agentguard-integrity-key-32-bytes!!",
        AGENTGUARD_NOTIFICATION_CIRCUIT_FAILURE_THRESHOLD=1,
        AGENTGUARD_NOTIFICATION_RETRY_MAX_ATTEMPTS=3,
        AGENTGUARD_NOTIFICATION_RETRY_BASE_SECONDS=1,
    )
    import agentguard_server.services.notifications as notifications
    monkeypatch.setattr(notifications, "get_settings", lambda: settings)

    tenant = create_tenant(db_session, "v14-circuit-" + uuid4().hex[:8], "Circuit")
    create_destination(db_session, tenant.id, name="receiver", url="http://127.0.0.1:8765/hook")
    create_policy(db_session, tenant.id, name="policy")
    incident = _incident(db_session, tenant.id)
    delivery = create_notification_intents(db_session, tenant.id, incident, "INCIDENT_CREATED")[0]

    result = dispatch_delivery(
        db_session, delivery.id, sender=lambda *args, **kwargs: (503, None),
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert result.status == "RETRYING"
    from agentguard_server.models import NotificationCircuitState
    state = db_session.get(NotificationCircuitState, result.destination_id)
    assert state is not None and state.state == "OPEN"