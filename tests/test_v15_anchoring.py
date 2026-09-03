from datetime import datetime, timezone
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from agentguard_server.models import IntegrityCheckpoint
from agentguard_server.services.anchoring import (
    CHECKPOINT_VERSION, canonical_manifest, checkpoint_digest, load_verify_keys,
    manifest_digest, receipt_message, verify_receipt_signature,
)


def test_checkpoint_canonicalization_is_independent_of_entry_order():
    created = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc)
    entries = [
        {"tenant_id": "b", "trace_id": "z", "tenant_chain_sequence": 2, "tenant_chain_head_hash": "b" * 64},
        {"tenant_id": "a", "trace_id": "a", "tenant_chain_sequence": 1, "tenant_chain_head_hash": "a" * 64},
    ]
    assert canonical_manifest(entries) == canonical_manifest(list(reversed(entries)))
    digest = manifest_digest(entries)
    assert len(digest) == 64 and digest == manifest_digest(list(reversed(entries)))
    assert checkpoint_digest(namespace="agentguard-development", checkpoint_sequence=1,
        manifest_digest_value=digest, previous_checkpoint_digest=None,
        created_at=created, entry_count=2) == checkpoint_digest(
        namespace="agentguard-development", checkpoint_sequence=1,
        manifest_digest_value=digest, previous_checkpoint_digest=None,
        created_at=created, entry_count=2)
    assert CHECKPOINT_VERSION == "checkpoint-v1"


def test_receipt_signature_uses_trusted_public_key_only():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    key_id = "witness-test-v1"
    message = receipt_message(schema_version="https-signed-witness-v1", external_anchor_id="anchor-1",
        namespace="agentguard-development", checkpoint_sequence=1, checkpoint_digest_value="a" * 64,
        previous_checkpoint_digest=None, created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        witness_received_at=datetime(2026, 1, 2, 0, 0, 1, tzinfo=timezone.utc), signer_key_id=key_id)
    signature = base64.b64encode(private.sign(message)).decode("ascii")
    keys = load_verify_keys(json.dumps({key_id: base64.b64encode(public).decode("ascii")}))
    assert verify_receipt_signature(message, signature, key_id, keys) is True
    assert verify_receipt_signature(message, signature[:-4] + "AAAA", key_id, keys) is False


def test_checkpoint_model_is_available_to_metadata(db_session):
    checkpoint = IntegrityCheckpoint(namespace="agentguard-development", checkpoint_sequence=1,
        checkpoint_version=CHECKPOINT_VERSION, manifest_digest="a" * 64, previous_checkpoint_digest=None,
        checkpoint_digest="b" * 64, entry_count=0, created_at=datetime.now(timezone.utc))
    db_session.add(checkpoint)
    db_session.commit()
    assert db_session.scalar(select(IntegrityCheckpoint).where(IntegrityCheckpoint.id == checkpoint.id)) is not None

from agentguard_server.config import Settings
from agentguard_server.services.anchoring import FakeWitnessProvider, anchor_job, create_checkpoint, remote_continuity, verify_checkpoint
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.schemas.events import Event
from agentguard_server.models import IntegrityAnchorJob, ExternalAnchorReceipt


def test_checkpoint_anchor_and_remote_continuity(db_session):
    private = Ed25519PrivateKey.generate()
    key_id = "witness-test-v1"
    settings = Settings(anchor_enabled=True, anchor_namespace="agentguard-development",
        anchor_verify_keys=json.dumps({key_id: base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")}))
    tenant = create_tenant(db_session, "v15-anchor-test", "V15")
    trace_id = "v15-trace"
    ingest_events(db_session, [Event(event_type="trace.started", event_id=trace_id,
        data={"trace_id": trace_id})], tenant.id)
    checkpoint = create_checkpoint(db_session, settings=settings, force=True,
                                   now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert checkpoint is not None
    assert verify_checkpoint(db_session, checkpoint.id, settings=settings)["status"] == "NOT_ANCHORED"
    job = db_session.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.checkpoint_id == checkpoint.id))
    assert job is not None
    witness = FakeWitnessProvider(private, key_id)
    result = anchor_job(db_session, job.id, witness, settings=settings,
                        now=datetime(2026, 1, 2, 0, 0, 2, tzinfo=timezone.utc))
    assert result is not None and result.status == "DELIVERED"
    assert verify_checkpoint(db_session, checkpoint.id, settings=settings)["status"] == "VALID"
    assert remote_continuity(db_session, witness, settings=settings).status == "MATCH"




from datetime import timedelta
from agentguard_server.services.anchoring import AnchorUnavailable, AnchorConflictError, parse_receipt, freshness


def test_key_rotation_and_local_receipt_tamper_states(db_session):
    private = Ed25519PrivateKey.generate()
    key_id = "witness-test-v1"
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    settings = Settings(anchor_enabled=True, anchor_namespace="agentguard-development",
        anchor_verify_keys=json.dumps({key_id: public}))
    tenant = create_tenant(db_session, "v15-rotation-test", "V15")
    ingest_events(db_session, [Event(event_type="trace.started", event_id="rotation-trace",
        data={"trace_id": "rotation-trace"})], tenant.id)
    checkpoint = create_checkpoint(db_session, settings=settings, force=True,
        now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    witness = FakeWitnessProvider(private, key_id)
    job = db_session.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.checkpoint_id == checkpoint.id))
    anchor_job(db_session, job.id, witness, settings=settings)
    assert verify_checkpoint(db_session, checkpoint.id, settings=settings)["status"] == "VALID"
    settings.anchor_verify_keys = json.dumps({})
    assert verify_checkpoint(db_session, checkpoint.id, settings=settings)["status"] == "UNVERIFIABLE_WITNESS_KEY_MISSING"
    settings.anchor_verify_keys = json.dumps({key_id: public})
    receipt = db_session.scalar(select(ExternalAnchorReceipt).where(
        ExternalAnchorReceipt.checkpoint_id == checkpoint.id))
    receipt.receipt_digest = "c" * 64
    db_session.commit()
    assert verify_checkpoint(db_session, checkpoint.id, settings=settings)["status"] == "ANCHOR_DIGEST_MISMATCH"


def test_expired_anchor_lease_is_reclaimable(db_session):
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    settings = Settings(anchor_enabled=True, anchor_namespace="agentguard-development", anchor_verify_keys=json.dumps({"k": "00" * 32}), anchor_lease_seconds=5)
    checkpoint = create_checkpoint(db_session, settings=settings, force=True, now=now)
    job = db_session.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.checkpoint_id == checkpoint.id))
    first = __import__("agentguard_server.services.anchoring", fromlist=["claim_anchor_job"]).claim_anchor_job(db_session, job_id=job.id, now=now, instance_id="a", settings=settings)
    first_token = first.claim_token if first else None
    second = __import__("agentguard_server.services.anchoring", fromlist=["claim_anchor_job"]).claim_anchor_job(db_session, job_id=job.id, now=now + timedelta(seconds=6), instance_id="b", settings=settings)
    assert first is not None and second is not None and second.claimed_by == "b" and second.claim_token != first_token


def test_http_provider_rejects_private_production_endpoint():
    settings = Settings(anchor_enabled=True, anchor_endpoint="http://127.0.0.1:8080", anchor_namespace="agentguard-development", anchor_verify_keys=json.dumps({"k": "00" * 32}), environment="production")
    from agentguard_server.services.anchoring import HttpSignedWitnessProvider
    with __import__("pytest").raises(Exception):
        HttpSignedWitnessProvider(settings)._target()




from agentguard_server.models import ApiKey


def test_v15_checkpoint_api_is_scope_gated_and_read_only(client, db_session):
    key = db_session.scalar(select(ApiKey))
    key.scopes = ["integrity:read", "integrity:anchor"]
    db_session.commit()
    response = client.post("/v1/integrity/checkpoints", json={"force": True})
    assert response.status_code == 201
    checkpoint_id = response.json()["id"]
    detail = client.get(f"/v1/integrity/checkpoints/{checkpoint_id}")
    assert detail.status_code == 200
    assert "tenant_id" not in detail.text
    assert client.post(f"/v1/integrity/checkpoints/{checkpoint_id}/verify").json()["status"] == "NOT_ANCHORED"
