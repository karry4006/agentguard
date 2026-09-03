"""V15 external integrity anchoring primitives and durable services."""
from __future__ import annotations
import base64, hashlib, json, logging, re, secrets, http.client, socket, ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import UUID
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.orm import Session
from agentguard_server.config import Settings, get_settings
from agentguard_server.models import (ExternalAnchorReceipt, IntegrityAnchorJob,
    IntegrityAnchorState, IntegrityCheckpoint, IntegrityCheckpointEntry, IntegrityChainHead)
from agentguard_server.services.integrity import verify_trace_integrity
from agentguard_server.services.notifications import NotificationSecurityError, WebhookTarget, validate_webhook_url
from agentguard_server.services.rate_limit import database_now
logger = logging.getLogger("agentguard.anchoring")
CHECKPOINT_VERSION = "checkpoint-v1"
ANCHOR_PROTOCOL_VERSION = "https-signed-witness-v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NAMESPACE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")

class AnchoringError(ValueError): pass
class CheckpointEligibilityError(AnchoringError): pass
class AnchorUnavailable(AnchoringError): pass
class AnchorPermanentError(AnchoringError): pass
class AnchorConflictError(AnchorPermanentError): pass

@dataclass(frozen=True)
class AnchorFailure:
    category: str
    retryable: bool

@dataclass(frozen=True)
class Continuity:
    status: str
    local_sequence: int | None = None
    remote_sequence: int | None = None
    local_digest: str | None = None
    remote_digest: str | None = None
    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "local_sequence": self.local_sequence,
                "remote_sequence": self.remote_sequence, "local_digest": self.local_digest,
                "remote_digest": self.remote_digest}

def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def canonical_timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")

def validate_namespace(namespace: str) -> str:
    if not isinstance(namespace, str) or len(namespace) > 128 or not _NAMESPACE.fullmatch(namespace):
        raise AnchoringError("anchor namespace is invalid")
    return namespace

def _entry_value(entry: Mapping[str, Any]) -> dict[str, Any]:
    tenant, trace = str(entry.get("tenant_id", "")), str(entry.get("trace_id", ""))
    sequence, head = entry.get("tenant_chain_sequence"), str(entry.get("tenant_chain_head_hash", "")).lower()
    if not tenant or not trace or not isinstance(sequence, int) or sequence < 1 or not _HEX64.fullmatch(head):
        raise AnchoringError("checkpoint entry is invalid")
    return {"tenant_chain_head_hash": head, "tenant_chain_sequence": sequence,
            "tenant_id": tenant, "trace_id": trace}

def canonical_manifest(entries: list[Mapping[str, Any]]) -> bytes:
    normalized = [_entry_value(entry) for entry in entries]
    normalized.sort(key=lambda item: (item["tenant_id"], item["trace_id"]))
    return canonical_json({"checkpoint_version": CHECKPOINT_VERSION, "entries": normalized})

def manifest_digest(entries: list[Mapping[str, Any]]) -> str:
    return hashlib.sha256(canonical_manifest(entries)).hexdigest()

def _checkpoint_document(*, namespace: str, checkpoint_sequence: int, manifest_digest_value: str,
                         previous_checkpoint_digest: str | None, created_at: datetime, entry_count: int) -> dict[str, Any]:
    return {"checkpoint_version": CHECKPOINT_VERSION, "created_at": canonical_timestamp(created_at),
            "entry_count": entry_count, "manifest_digest": manifest_digest_value.lower(),
            "namespace": validate_namespace(namespace),
            "previous_checkpoint_digest": previous_checkpoint_digest.lower() if previous_checkpoint_digest else None,
            "checkpoint_sequence": checkpoint_sequence}

def canonical_checkpoint(*, namespace: str, checkpoint_sequence: int, manifest_digest_value: str,
                         previous_checkpoint_digest: str | None, created_at: datetime, entry_count: int) -> bytes:

    return canonical_json(_checkpoint_document(namespace=namespace, checkpoint_sequence=checkpoint_sequence,
        manifest_digest_value=manifest_digest_value, previous_checkpoint_digest=previous_checkpoint_digest,
        created_at=created_at, entry_count=entry_count))

def checkpoint_digest(*, namespace: str, checkpoint_sequence: int, manifest_digest_value: str,
                      previous_checkpoint_digest: str | None, created_at: datetime, entry_count: int) -> str:
    return hashlib.sha256(canonical_checkpoint(namespace=namespace, checkpoint_sequence=checkpoint_sequence,
        manifest_digest_value=manifest_digest_value, previous_checkpoint_digest=previous_checkpoint_digest,
        created_at=created_at, entry_count=entry_count)).hexdigest()

def receipt_message(*, schema_version: str, external_anchor_id: str, namespace: str, checkpoint_sequence: int,
                    checkpoint_digest_value: str, previous_checkpoint_digest: str | None, created_at: datetime,
                    witness_received_at: datetime, signer_key_id: str) -> bytes:
    return canonical_json({"checkpoint_digest": checkpoint_digest_value.lower(), "checkpoint_sequence": checkpoint_sequence,
        "created_at": canonical_timestamp(created_at), "external_anchor_id": external_anchor_id,
        "namespace": validate_namespace(namespace),
        "previous_checkpoint_digest": previous_checkpoint_digest.lower() if previous_checkpoint_digest else None,
        "schema_version": schema_version, "signer_key_id": signer_key_id,
        "witness_received_at": canonical_timestamp(witness_received_at)})

def _decode_public_key(value: str) -> bytes:
    try:
        raw = value.strip()
        decoded = bytes.fromhex(raw) if re.fullmatch(r"[0-9a-fA-F]{64}", raw) else base64.b64decode(raw, validate=True)
    except (ValueError, TypeError):
        raise AnchoringError("anchor verification key is not valid") from None
    if len(decoded) != 32: raise AnchoringError("anchor verification key must be 32 bytes")
    return decoded

def load_verify_keys(source: str | Mapping[str, str] | None = None, *, file_path: str | None = None) -> dict[str, bytes]:
    if file_path:
        try: source = Path(file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc: raise AnchoringError("anchor verification key file is unavailable") from exc
    if source is None or source == "": return {}
    try: parsed = json.loads(source) if isinstance(source, str) else dict(source)
    except json.JSONDecodeError as exc: raise AnchoringError("anchor verification keys must be a JSON object") from exc
    if not isinstance(parsed, dict) or len(parsed) > 32: raise AnchoringError("anchor verification keys are invalid")
    result = {}
    for key_id, value in parsed.items():
        if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id) or not isinstance(value, str):
            raise AnchoringError("anchor verification key registry is invalid")
        result[key_id] = _decode_public_key(value)
    return result

def configured_verify_keys(settings: Settings) -> dict[str, bytes]:
    return load_verify_keys(getattr(settings, "anchor_verify_keys", None),
                            file_path=getattr(settings, "anchor_verify_keys_file", None))

def verify_receipt_signature(message: bytes, signature: str, signer_key_id: str, keys: Mapping[str, bytes]) -> bool:
    key = keys.get(signer_key_id)
    if key is None: return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(signature, validate=True), message)
        return True
    except Exception: return False

def _parse_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 64: raise AnchorPermanentError("witness timestamp is invalid")
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise AnchorPermanentError("witness timestamp is invalid") from exc
    if parsed.tzinfo is None: raise AnchorPermanentError("witness timestamp must include timezone")
    return parsed.astimezone(timezone.utc)

def parse_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {"schema_version", "external_anchor_id", "namespace", "checkpoint_sequence",
                "checkpoint_digest", "witness_received_at", "signer_key_id", "signature"}
    if not isinstance(value, Mapping) or set(value) != required: raise AnchorPermanentError("witness receipt schema is invalid")
    if value["schema_version"] != ANCHOR_PROTOCOL_VERSION: raise AnchorPermanentError("witness protocol version is unsupported")
    if not isinstance(value["external_anchor_id"], str) or not 1 <= len(value["external_anchor_id"]) <= 128: raise AnchorPermanentError("witness anchor id is invalid")
    if not isinstance(value["signer_key_id"], str) or not 1 <= len(value["signer_key_id"]) <= 128: raise AnchorPermanentError("witness signer key id is invalid")
    if not isinstance(value["checkpoint_sequence"], int) or value["checkpoint_sequence"] < 1: raise AnchorPermanentError("witness checkpoint sequence is invalid")
    digest = value["checkpoint_digest"]
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest.lower()): raise AnchorPermanentError("witness checkpoint digest is invalid")
    signature = value["signature"]
    if not isinstance(signature, str) or not 1 <= len(signature) <= 256: raise AnchorPermanentError("witness signature is invalid")
    try: decoded = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError): raise AnchorPermanentError("witness signature is invalid") from None
    if len(decoded) != 64: raise AnchorPermanentError("witness signature is invalid")
    return {**value, "namespace": validate_namespace(value["namespace"]), "checkpoint_digest": digest.lower(),
            "witness_received_at": _parse_datetime(value["witness_received_at"])}

def _receipt_digest(checkpoint: IntegrityCheckpoint, receipt: Mapping[str, Any]) -> str:
    return hashlib.sha256(receipt_message(schema_version=receipt["schema_version"],
        external_anchor_id=receipt["external_anchor_id"], namespace=receipt["namespace"],
        checkpoint_sequence=receipt["checkpoint_sequence"], checkpoint_digest_value=receipt["checkpoint_digest"],
        previous_checkpoint_digest=checkpoint.previous_checkpoint_digest, created_at=checkpoint.created_at,
        witness_received_at=receipt["witness_received_at"], signer_key_id=receipt["signer_key_id"])).hexdigest()

class WitnessProvider(Protocol):
    def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def latest(self, namespace: str) -> Mapping[str, Any] | None: ...

class FakeWitnessProvider:
    """Deterministic test seam; production uses HttpSignedWitnessProvider."""
    def __init__(self, private_key: Any, signer_key_id: str = "witness-test-v1"):
        self.private_key, self.signer_key_id, self.anchors = private_key, signer_key_id, {}
    def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        from uuid import uuid4
        received = datetime.now(timezone.utc)
        identity = (request["namespace"], request["checkpoint_sequence"])
        existing = self.anchors.get(identity)
        if existing and existing["checkpoint_digest"] != request["checkpoint_digest"]: raise AnchorConflictError("witness conflict")
        if existing: return existing
        anchor_id = str(uuid4())
        body = {"schema_version": ANCHOR_PROTOCOL_VERSION, "external_anchor_id": anchor_id,
            "namespace": request["namespace"], "checkpoint_sequence": request["checkpoint_sequence"],
            "checkpoint_digest": request["checkpoint_digest"], "witness_received_at": canonical_timestamp(received),
            "signer_key_id": self.signer_key_id}
        message = receipt_message(schema_version=body["schema_version"], external_anchor_id=anchor_id,
            namespace=body["namespace"], checkpoint_sequence=body["checkpoint_sequence"],
            checkpoint_digest_value=body["checkpoint_digest"], previous_checkpoint_digest=request.get("previous_checkpoint_digest"),
            created_at=_parse_datetime(request["created_at"]), witness_received_at=received, signer_key_id=self.signer_key_id)
        body["signature"] = base64.b64encode(self.private_key.sign(message)).decode("ascii")
        self.anchors[identity] = body
        return body
    def latest(self, namespace: str) -> Mapping[str, Any] | None:
        rows = [v for (ns, _), v in self.anchors.items() if ns == namespace]
        return max(rows, key=lambda v: v["checkpoint_sequence"]) if rows else None

def _entries_for_snapshot(db: Session, settings: Settings) -> list[dict[str, Any]]:
    heads = list(db.scalars(select(IntegrityChainHead).where(IntegrityChainHead.next_sequence > 1)))
    entries = []
    for head in heads:
        result = verify_trace_integrity(db, head.tenant_id, head.trace_id, settings)
        if result.status != "valid" and result.first_failure == "missing_integrity_record":
            # V17 may have removed only the eligible EventLog projection while
            # preserving IntegrityRecord and the chain head.  Re-verify the
            # complete history from the immutable segment plus the hot tail so
            # future V15 checkpoints remain usable after compaction.
            try:
                from agentguard_server.services.archive import ArchiveKeyring
                from agentguard_server.services.archive_store import S3ArchiveStore
                from agentguard_server.services.ledger import verify_mixed_ledger
                mixed = verify_mixed_ledger(
                    db, tenant_id=head.tenant_id, trace_id=head.trace_id,
                    store=S3ArchiveStore(settings),
                    keyring=ArchiveKeyring.from_settings(settings), settings=settings,
                )
            except Exception as exc:
                raise CheckpointEligibilityError("V17 mixed ledger is unavailable") from exc
            if mixed.status == "VALID":
                result = type("MixedIntegrityVerification", (), {"status": "valid", "first_failure": None})()
        if result.status != "valid": raise CheckpointEligibilityError(f"V3 evidence is not eligible: {result.first_failure or result.status}")
        if not head.head_mac: raise CheckpointEligibilityError("V3 chain head is missing")
        entries.append({"tenant_id": head.tenant_id, "trace_id": head.trace_id,
                        "tenant_chain_sequence": int(head.next_sequence) - 1, "tenant_chain_head_hash": head.head_mac})
    entries.sort(key=lambda x: (x["tenant_id"], x["trace_id"]))
    if len(entries) > settings.anchor_max_entries: raise CheckpointEligibilityError("checkpoint entry limit exceeded")
    return entries

def create_checkpoint(db: Session, *, settings: Settings | None = None, now: datetime | None = None,
                       force: bool = False) -> IntegrityCheckpoint | None:
    settings = settings or get_settings()
    namespace = validate_namespace(settings.anchor_namespace or "")
    db.rollback(); db.begin()
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": f"agentguard-anchor:{namespace}"})
    current = _utc(now) if now is not None else database_now(db)
    state = db.scalar(select(IntegrityAnchorState).where(IntegrityAnchorState.namespace == namespace).with_for_update())
    if state is None:
        state = IntegrityAnchorState(namespace=namespace, latest_checkpoint_sequence=0, updated_at=current, next_checkpoint_due_at=current)
        db.add(state); db.flush()
    if not force and state.next_checkpoint_due_at and state.next_checkpoint_due_at > current:
        db.commit(); return None
    pending = db.scalar(select(func.count(IntegrityAnchorJob.id)).where(IntegrityAnchorJob.status.in_(["PENDING", "IN_FLIGHT", "RETRY_WAIT"]))) or 0
    if pending >= settings.anchor_max_pending_jobs:
        db.commit(); return None
    entries = _entries_for_snapshot(db, settings)
    sequence, previous = int(state.latest_checkpoint_sequence) + 1, state.latest_checkpoint_digest
    manifest = manifest_digest(entries)
    digest = checkpoint_digest(namespace=namespace, checkpoint_sequence=sequence, manifest_digest_value=manifest,
                              previous_checkpoint_digest=previous, created_at=current, entry_count=len(entries))
    checkpoint = IntegrityCheckpoint(namespace=namespace, checkpoint_sequence=sequence, checkpoint_version=CHECKPOINT_VERSION,
        manifest_digest=manifest, previous_checkpoint_digest=previous, checkpoint_digest=digest, entry_count=len(entries), created_at=current)
    db.add(checkpoint); db.flush()
    for entry in entries: db.add(IntegrityCheckpointEntry(checkpoint_id=checkpoint.id, **entry))
    if getattr(settings, "quorum_enabled", False):
        # V20 adds independent witness jobs while retaining the V15 checkpoint
        # identity and digest unchanged.
        from agentguard_server.services.quorum import ensure_configured_policy, enqueue_publish_jobs
        policy = ensure_configured_policy(db, settings=settings, now=current)
        if policy is None:
            raise CheckpointEligibilityError("V20 quorum policy is unavailable")
        checkpoint.policy_epoch, checkpoint.policy_digest = policy.policy_epoch, policy.policy_digest
        enqueue_publish_jobs(db, checkpoint=checkpoint, policy=policy, now=current)
    state.latest_checkpoint_sequence, state.latest_checkpoint_digest = sequence, digest
    state.last_checkpoint_at, state.next_checkpoint_due_at, state.updated_at = current, current + timedelta(seconds=settings.anchor_interval_seconds), current
    if settings.anchor_enabled and not getattr(settings, "quorum_enabled", False):
        db.add(IntegrityAnchorJob(checkpoint_id=checkpoint.id, status="PENDING", created_at=current, updated_at=current))
    db.commit(); db.refresh(checkpoint)
    logger.info("checkpoint_created namespace=%s sequence=%s entry_count=%s", namespace, sequence, len(entries))
    return checkpoint

def _local_latest(db: Session, namespace: str) -> IntegrityCheckpoint | None:
    return db.scalar(select(IntegrityCheckpoint).where(IntegrityCheckpoint.namespace == namespace).order_by(IntegrityCheckpoint.checkpoint_sequence.desc()).limit(1))

def verify_checkpoint(db: Session, checkpoint_id: UUID, *, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings(); checkpoint = db.get(IntegrityCheckpoint, checkpoint_id)
    if checkpoint is None: raise LookupError("checkpoint not found")
    entries = [{"tenant_id": e.tenant_id, "trace_id": e.trace_id, "tenant_chain_sequence": e.tenant_chain_sequence, "tenant_chain_head_hash": e.tenant_chain_head_hash}
               for e in db.scalars(select(IntegrityCheckpointEntry).where(IntegrityCheckpointEntry.checkpoint_id == checkpoint.id))]
    if manifest_digest(entries) != checkpoint.manifest_digest or len(entries) != checkpoint.entry_count:
        return {"status": "INVALID_CHECKPOINT", "checkpoint_id": str(checkpoint.id)}
    expected = checkpoint_digest(namespace=checkpoint.namespace, checkpoint_sequence=checkpoint.checkpoint_sequence,
        manifest_digest_value=checkpoint.manifest_digest, previous_checkpoint_digest=checkpoint.previous_checkpoint_digest,
        created_at=checkpoint.created_at, entry_count=checkpoint.entry_count)
    if expected != checkpoint.checkpoint_digest: return {"status": "INVALID_CHECKPOINT", "checkpoint_id": str(checkpoint.id)}
    previous = db.scalar(select(IntegrityCheckpoint).where(IntegrityCheckpoint.namespace == checkpoint.namespace,
        IntegrityCheckpoint.checkpoint_sequence == checkpoint.checkpoint_sequence - 1)) if checkpoint.checkpoint_sequence > 1 else None
    if (checkpoint.checkpoint_sequence == 1 and checkpoint.previous_checkpoint_digest is not None) or (checkpoint.checkpoint_sequence > 1 and (previous is None or previous.checkpoint_digest != checkpoint.previous_checkpoint_digest)):
        return {"status": "CHECKPOINT_CHAIN_DIVERGED", "checkpoint_id": str(checkpoint.id)}
    result = {"status": "NOT_ANCHORED", "checkpoint_id": str(checkpoint.id), "checkpoint_sequence": checkpoint.checkpoint_sequence, "checkpoint_digest": checkpoint.checkpoint_digest}
    receipt = db.scalar(select(ExternalAnchorReceipt).where(ExternalAnchorReceipt.checkpoint_id == checkpoint.id))
    if receipt is None: return result
    if receipt.namespace != checkpoint.namespace or receipt.checkpoint_sequence != checkpoint.checkpoint_sequence or receipt.checkpoint_digest != checkpoint.checkpoint_digest:
        return {**result, "status": "ANCHOR_DIGEST_MISMATCH"}
    receipt_data = {"schema_version": receipt.anchor_protocol_version, "external_anchor_id": receipt.external_anchor_id, "namespace": receipt.namespace,
        "checkpoint_sequence": receipt.checkpoint_sequence, "checkpoint_digest": receipt.checkpoint_digest, "witness_received_at": receipt.witness_received_at,
        "signer_key_id": receipt.signer_key_id, "signature": receipt.signature}
    if receipt.receipt_digest != _receipt_digest(checkpoint, receipt_data): return {**result, "status": "ANCHOR_DIGEST_MISMATCH"}
    keys = configured_verify_keys(settings)
    if receipt.signer_key_id not in keys: return {**result, "status": "UNVERIFIABLE_WITNESS_KEY_MISSING", "signer_key_id": receipt.signer_key_id}
    message = receipt_message(schema_version=receipt.anchor_protocol_version, external_anchor_id=receipt.external_anchor_id,
        namespace=receipt.namespace, checkpoint_sequence=receipt.checkpoint_sequence, checkpoint_digest_value=receipt.checkpoint_digest,
        previous_checkpoint_digest=checkpoint.previous_checkpoint_digest, created_at=checkpoint.created_at,
        witness_received_at=receipt.witness_received_at, signer_key_id=receipt.signer_key_id)
    if not verify_receipt_signature(message, receipt.signature, receipt.signer_key_id, keys):
        return {**result, "status": "INVALID_RECEIPT_SIGNATURE", "signer_key_id": receipt.signer_key_id}
    return {**result, "status": "VALID", "signer_key_id": receipt.signer_key_id, "witness_received_at": canonical_timestamp(receipt.witness_received_at)}

def claim_anchor_job(db: Session, *, job_id: UUID | None = None, now: datetime | None = None,
                     instance_id: str | None = None, settings: Settings | None = None) -> IntegrityAnchorJob | None:
    settings = settings or get_settings(); current = _utc(now) if now else database_now(db)
    owner, token = (instance_id or settings.instance_id)[:128], secrets.token_urlsafe(24)
    conditions = [IntegrityAnchorJob.status.in_(["PENDING", "RETRY_WAIT", "IN_FLIGHT"]), or_(IntegrityAnchorJob.next_attempt_at.is_(None), IntegrityAnchorJob.next_attempt_at <= current),
                  or_(IntegrityAnchorJob.lease_expires_at.is_(None), IntegrityAnchorJob.lease_expires_at <= current)]
    if job_id is not None: conditions.append(IntegrityAnchorJob.id == job_id)
    stmt = update(IntegrityAnchorJob).where(and_(*conditions)).values(status="IN_FLIGHT", claimed_by=owner, claim_token=token, claimed_at=current,
        lease_expires_at=current + timedelta(seconds=settings.anchor_lease_seconds), attempt_count=IntegrityAnchorJob.attempt_count + 1,
        updated_at=current).returning(IntegrityAnchorJob.id)
    claimed = db.execute(stmt).scalar_one_or_none(); db.commit()
    return db.get(IntegrityAnchorJob, claimed) if claimed else None

def _finish_job(db: Session, job_id: UUID, claim_token: str, *, receipt: Mapping[str, Any] | None,
                failure: AnchorFailure | None, settings: Settings, now: datetime) -> IntegrityAnchorJob | None:
    job = db.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.id == job_id).with_for_update())
    if job is None or job.claim_token != claim_token: db.rollback(); return job
    if receipt is not None:
        checkpoint = db.get(IntegrityCheckpoint, job.checkpoint_id)
        try: parsed = parse_receipt(receipt)
        except AnchorPermanentError: failure = AnchorFailure("PROTOCOL", False)
        else:
            if parsed["namespace"] != checkpoint.namespace or parsed["checkpoint_sequence"] != checkpoint.checkpoint_sequence or parsed["checkpoint_digest"] != checkpoint.checkpoint_digest:
                failure = AnchorFailure("DIGEST_MISMATCH", False)
            else:
                if db.scalar(select(ExternalAnchorReceipt).where(ExternalAnchorReceipt.checkpoint_id == checkpoint.id)) is None:
                    db.add(ExternalAnchorReceipt(checkpoint_id=checkpoint.id, anchor_protocol_version=parsed["schema_version"],
                        external_anchor_id=parsed["external_anchor_id"], namespace=parsed["namespace"], checkpoint_sequence=parsed["checkpoint_sequence"],
                        checkpoint_digest=parsed["checkpoint_digest"], witness_received_at=parsed["witness_received_at"], signer_key_id=parsed["signer_key_id"],
                        signature=parsed["signature"], receipt_digest=_receipt_digest(checkpoint, parsed), received_at=now))
                job.status, failure = "DELIVERED", None
    if failure:
        job.last_failure_category = failure.category
        if failure.retryable and job.attempt_count < settings.anchor_retry_max_attempts:
            delay = min(settings.anchor_retry_max_seconds, settings.anchor_retry_base_seconds * 2 ** max(0, job.attempt_count - 1))
            job.status, job.next_attempt_at = "RETRY_WAIT", now + timedelta(seconds=delay)
        else: job.status, job.next_attempt_at = "FAILED", None
    job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None; job.updated_at = now
    db.commit(); db.refresh(job); return job

def anchor_job(db: Session, job_id: UUID, provider: WitnessProvider, *, settings: Settings | None = None,
               now: datetime | None = None) -> IntegrityAnchorJob | None:
    settings = settings or get_settings(); current = _utc(now) if now else database_now(db)
    claimed = claim_anchor_job(db, job_id=job_id, now=current, settings=settings)
    if claimed is None: return db.get(IntegrityAnchorJob, job_id)
    checkpoint = db.get(IntegrityCheckpoint, claimed.checkpoint_id)
    claim_token = claimed.claim_token or ""
    request = {"schema_version": ANCHOR_PROTOCOL_VERSION, "namespace": checkpoint.namespace,
        "checkpoint_sequence": checkpoint.checkpoint_sequence, "checkpoint_digest": checkpoint.checkpoint_digest,
        "previous_checkpoint_digest": checkpoint.previous_checkpoint_digest, "created_at": canonical_timestamp(checkpoint.created_at)}
    try: receipt = provider.submit(request)
    except AnchorConflictError: return _finish_job(db, claimed.id, claim_token, receipt=None, failure=AnchorFailure("CONFLICT", False), settings=settings, now=current)
    except AnchorUnavailable: return _finish_job(db, claimed.id, claim_token, receipt=None, failure=AnchorFailure("WITNESS_UNAVAILABLE", True), settings=settings, now=current)
    except AnchorPermanentError: return _finish_job(db, claimed.id, claim_token, receipt=None, failure=AnchorFailure("PROTOCOL", False), settings=settings, now=current)
    return _finish_job(db, claimed.id, claim_token, receipt=receipt, failure=None, settings=settings, now=current)

def remote_continuity(db: Session, provider: WitnessProvider, *, settings: Settings | None = None) -> Continuity:
    settings = settings or get_settings(); namespace = validate_namespace(settings.anchor_namespace or "")
    local = _local_latest(db, namespace)
    try: remote = provider.latest(namespace)
    except (AnchorUnavailable, AnchorPermanentError): return Continuity("WITNESS_UNAVAILABLE", local_sequence=local.checkpoint_sequence if local else None, local_digest=local.checkpoint_digest if local else None)
    if remote is None: return Continuity("NEVER_ANCHORED", local_sequence=local.checkpoint_sequence if local else None, local_digest=local.checkpoint_digest if local else None)
    rs, rd = int(remote["checkpoint_sequence"]), str(remote["checkpoint_digest"]).lower()
    if local is None: status = "REMOTE_AHEAD"

    elif local.checkpoint_sequence == rs and local.checkpoint_digest == rd: status = "MATCH"
    elif rs > local.checkpoint_sequence: status = "REMOTE_AHEAD"
    elif local.checkpoint_sequence > rs: status = "LOCAL_AHEAD"
    else: status = "DIVERGED"
    return Continuity(status, local_sequence=local.checkpoint_sequence if local else None, remote_sequence=rs,
                      local_digest=local.checkpoint_digest if local else None, remote_digest=rd)

def freshness(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> dict[str, Any]:
    settings = settings or get_settings(); current = _utc(now) if now else database_now(db)
    receipt = db.scalar(select(ExternalAnchorReceipt).where(ExternalAnchorReceipt.namespace == validate_namespace(settings.anchor_namespace or "")).order_by(ExternalAnchorReceipt.received_at.desc()).limit(1))
    if receipt is None: return {"status": "NEVER_ANCHORED", "last_successful_anchor_at": None}
    last = _utc(receipt.received_at); age = max(0, int((current - last).total_seconds()))
    return {"status": "FRESH" if age <= settings.anchor_max_age_seconds else "STALE", "last_successful_anchor_at": canonical_timestamp(last), "age_seconds": age}







class HttpSignedWitnessProvider:
    """Trusted-config endpoint with pinned resolution, TLS, and no redirects."""
    def __init__(self, settings: Settings):
        self.settings = settings

    def _target(self, suffix: str = "") -> WebhookTarget:
        endpoint = (self.settings.anchor_endpoint or "").rstrip("/") + suffix
        try:
            return validate_webhook_url(endpoint, allow_private_test=self.settings.allow_private_anchor_tests,
                                        environment=self.settings.environment)
        except NotificationSecurityError as exc:
            if str(exc) in {"webhook host cannot be resolved", "webhook host has no usable address"}:
                raise AnchorUnavailable("witness unavailable") from exc
            raise AnchorPermanentError("witness endpoint is not allowed") from exc

    @staticmethod
    def _send(target: WebhookTarget, payload: bytes, timeout: float) -> tuple[int, bytes]:
        sock = None
        try:
            sock = socket.create_connection((target.resolved_addresses[0], target.port), timeout=timeout)
        except (OSError, TimeoutError) as exc:
            raise AnchorUnavailable("witness unavailable") from exc
        try:
            sock.settimeout(timeout)
            if target.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target.host)
            request = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
            request.sock = sock
            request.putrequest("POST", target.path, skip_host=True, skip_accept_encoding=True)
            request.putheader("Host", target.host if target.port in {80, 443} else f"{target.host}:{target.port}")
            request.putheader("Content-Type", "application/json")
            request.putheader("Accept", "application/json")
            request.putheader("Content-Length", str(len(payload)))
            request.endheaders(payload)
            response = request.getresponse()
            body = response.read(256 * 1024 + 1)
            if len(body) > 256 * 1024: raise AnchorPermanentError("witness response is too large")
            return response.status, body
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            raise AnchorUnavailable("witness unavailable") from exc
        finally:
            if sock is not None:
                try: sock.close()
                except OSError: pass

    def _request(self, suffix: str, body: Mapping[str, Any]) -> Mapping[str, Any] | None:
        try: status, raw = self._send(self._target(suffix), canonical_json(body), self.settings.anchor_request_timeout_seconds)
        except AnchorUnavailable: raise
        if status == 409: raise AnchorConflictError("witness rejected a conflicting checkpoint")
        if status == 429 or status >= 500 or status in {408, 425}: raise AnchorUnavailable("witness temporary failure")
        if not 200 <= status < 300: raise AnchorPermanentError("witness request was rejected")
        if not raw: return None
        try: value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise AnchorPermanentError("witness returned invalid JSON") from exc
        if not isinstance(value, dict): raise AnchorPermanentError("witness returned invalid JSON")
        return value

    def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        value = self._request("", request)
        if value is None: raise AnchorPermanentError("witness receipt is missing")
        return value

    def latest(self, namespace: str) -> Mapping[str, Any] | None:
        value = self._request("/latest", {"schema_version": ANCHOR_PROTOCOL_VERSION, "namespace": validate_namespace(namespace)})
        return parse_receipt(value) if value else None







def run_anchor_cycle(db: Session, *, settings: Settings | None = None) -> list[IntegrityAnchorJob]:
    """Wake-up operation; PostgreSQL state/leases remain the distributed authority."""
    settings = settings or get_settings()
    if not settings.anchor_enabled:
        return []
    try:
        create_checkpoint(db, settings=settings)
    except CheckpointEligibilityError as exc:
        db.rollback()
        logger.warning("checkpoint_not_created reason=%s", type(exc).__name__)
    jobs = list(db.scalars(select(IntegrityAnchorJob).where(
        IntegrityAnchorJob.status.in_(["PENDING", "RETRY_WAIT", "IN_FLIGHT"]),
    ).order_by(IntegrityAnchorJob.created_at).limit(settings.anchor_max_pending_jobs)))
    provider = HttpSignedWitnessProvider(settings)
    completed = []
    for job in jobs:
        result = anchor_job(db, job.id, provider, settings=settings)
        if result is not None:
            completed.append(result)
    return completed


