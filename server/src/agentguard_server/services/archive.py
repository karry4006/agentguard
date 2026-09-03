"""Deterministic trace archiving, encryption, and integrity verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import gzip
import hashlib
import json
import secrets
import zlib
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import ArchiveLifecycle, ArchiveRecord, EventLog, IntegrityCheckpoint, IntegrityCheckpointEntry, IntegrityRecord, Span, Trace
from agentguard_server.services.archive_store import ArchiveObjectConflict, ArchiveObjectMissing, ArchiveStore, ArchiveStoreError
from agentguard_server.services.anchoring import remote_continuity, verify_checkpoint
from agentguard_server.services.integrity import verify_trace_integrity

ARCHIVE_FORMAT_VERSION = "trace-archive-v1"
ARCHIVE_ENVELOPE_VERSION = "archive-envelope-v1"
MAX_ARCHIVE_DEPTH = 16


class ArchiveError(ValueError):
    pass


class ArchiveEligibilityError(ArchiveError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ArchiveVerificationError(ArchiveError):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class ArchiveKeyMissing(ArchiveVerificationError):
    def __init__(self):
        super().__init__("UNVERIFIABLE_ARCHIVE_KEY_MISSING")


@dataclass(frozen=True)
class ArchiveKeyring:
    keys: Mapping[str, bytes]
    current_key_id: str

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "ArchiveKeyring":
        settings = settings or get_settings()
        raw = settings.archive_encryption_keys
        if not raw and settings.archive_encryption_keys_file:
            try:
                raw = Path(settings.archive_encryption_keys_file).read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ValueError("archive encryption key registry is unavailable") from exc
        if not raw:
            raise ValueError("archive encryption key registry is required")
        try:
            values = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("archive encryption key registry is invalid") from exc
        if not isinstance(values, dict) or not values:
            raise ValueError("archive encryption key registry is invalid")
        decoded: dict[str, bytes] = {}
        for key_id, value in values.items():
            if not isinstance(key_id, str) or not key_id or len(key_id) > 128 or not isinstance(value, str):
                raise ValueError("archive encryption key registry is invalid")
            try:
                key = base64.b64decode(value.encode("ascii"), validate=True)
            except (ValueError, UnicodeError):
                try:
                    key = bytes.fromhex(value)
                except ValueError as exc:
                    raise ValueError("archive encryption key registry is invalid") from exc
            if len(key) != 32:
                raise ValueError("archive encryption keys must be 32 bytes")
            decoded[key_id] = key
        if settings.archive_encryption_key_id not in decoded:
            raise ValueError("current archive encryption key id is missing")
        return cls(decoded, settings.archive_encryption_key_id)

    def key_for(self, key_id: str) -> bytes:
        key = self.keys.get(key_id)
        if key is None:
            raise ArchiveKeyMissing()
        return key


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        current = value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return current.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported archive value: {type(value).__name__}")


def canonical_archive_json(value: Mapping[str, Any]) -> bytes:
    """Canonical UTF-8 JSON used for both digesting and archive plaintext."""
    return json.dumps(_json_value(dict(value)), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def source_projection_digest(source_projection: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_archive_json(source_projection)).hexdigest()


def deterministic_gzip(value: bytes) -> bytes:
    return gzip.compress(value, compresslevel=9, mtime=0)


def _validate_archive_tree(value: Any, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = count or [0]
    if depth > MAX_ARCHIVE_DEPTH:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    count[0] += 1
    if count[0] > 200_000:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 512:
                raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
            _validate_archive_tree(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _validate_archive_tree(item, depth=depth + 1, count=count)
    elif isinstance(value, str) and len(value) > 1_000_000:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")


def _aad(*, archive_id: UUID, tenant_id: UUID, trace_id: str, archive_version: str) -> bytes:
    return canonical_archive_json({
        "envelope_version": ARCHIVE_ENVELOPE_VERSION,
        "archive_id": archive_id,
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "archive_version": archive_version,
    })


@dataclass(frozen=True)
class SealedArchive:
    object_bytes: bytes
    plaintext: bytes
    compressed: bytes
    ciphertext: bytes
    key_id: str
    plaintext_sha256: str
    compressed_sha256: str
    ciphertext_sha256: str


def seal_archive(*, archive_id: UUID, tenant_id: UUID, trace_id: str, plaintext: bytes, keyring: ArchiveKeyring, archive_version: str = ARCHIVE_FORMAT_VERSION) -> SealedArchive:
    compressed = deterministic_gzip(plaintext)
    key_id = keyring.current_key_id
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(keyring.key_for(key_id)).encrypt(nonce, compressed, _aad(archive_id=archive_id, tenant_id=tenant_id, trace_id=trace_id, archive_version=archive_version))
    envelope = {
        "envelope_version": ARCHIVE_ENVELOPE_VERSION,
        "archive_version": archive_version,
        "archive_id": archive_id,
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "key_id": key_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
    }
    return SealedArchive(
        object_bytes=canonical_archive_json(envelope), plaintext=plaintext, compressed=compressed, ciphertext=ciphertext,
        key_id=key_id, plaintext_sha256=envelope["plaintext_sha256"], compressed_sha256=envelope["compressed_sha256"], ciphertext_sha256=envelope["ciphertext_sha256"],
    )


def _bounded_gunzip(value: bytes, max_bytes: int) -> bytes:
    if len(value) > max_bytes:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    for offset in range(0, len(value), 64 * 1024):
        output.extend(decompressor.decompress(value[offset:offset + 64 * 1024], max_bytes - len(output) + 1))
        if len(output) > max_bytes:
            raise ArchiveVerificationError("ARCHIVE_DECOMPRESSION_LIMIT")
    output.extend(decompressor.flush(max_bytes - len(output) + 1))
    if len(output) > max_bytes or not decompressor.eof:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    return bytes(output)


@dataclass(frozen=True)
class VerifiedArchive:
    envelope: dict[str, Any]
    payload: dict[str, Any]
    plaintext: bytes
    compressed: bytes
    ciphertext: bytes


def unseal_archive(*, object_bytes: bytes, archive_id: UUID, tenant_id: UUID, trace_id: str, keyring: ArchiveKeyring, max_object_bytes: int = 64 * 1024 * 1024, max_decompressed_bytes: int = 64 * 1024 * 1024) -> VerifiedArchive:
    if len(object_bytes) > max_object_bytes:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    try:
        envelope = json.loads(object_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE") from exc
    required = {"envelope_version", "archive_version", "archive_id", "tenant_id", "trace_id", "key_id", "nonce", "ciphertext", "plaintext_sha256", "compressed_sha256", "ciphertext_sha256"}
    if not isinstance(envelope, dict) or set(envelope) != required or envelope["envelope_version"] != ARCHIVE_ENVELOPE_VERSION or envelope["archive_version"] != ARCHIVE_FORMAT_VERSION:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    if envelope["archive_id"] != str(archive_id) or envelope["tenant_id"] != str(tenant_id) or envelope["trace_id"] != trace_id:
        raise ArchiveVerificationError("ARCHIVE_IDENTITY_MISMATCH")
    try:
        nonce = base64.b64decode(envelope["nonce"].encode("ascii"), validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"].encode("ascii"), validate=True)
    except (ValueError, UnicodeError, AttributeError) as exc:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE") from exc
    if len(nonce) != 12 or hashlib.sha256(ciphertext).hexdigest() != envelope["ciphertext_sha256"]:
        raise ArchiveVerificationError("INVALID_ARCHIVE_CIPHERTEXT")
    try:
        compressed = AESGCM(keyring.key_for(str(envelope["key_id"]))).decrypt(nonce, ciphertext, _aad(archive_id=archive_id, tenant_id=tenant_id, trace_id=trace_id, archive_version=ARCHIVE_FORMAT_VERSION))
    except ArchiveKeyMissing:
        raise
    except (InvalidTag, ValueError) as exc:
        raise ArchiveVerificationError("INVALID_ARCHIVE_CIPHERTEXT") from exc
    if hashlib.sha256(compressed).hexdigest() != envelope["compressed_sha256"]:
        raise ArchiveVerificationError("ARCHIVE_DIGEST_MISMATCH")
    try:
        plaintext = _bounded_gunzip(compressed, max_decompressed_bytes)
    except (ArchiveVerificationError, zlib.error) as exc:
        if isinstance(exc, ArchiveVerificationError):
            raise
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE") from exc
    if hashlib.sha256(plaintext).hexdigest() != envelope["plaintext_sha256"]:
        raise ArchiveVerificationError("ARCHIVE_DIGEST_MISMATCH")
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE") from exc
    if not isinstance(payload, dict) or set(payload) != {"manifest", "source_projection"} or not isinstance(payload["manifest"], dict) or not isinstance(payload["source_projection"], dict):
        raise ArchiveVerificationError("INVALID_ARCHIVE_ENVELOPE")
    _validate_archive_tree(payload)
    manifest = payload["manifest"]
    if manifest.get("archive_id") != str(archive_id) or manifest.get("tenant_id") != str(tenant_id) or manifest.get("trace_id") != trace_id or manifest.get("archive_version") != ARCHIVE_FORMAT_VERSION:
        raise ArchiveVerificationError("ARCHIVE_IDENTITY_MISMATCH")
    if manifest.get("source_projection_digest") != source_projection_digest(payload["source_projection"]):
        raise ArchiveVerificationError("ARCHIVE_PROJECTION_DIGEST_MISMATCH")
    return VerifiedArchive(envelope=envelope, payload=payload, plaintext=plaintext, compressed=compressed, ciphertext=ciphertext)


def build_source_projection(db: Session, tenant_id: UUID, trace_id: str) -> dict[str, Any]:
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    if trace is None:
        raise ArchiveEligibilityError("TRACE_NOT_FOUND")
    spans = list(db.scalars(select(Span).where(Span.tenant_id == tenant_id, Span.trace_id == trace_id).order_by(Span.span_id)))
    return {
        "trace": {"trace_id": trace.trace_id, "workflow_name": trace.workflow_name, "group_id": trace.group_id, "provider": trace.provider, "started_at": trace.started_at, "ended_at": trace.ended_at, "status": trace.status, "metadata": trace.metadata_json or {}, "schema_version": trace.schema_version},
        "spans": [{"span_id": span.span_id, "trace_id": span.trace_id, "parent_span_id": span.parent_span_id, "span_type": span.span_type, "name": span.name, "started_at": span.started_at, "ended_at": span.ended_at, "duration_ms": span.duration_ms, "status": span.status, "error_type": span.error_type, "error_message": span.error_message, "attributes": span.attributes or {}, "schema_version": span.schema_version} for span in spans],
    }


def _covering_checkpoint(db: Session, tenant_id: UUID, trace_id: str, settings: Settings) -> tuple[Any, dict[str, Any]]:
    entries = list(db.scalars(select(IntegrityCheckpointEntry).where(IntegrityCheckpointEntry.tenant_id == tenant_id, IntegrityCheckpointEntry.trace_id == trace_id).order_by(IntegrityCheckpointEntry.tenant_chain_sequence.desc())))
    for entry in entries:
        # Avoid relying on an ORM relationship being loaded in SQLite fixtures.
        checkpoint = db.get(IntegrityCheckpoint, entry.checkpoint_id)
        if checkpoint is None:
            continue
        verification = verify_checkpoint(db, checkpoint.id, settings=settings)
        if verification.get("status") == "VALID":
            return checkpoint, verification
    raise ArchiveEligibilityError("V15_COVERAGE_INVALID")


def check_archive_eligibility(db: Session, tenant_id: UUID, trace_id: str, *, settings: Settings | None = None, now: datetime | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    current = now or datetime.now(timezone.utc)
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    if trace is None:
        raise ArchiveEligibilityError("TRACE_NOT_FOUND")
    if not trace.ended_at:
        raise ArchiveEligibilityError("TRACE_NOT_FINALIZED")
    ended = trace.ended_at if trace.ended_at.tzinfo else trace.ended_at.replace(tzinfo=timezone.utc)
    threshold = timedelta(days=settings.archive_after_days + settings.retention_finalization_grace_days)
    if ended.astimezone(timezone.utc) > current.astimezone(timezone.utc) - threshold:
        raise ArchiveEligibilityError("TRACE_TOO_RECENT")
    integrity = verify_trace_integrity(db, tenant_id, trace_id, settings)
    if integrity.status != "valid":
        raise ArchiveEligibilityError("V3_INTEGRITY_INVALID")
    checkpoint, verification = _covering_checkpoint(db, tenant_id, trace_id, settings)
    spans = list(db.scalars(select(Span).where(Span.tenant_id == tenant_id, Span.trace_id == trace_id)))
    if len(canonical_archive_json(build_source_projection(db, tenant_id, trace_id))) > settings.archive_max_plaintext_bytes:
        raise ArchiveEligibilityError("ARCHIVE_SIZE_LIMIT")
    sequences = list(db.scalars(select(IntegrityRecord.sequence).where(IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id).order_by(IntegrityRecord.sequence)))
    return {"trace": trace, "checkpoint": checkpoint, "checkpoint_verification": verification, "span_count": len(spans), "source_v3_min_sequence": min(sequences) if sequences else None, "source_v3_max_sequence": max(sequences) if sequences else None}


def archive_payload(db: Session, tenant_id: UUID, trace_id: str, archive_id: UUID, checkpoint: Any, *, now: datetime | None = None) -> tuple[bytes, dict[str, Any]]:
    source = build_source_projection(db, tenant_id, trace_id)
    source_digest = source_projection_digest(source)
    manifest = {"archive_version": ARCHIVE_FORMAT_VERSION, "archive_id": archive_id, "tenant_id": tenant_id, "trace_id": trace_id, "created_at": now or datetime.now(timezone.utc), "source_projection_digest": source_digest, "covering_checkpoint_sequence": checkpoint.checkpoint_sequence, "covering_checkpoint_digest": checkpoint.checkpoint_digest, "trace_count": 1, "span_count": len(source["spans"])}
    payload = {"manifest": manifest, "source_projection": source}
    return canonical_archive_json(payload), manifest


def verify_stored_archive(db: Session, record: ArchiveRecord, store: ArchiveStore, keyring: ArchiveKeyring, *, settings: Settings | None = None) -> VerifiedArchive:
    settings = settings or get_settings()
    try:
        body = store.get(record.object_key)
    except ArchiveObjectMissing as exc:
        raise ArchiveVerificationError("ARCHIVE_OBJECT_MISSING") from exc
    except ArchiveStoreError as exc:
        raise ArchiveVerificationError("OBJECT_STORE_UNAVAILABLE") from exc
    verified = unseal_archive(object_bytes=body, archive_id=record.id, tenant_id=record.tenant_id, trace_id=record.trace_id, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
    if record.ciphertext_sha256 and verified.envelope["ciphertext_sha256"] != record.ciphertext_sha256:
        raise ArchiveVerificationError("ARCHIVE_DIGEST_MISMATCH")
    if record.source_projection_digest and verified.payload["manifest"]["source_projection_digest"] != record.source_projection_digest:
        raise ArchiveVerificationError("ARCHIVE_PROJECTION_DIGEST_MISMATCH")
    return verified


# Stable descriptive aliases for callers that do not need implementation
# details in the function names.
canonicalize_archive = canonical_archive_json
compress_archive = deterministic_gzip
encrypt_archive = seal_archive
decrypt_archive = unseal_archive
