"""V20 multi-witness external evidence aggregation.

This module is intentionally an evidence evaluator, not a consensus
protocol.  Witnesses are independently trusted operator-configured sources;
valid contradictory evidence is retained and blocks destructive work.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol, Sequence
from uuid import UUID

from sqlalchemy import and_, case, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import (
    CheckpointQuorumEvaluation, CheckpointWitnessReceipt, IntegrityCheckpoint,
    Witness, WitnessHealthSnapshot, WitnessPublishJob, WitnessQuorumPolicy,
    WitnessQuorumPolicyMember, WitnessVerificationKey,
)
from agentguard_server.services.rate_limit import database_now

logger = logging.getLogger("agentguard.quorum")

POLICY_VERSION = "witness-quorum-policy-v1"
RECEIPT_VERSION = "multi-witness-receipt-v1"
QUORUM_MATCH = "QUORUM_MATCH"
QUORUM_MATCH_DEGRADED = "QUORUM_MATCH_DEGRADED"
QUORUM_UNAVAILABLE = "QUORUM_UNAVAILABLE"
QUORUM_LOCAL_AHEAD = "QUORUM_LOCAL_AHEAD"
QUORUM_REMOTE_AHEAD = "QUORUM_REMOTE_AHEAD"
QUORUM_DIVERGED = "QUORUM_DIVERGED"
QUORUM_HARD_CONFLICT = "QUORUM_HARD_CONFLICT"
QUORUM_INVALID_SIGNATURE = "QUORUM_INVALID_SIGNATURE"
QUORUM_POLICY_INVALID = "QUORUM_POLICY_INVALID"
QUORUM_STALE = "QUORUM_STALE"
QUORUM_UNVERIFIABLE_KEY = "QUORUM_UNVERIFIABLE_KEY"
BLOCKING_STATES = {QUORUM_UNAVAILABLE, QUORUM_LOCAL_AHEAD, QUORUM_REMOTE_AHEAD,
                   QUORUM_DIVERGED, QUORUM_HARD_CONFLICT, QUORUM_INVALID_SIGNATURE,
                   QUORUM_POLICY_INVALID, QUORUM_STALE, QUORUM_UNVERIFIABLE_KEY}
_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class QuorumError(ValueError):
    pass


class InvalidWitnessConfiguration(QuorumError):
    pass


class PolicyValidationError(QuorumError):
    pass


class PolicyDowngradeError(PolicyValidationError):
    pass


class ReceiptValidationError(QuorumError):
    pass


class UnknownWitnessKeyError(ReceiptValidationError):
    pass


class WitnessUnavailable(QuorumError):
    pass


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def canonical_witness_id(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidWitnessConfiguration("witness_id must be a string")
    value = value.strip().lower()
    if not _ID.fullmatch(value):
        raise InvalidWitnessConfiguration("witness_id is invalid")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ReceiptValidationError("receipt timestamp must include timezone")
        return utc(value)
    if not isinstance(value, str) or len(value) > 64:
        raise ReceiptValidationError("receipt timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptValidationError("receipt timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ReceiptValidationError("receipt timestamp must include timezone")
    return utc(parsed)


def _decode_key(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        try:
            raw = bytes.fromhex(value) if re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()) else base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise InvalidWitnessConfiguration("verification key is invalid") from None
    else:
        raise InvalidWitnessConfiguration("verification key is invalid")
    if len(raw) != 32:
        raise InvalidWitnessConfiguration("Ed25519 verification key must be 32 bytes")
    return raw


def policy_document(*, policy_version: str, policy_epoch: int, threshold: int,
                    witness_ids: Sequence[str], strict_conflict_blocking: bool,
                    allow_degraded_match: bool, receipt_freshness_seconds: int,
                    quorum_freshness_seconds: int, conflict_behavior: str) -> dict[str, Any]:
    members = sorted({canonical_witness_id(item) for item in witness_ids})
    return {"allow_degraded_match": bool(allow_degraded_match),
            "conflict_behavior": conflict_behavior,
            "member_count": len(members), "policy_epoch": int(policy_epoch),
            "policy_version": policy_version, "quorum_freshness_seconds": int(quorum_freshness_seconds),
            "receipt_freshness_seconds": int(receipt_freshness_seconds),
            "strict_conflict_blocking": bool(strict_conflict_blocking),
            "threshold": int(threshold), "witness_ids": members}


def policy_digest(**kwargs: Any) -> str:
    return hashlib.sha256(canonical_json(policy_document(**kwargs))).hexdigest()


def _receipt_unsigned(receipt: Mapping[str, Any]) -> dict[str, Any]:
    result = {key: receipt[key] for key in receipt if key != "signature"}
    if isinstance(result.get("observed_at"), datetime):
        result["observed_at"] = utc(result["observed_at"]).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return result


def receipt_signing_bytes(receipt: Mapping[str, Any]) -> bytes:
    candidate = dict(receipt)
    # Signing is performed before the signature field exists. A fixed-length
    # placeholder lets the same strict schema validation protect both paths.
    candidate.setdefault("signature", base64.b64encode(bytes(64)).decode("ascii"))
    parsed = validate_receipt(candidate, verify_signature=False)
    return canonical_json(_receipt_unsigned(parsed))


def receipt_payload_hash(receipt: Mapping[str, Any]) -> str:
    parsed = validate_receipt(receipt, verify_signature=False)
    payload = dict(parsed)
    if isinstance(payload.get("observed_at"), datetime):
        payload["observed_at"] = utc(payload["observed_at"]).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def verify_ed25519(message: bytes, signature: str, public_key: str | bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(_decode_key(public_key)).verify(
            base64.b64decode(signature, validate=True), message)
        return True
    except Exception:
        return False


def sign_receipt(receipt: Mapping[str, Any], private_key: Any) -> dict[str, Any]:
    """Sign a V20 receipt with a witness-owned private key.

    This helper is intended for witness implementations and tests; the
    private key is never persisted by AgentGuard.
    """
    candidate = dict(receipt)
    candidate.pop("signature", None)
    candidate["signature"] = base64.b64encode(private_key.sign(receipt_signing_bytes(candidate))).decode("ascii")
    return validate_receipt(candidate)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptValidationError("duplicate receipt key")
        result[key] = value
    return result


def validate_receipt(value: Mapping[str, Any] | bytes | str, *, verify_signature: bool = False,
                     public_key: str | bytes | None = None) -> dict[str, Any]:
    raw_value = value if isinstance(value, (bytes, str)) else None
    if isinstance(value, bytes):
        try:
            value = json.loads(value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReceiptValidationError("receipt JSON is invalid") from exc
    elif isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=_reject_duplicate_pairs)
        except json.JSONDecodeError as exc:
            raise ReceiptValidationError("receipt JSON is invalid") from exc
    if not isinstance(value, Mapping):
        raise ReceiptValidationError("receipt must be an object")
    required = {"receipt_version", "witness_id", "verification_key_id", "policy_epoch",
                "checkpoint_sequence", "checkpoint_digest", "witness_head_sequence",
                "witness_head_digest", "continuity_state", "observed_at", "signature"}
    if set(value) != required:
        raise ReceiptValidationError("receipt schema is invalid")
    witness_id = canonical_witness_id(value["witness_id"])
    key_id = value["verification_key_id"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise ReceiptValidationError("receipt verification key id is invalid")
    if value["receipt_version"] != RECEIPT_VERSION:
        raise ReceiptValidationError("receipt version is unsupported")
    if not isinstance(value["policy_epoch"], int) or value["policy_epoch"] < 1:
        raise ReceiptValidationError("receipt policy epoch is invalid")
    if not isinstance(value["checkpoint_sequence"], int) or value["checkpoint_sequence"] < 1:
        raise ReceiptValidationError("receipt checkpoint sequence is invalid")
    digest = value["checkpoint_digest"]
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest.lower()):
        raise ReceiptValidationError("receipt checkpoint digest is invalid")
    head_digest = value["witness_head_digest"]
    if head_digest is not None and (not isinstance(head_digest, str) or not _HEX64.fullmatch(head_digest.lower())):
        raise ReceiptValidationError("receipt witness head digest is invalid")
    if value["witness_head_sequence"] is not None and (not isinstance(value["witness_head_sequence"], int) or value["witness_head_sequence"] < 0):
        raise ReceiptValidationError("receipt witness head sequence is invalid")
    if value["continuity_state"] not in {"MATCH", "REMOTE_AHEAD", "LOCAL_AHEAD", "DIVERGED"}:
        raise ReceiptValidationError("receipt continuity state is invalid")
    signature = value["signature"]
    if not isinstance(signature, str) or not 1 <= len(signature) <= 256:
        raise ReceiptValidationError("receipt signature is invalid")
    try:
        if len(base64.b64decode(signature, validate=True)) != 64:
            raise ValueError
    except (ValueError, TypeError):
        raise ReceiptValidationError("receipt signature is invalid") from None
    result = dict(value)
    result.update(witness_id=witness_id, verification_key_id=key_id,
                  checkpoint_digest=digest.lower(), witness_head_digest=head_digest.lower() if head_digest else None,
                  observed_at=_parse_timestamp(value["observed_at"]))
    if raw_value is not None:
        raw_bytes = raw_value if isinstance(raw_value, bytes) else raw_value.encode("utf-8")
        if raw_bytes != canonical_json(value):
            raise ReceiptValidationError("receipt is not canonical JSON")
    if verify_signature and (public_key is None or not verify_ed25519(receipt_signing_bytes(result), signature, public_key)):
        raise ReceiptValidationError("receipt signature is invalid")
    return result


@dataclass(frozen=True)
class QuorumResult:
    state: str
    threshold: int
    member_count: int
    match_count: int = 0
    unavailable_count: int = 0
    conflict_count: int = 0
    invalid_signature_count: int = 0
    valid_receipt_count: int = 0
    matching_witness_ids: tuple[str, ...] = ()
    conflicting_witness_ids: tuple[str, ...] = ()
    receipt_set_digest: str = ""
    evaluation_digest: str = ""
    evaluated_at: datetime | None = None
    fresh_until: datetime | None = None
    blocking_reason: str | None = None

    @property
    def destructive_allowed(self) -> bool:
        return self.state in {QUORUM_MATCH, QUORUM_MATCH_DEGRADED}

    @property
    def status(self) -> str:
        return self.state

    def as_dict(self) -> dict[str, Any]:
        result = dict(self.__dict__)
        result.update(evaluated_at=self.evaluated_at.isoformat() if self.evaluated_at else None,
                      fresh_until=self.fresh_until.isoformat() if self.fresh_until else None,
                      destructive_allowed=self.destructive_allowed,
                      matching_witness_ids=list(self.matching_witness_ids),
                      conflicting_witness_ids=list(self.conflicting_witness_ids))
        return result


def _candidate_values(receipts: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[tuple[str | None, Any]]:
    if isinstance(receipts, Mapping):
        return [(str(key), value) for key, value in receipts.items()]
    result = []
    for item in receipts:
        if isinstance(item, Mapping) and "receipt" in item:
            result.append((str(item.get("witness_id")) if item.get("witness_id") is not None else None, item["receipt"]))
        else:
            result.append((None, item))
    return result


def evaluate_quorum(policy: WitnessQuorumPolicy | Mapping[str, Any],
                    receipts: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None, *,
                    members: Sequence[Any] | Mapping[str, Any] | None = None,
                    checkpoint_sequence: int, checkpoint_digest: str,
                    now: datetime | None = None,
                    public_keys: Mapping[str, str | bytes] | None = None) -> QuorumResult:
    """Evaluate only distinct configured witness identities.

    A valid contradictory receipt is never cancelled out by a majority.  An
    invalid response is not counted and is also a destructive-operation
    blocker under V20 policy v1.
    """
    if receipts is None:
        receipts = []
    current = utc(now or datetime.now(timezone.utc))
    if isinstance(policy, Mapping):
        threshold = int(policy["threshold"])
        epoch = int(policy["policy_epoch"])
        freshness = int(policy.get("receipt_freshness_seconds", 900))
        quorum_freshness = int(policy.get("quorum_freshness_seconds", 300))
        strict = bool(policy.get("strict_conflict_blocking", True))
        policy_ids = [canonical_witness_id(item) for item in policy.get("witness_ids", ())]
    else:
        threshold, epoch = policy.threshold, policy.policy_epoch
        freshness, quorum_freshness = policy.receipt_freshness_seconds, policy.quorum_freshness_seconds
        strict = policy.strict_conflict_blocking
        policy_ids = []
    if members is not None:
        if isinstance(members, Mapping):
            policy_ids = [canonical_witness_id(item) for item in members]
        else:
            members = list(members)
            policy_ids = [canonical_witness_id(getattr(item, "witness_id", item.get("witness_id") if isinstance(item, Mapping) else item)) for item in members]
    policy_ids = list(dict.fromkeys(policy_ids))
    member_count = len(policy_ids)
    if threshold < 1 or threshold > member_count:
        return QuorumResult(QUORUM_POLICY_INVALID, threshold, member_count, blocking_reason="INVALID_THRESHOLD")
    checkpoint_digest = checkpoint_digest.lower()
    seen: set[str] = set()
    matching: list[str] = []
    conflicts: list[str] = []
    local_ahead = False
    invalid = 0
    unknown_key = 0
    stale = 0
    valid = 0
    receipt_hashes: list[str] = []
    for supplied_id, candidate in _candidate_values(receipts):
        try:
            parsed = validate_receipt(candidate)
            witness_id = parsed["witness_id"]
            if parsed["policy_epoch"] != epoch:
                raise ReceiptValidationError("receipt policy epoch mismatch")
            if supplied_id and canonical_witness_id(supplied_id) != witness_id:
                raise ReceiptValidationError("witness identity mismatch")
            if witness_id not in policy_ids or witness_id in seen:
                continue
            seen.add(witness_id)
            expected_key = None
            if members is not None:
                member = members.get(witness_id) if isinstance(members, Mapping) else next((m for m in members if getattr(m, "witness_id", None) == witness_id), None)
                expected_key = (member.get("verification_key_id") if isinstance(member, Mapping) else getattr(member, "verification_key_id", None)) if member else None
            if expected_key and parsed["verification_key_id"] != expected_key:
                raise ReceiptValidationError("receipt key is not pinned for witness")
            key = public_keys.get(parsed["verification_key_id"]) if public_keys else None
            if key is not None and not verify_ed25519(receipt_signing_bytes(parsed), parsed["signature"], key):
                raise ReceiptValidationError("receipt signature is invalid")
            if key is None:
                raise UnknownWitnessKeyError("receipt key is unknown")
            valid += 1
            receipt_hashes.append(receipt_payload_hash(parsed))
            if current - parsed["observed_at"] > timedelta(seconds=freshness):
                stale += 1
            state = parsed["continuity_state"]
            if state == "LOCAL_AHEAD":
                local_ahead = True
            elif state in {"REMOTE_AHEAD", "DIVERGED"}:
                conflicts.append(witness_id)
            elif state == "MATCH" and parsed["checkpoint_sequence"] == checkpoint_sequence and parsed["checkpoint_digest"] == checkpoint_digest:
                matching.append(witness_id)
            else:
                conflicts.append(witness_id)
        except UnknownWitnessKeyError:
            unknown_key += 1
        except ReceiptValidationError:
            if supplied_id and canonical_witness_id(supplied_id) not in policy_ids:
                continue
            invalid += 1
    unavailable = member_count - len(seen)
    receipt_set_digest = hashlib.sha256(canonical_json(sorted(receipt_hashes))).hexdigest()
    state = QUORUM_UNAVAILABLE
    reason = None
    if unknown_key:
        state, reason = QUORUM_UNVERIFIABLE_KEY, "UNKNOWN_PUBLIC_KEY"
    elif invalid:
        state, reason = QUORUM_INVALID_SIGNATURE, "INVALID_WITNESS_SIGNATURE"
    elif conflicts and strict:
        state = QUORUM_REMOTE_AHEAD if any(
            isinstance(candidate, Mapping) and candidate.get("continuity_state") == "REMOTE_AHEAD" for _, candidate in _candidate_values(receipts)
        ) else QUORUM_DIVERGED
        reason = "HARD_CONFLICT_REMOTE_AHEAD" if state == QUORUM_REMOTE_AHEAD else "HARD_CONFLICT_DIVERGED"
    elif stale:
        state, reason = QUORUM_STALE, "STALE_RECEIPT"
    elif len(matching) >= threshold:
        state = QUORUM_MATCH_DEGRADED if unavailable else QUORUM_MATCH
    elif local_ahead:
        state, reason = QUORUM_LOCAL_AHEAD, "LOCAL_AHEAD_WITHOUT_QUORUM"
    elif len(matching) < threshold and checkpoint_sequence > 0:
        state, reason = QUORUM_UNAVAILABLE, "THRESHOLD_NOT_MET"
    if state in BLOCKING_STATES and reason is None:
        reason = state
    evaluation_payload = {"checkpoint_digest": checkpoint_digest, "checkpoint_sequence": checkpoint_sequence,
                          "conflicting_witness_ids": sorted(conflicts), "matching_witness_ids": sorted(matching),
                          "policy_epoch": epoch, "receipt_set_digest": receipt_set_digest, "state": state,
                          "threshold": threshold}
    evaluation_digest = hashlib.sha256(canonical_json(evaluation_payload)).hexdigest()
    fresh_until = current + timedelta(seconds=quorum_freshness) if state in {QUORUM_MATCH, QUORUM_MATCH_DEGRADED} else None
    return QuorumResult(state, threshold, member_count, len(matching), unavailable, len(conflicts), invalid, valid,
                        tuple(sorted(matching)), tuple(sorted(conflicts)), receipt_set_digest, evaluation_digest,
                        current, fresh_until, reason)


def _registry(settings: Settings) -> list[dict[str, Any]]:
    raw = getattr(settings, "quorum_witness_registry", None)
    if not raw:
        return []
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, json.JSONDecodeError) as exc:
        raise InvalidWitnessConfiguration("witness registry is invalid") from exc
    if not isinstance(value, list) or not value or len(value) > 32:
        raise InvalidWitnessConfiguration("witness registry is invalid")
    return value


def create_witness(db: Session, *, witness_id: str, display_name: str, verification_key_id: str,
                   verification_public_key: str, endpoint_config_ref: str, now: datetime | None = None) -> Witness:
    wid = canonical_witness_id(witness_id)
    if not _KEY_ID.fullmatch(verification_key_id):
        raise InvalidWitnessConfiguration("verification key id is invalid")
    _decode_key(verification_public_key)
    current = utc(now or database_now(db))
    row = Witness(witness_id=wid, display_name=display_name[:255], verification_key_id=verification_key_id,
                  verification_public_key=verification_public_key, endpoint_config_ref=endpoint_config_ref[:255],
                  enabled=True, created_at=current, updated_at=current)
    db.add(row)
    db.add(WitnessVerificationKey(witness_id=wid, verification_key_id=verification_key_id,
                                 verification_public_key=verification_public_key, key_epoch=1,
                                 created_at=current))
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise InvalidWitnessConfiguration("duplicate witness_id") from exc
    return row


def register_witness_verification_key(db: Session, *, witness_id: str, verification_key_id: str,
                                     verification_public_key: str, key_epoch: int,
                                     now: datetime | None = None) -> WitnessVerificationKey:
    """Register historical verification material before activating a new policy epoch."""
    wid = canonical_witness_id(witness_id)
    if not _KEY_ID.fullmatch(verification_key_id) or key_epoch < 1:
        raise InvalidWitnessConfiguration("witness key binding is invalid")
    _decode_key(verification_public_key)
    if db.scalar(select(Witness).where(Witness.witness_id == wid)) is None:
        raise InvalidWitnessConfiguration("witness is not configured")
    row = WitnessVerificationKey(witness_id=wid, verification_key_id=verification_key_id,
                                 verification_public_key=verification_public_key, key_epoch=key_epoch,
                                 created_at=utc(now or database_now(db)))
    db.add(row); db.flush(); return row


def create_policy(db: Session, *, policy_epoch: int, threshold: int, witness_ids: Sequence[str],
                  members: Mapping[str, str], policy_version: str = POLICY_VERSION,
                  strict_conflict_blocking: bool = True, allow_degraded_match: bool = True,
                  receipt_freshness_seconds: int = 900, quorum_freshness_seconds: int = 300,
                  conflict_behavior: str = "BLOCK_ANY_VALID_CONTRADICTION", now: datetime | None = None) -> WitnessQuorumPolicy:
    ids = [canonical_witness_id(item) for item in witness_ids]
    if len(ids) != len(set(ids)):
        raise PolicyValidationError("duplicate witness_id in policy")
    if threshold < 1 or threshold > len(ids):
        raise PolicyValidationError("threshold must be between 1 and member count")
    normalized_members = {canonical_witness_id(key): value for key, value in members.items()}
    if set(ids) != set(normalized_members):
        raise PolicyValidationError("policy members do not match witness set")
    if policy_epoch < 1:
        raise PolicyValidationError("policy epoch must be positive")
    digest = policy_digest(policy_version=policy_version, policy_epoch=policy_epoch, threshold=threshold,
                           witness_ids=ids, strict_conflict_blocking=strict_conflict_blocking,
                           allow_degraded_match=allow_degraded_match, receipt_freshness_seconds=receipt_freshness_seconds,
                           quorum_freshness_seconds=quorum_freshness_seconds, conflict_behavior=conflict_behavior)
    current = utc(now or database_now(db))
    row = WitnessQuorumPolicy(policy_version=policy_version, policy_epoch=policy_epoch, threshold=threshold,
        member_count=len(ids), strict_conflict_blocking=strict_conflict_blocking, allow_degraded_match=allow_degraded_match,
        receipt_freshness_seconds=receipt_freshness_seconds, quorum_freshness_seconds=quorum_freshness_seconds,
        conflict_behavior=conflict_behavior, policy_digest=digest, created_at=current)
    db.add(row)
    for position, wid in enumerate(ids):
        db.add(WitnessQuorumPolicyMember(policy_epoch=policy_epoch, witness_id=wid,
                                         verification_key_id=normalized_members[wid], position=position, enabled=True))
    db.flush()
    return row


def activate_policy(db: Session, policy_epoch: int, *, now: datetime | None = None,
                    allow_downgrade: bool = False) -> WitnessQuorumPolicy:
    row = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == policy_epoch))
    if row is None:
        raise PolicyValidationError("policy epoch not found")
    current = utc(now or database_now(db))
    active = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.activated_at.is_not(None), WitnessQuorumPolicy.retired_at.is_(None)).order_by(WitnessQuorumPolicy.policy_epoch.desc()).limit(1))
    if active and row.policy_epoch < active.policy_epoch and not allow_downgrade:
        raise PolicyDowngradeError("policy epoch cannot move backwards")
    if active and not allow_downgrade and row.threshold < active.threshold:
        raise PolicyDowngradeError("threshold reduction requires trusted explicit action")
    if active and active.policy_epoch != row.policy_epoch:
        active.retired_at = current
    row.activated_at = row.activated_at or current
    db.flush()
    return row


def ensure_configured_policy(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> WitnessQuorumPolicy | None:
    settings = settings or get_settings()
    if not getattr(settings, "quorum_enabled", False):
        return None
    epoch = settings.quorum_policy_epoch
    existing = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == epoch))
    if existing:
        return existing
    definitions = _registry(settings)
    if not definitions:
        raise InvalidWitnessConfiguration("quorum is enabled without witnesses")
    members: dict[str, str] = {}
    for item in definitions:
        if not isinstance(item, dict):
            raise InvalidWitnessConfiguration("witness registry entry is invalid")
        wid = canonical_witness_id(item.get("witness_id", ""))
        key_id = item.get("verification_key_id")
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise InvalidWitnessConfiguration("witness registry key id is invalid")
        existing_w = db.scalar(select(Witness).where(Witness.witness_id == wid))
        if existing_w is None:
            create_witness(db, witness_id=wid, display_name=str(item.get("display_name", wid)),
                           verification_key_id=key_id, verification_public_key=str(item["verification_public_key"]),
                           endpoint_config_ref=str(item["endpoint_config_ref"]), now=now)
        members[wid] = key_id
    policy = create_policy(db, policy_epoch=epoch, threshold=settings.quorum_threshold, witness_ids=list(members),
                           members=members, policy_version=settings.quorum_policy_version,
                           strict_conflict_blocking=settings.quorum_strict_conflict_blocking,
                           receipt_freshness_seconds=settings.quorum_receipt_freshness_seconds,
                           quorum_freshness_seconds=settings.quorum_freshness_seconds, now=now)
    activate_policy(db, epoch, now=now)
    return policy


def record_receipt(db: Session, *, checkpoint: IntegrityCheckpoint, policy: WitnessQuorumPolicy,
                   receipt: Mapping[str, Any] | bytes | str, now: datetime | None = None) -> CheckpointWitnessReceipt:
    parsed = validate_receipt(receipt)
    if parsed["checkpoint_sequence"] != checkpoint.checkpoint_sequence or parsed["checkpoint_digest"] != checkpoint.checkpoint_digest:
        raise ReceiptValidationError("receipt checkpoint binding mismatch")
    if parsed["policy_epoch"] != policy.policy_epoch:
        raise ReceiptValidationError("receipt policy epoch mismatch")
    member = db.scalar(select(WitnessQuorumPolicyMember).where(WitnessQuorumPolicyMember.policy_epoch == policy.policy_epoch,
                                                                WitnessQuorumPolicyMember.witness_id == parsed["witness_id"],
                                                                WitnessQuorumPolicyMember.enabled.is_(True)))
    if member is None or member.verification_key_id != parsed["verification_key_id"]:
        raise ReceiptValidationError("receipt witness or key is not trusted")
    witness = db.scalar(select(Witness).where(Witness.witness_id == parsed["witness_id"], Witness.enabled.is_(True)))
    key_row = db.scalar(select(WitnessVerificationKey).where(WitnessVerificationKey.witness_id == parsed["witness_id"],
                                                               WitnessVerificationKey.verification_key_id == parsed["verification_key_id"]))
    if witness is None or key_row is None:
        raise ReceiptValidationError("witness is not configured")
    if not verify_ed25519(receipt_signing_bytes(parsed), parsed["signature"], key_row.verification_public_key):
        raise ReceiptValidationError("receipt signature is invalid")
    current = utc(now or database_now(db))
    existing = db.scalar(select(CheckpointWitnessReceipt).where(CheckpointWitnessReceipt.checkpoint_id == checkpoint.id,
                                                                 CheckpointWitnessReceipt.policy_epoch == policy.policy_epoch,
                                                                 CheckpointWitnessReceipt.witness_id == parsed["witness_id"]))
    values = dict(checkpoint_id=checkpoint.id, checkpoint_digest=checkpoint.checkpoint_digest,
                  checkpoint_sequence=checkpoint.checkpoint_sequence, policy_epoch=policy.policy_epoch,
                  witness_id=parsed["witness_id"], verification_key_id=parsed["verification_key_id"],
                  receipt_version=parsed["receipt_version"], receipt_payload_hash=receipt_payload_hash(parsed),
                  signature=parsed["signature"], witness_head_sequence=parsed["witness_head_sequence"],
                  witness_head_digest=parsed["witness_head_digest"], continuity_state=parsed["continuity_state"],
                  observed_at=parsed["observed_at"], verified_at=current, created_at=current)
    if existing:
        for key, value in values.items():
            if key != "checkpoint_id":
                setattr(existing, key, value)
        return existing
    row = CheckpointWitnessReceipt(**values)
    db.add(row)
    db.flush()
    return row


def enqueue_publish_jobs(db: Session, *, checkpoint: IntegrityCheckpoint, policy: WitnessQuorumPolicy,
                         now: datetime | None = None) -> list[WitnessPublishJob]:
    current = utc(now or database_now(db))
    members = list(db.scalars(select(WitnessQuorumPolicyMember).where(WitnessQuorumPolicyMember.policy_epoch == policy.policy_epoch,
                                                                        WitnessQuorumPolicyMember.enabled.is_(True)).order_by(WitnessQuorumPolicyMember.position, WitnessQuorumPolicyMember.witness_id)))
    jobs: list[WitnessPublishJob] = []
    for member in members:
        job = db.scalar(select(WitnessPublishJob).where(WitnessPublishJob.checkpoint_id == checkpoint.id,
                                                        WitnessPublishJob.policy_epoch == policy.policy_epoch,
                                                        WitnessPublishJob.witness_id == member.witness_id))
        if job is None:
            job = WitnessPublishJob(checkpoint_id=checkpoint.id, witness_id=member.witness_id,
                                    policy_epoch=policy.policy_epoch, status="PENDING", created_at=current, updated_at=current)
            db.add(job)
            jobs.append(job)
    db.flush()
    return jobs


def evaluate_checkpoint_quorum(db: Session, checkpoint_id: UUID, *, policy_epoch: int | None = None,
                               now: datetime | None = None, persist: bool = True) -> QuorumResult:
    checkpoint = db.get(IntegrityCheckpoint, checkpoint_id)
    if checkpoint is None:
        raise LookupError("checkpoint not found")
    epoch = policy_epoch or checkpoint.policy_epoch
    if epoch is None:
        return QuorumResult(QUORUM_POLICY_INVALID, 0, 0, blocking_reason="CHECKPOINT_HAS_NO_POLICY_EPOCH")
    policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == epoch))
    if policy is None:
        return QuorumResult(QUORUM_POLICY_INVALID, 0, 0, blocking_reason="POLICY_NOT_FOUND")
    member_rows = list(db.scalars(select(WitnessQuorumPolicyMember).where(WitnessQuorumPolicyMember.policy_epoch == epoch,
                                                                           WitnessQuorumPolicyMember.enabled.is_(True))))
    receipts = list(db.scalars(select(CheckpointWitnessReceipt).where(CheckpointWitnessReceipt.checkpoint_id == checkpoint.id,
                                                                        CheckpointWitnessReceipt.policy_epoch == epoch)))
    public_keys = {w.witness_id: w.verification_public_key for w in db.scalars(select(Witness).where(Witness.enabled.is_(True)))}
    # evaluate_quorum indexes keys by key id, as receipts bind key IDs.
    keys_by_id = {w.verification_key_id: w.verification_public_key for w in db.scalars(select(Witness).where(Witness.enabled.is_(True)))}
    result = evaluate_quorum(policy=policy, members=member_rows, checkpoint_sequence=checkpoint.checkpoint_sequence,
                             checkpoint_digest=checkpoint.checkpoint_digest,
                             receipts=[{ "receipt_version": r.receipt_version, "witness_id": r.witness_id,
                                         "verification_key_id": r.verification_key_id, "policy_epoch": r.policy_epoch,
                                         "checkpoint_sequence": r.checkpoint_sequence, "checkpoint_digest": r.checkpoint_digest,
                                         "witness_head_sequence": r.witness_head_sequence, "witness_head_digest": r.witness_head_digest,
                                         "continuity_state": r.continuity_state, "observed_at": r.observed_at.isoformat(),
                                         "signature": r.signature } for r in receipts], now=now, public_keys=keys_by_id)
    if persist:
        current = utc(now or database_now(db))
        row = db.scalar(select(CheckpointQuorumEvaluation).where(CheckpointQuorumEvaluation.checkpoint_id == checkpoint.id,
                                                                  CheckpointQuorumEvaluation.policy_epoch == epoch))
        values = dict(checkpoint_id=checkpoint.id, policy_epoch=epoch, evaluation_state=result.state,
                      threshold=result.threshold, member_count=result.member_count, match_count=result.match_count,
                      unavailable_count=result.unavailable_count, conflict_count=result.conflict_count,
                      invalid_signature_count=result.invalid_signature_count, valid_receipt_count=result.valid_receipt_count,
                      receipt_set_digest=result.receipt_set_digest, evaluation_digest=result.evaluation_digest,
                      evaluated_at=result.evaluated_at or current, fresh_until=result.fresh_until,
                      blocking_reason=result.blocking_reason, created_at=current)
        if row:
            for key, value in values.items():
                if key not in {"checkpoint_id", "policy_epoch", "created_at"}:
                    setattr(row, key, value)
        else:
            # Two coordinator workers may evaluate the same checkpoint at the
            # same time. Keep the unique constraint as the authority and use
            # a savepoint so the loser can reload the winner without losing
            # its surrounding transaction.
            try:
                with db.begin_nested():
                    db.add(CheckpointQuorumEvaluation(**values))
                    db.flush()
            except IntegrityError:
                row = db.scalar(select(CheckpointQuorumEvaluation).where(
                    CheckpointQuorumEvaluation.checkpoint_id == checkpoint.id,
                    CheckpointQuorumEvaluation.policy_epoch == epoch,
                ))
                if row is None:
                    raise
                for key, value in values.items():
                    if key not in {"checkpoint_id", "policy_epoch", "created_at"}:
                        setattr(row, key, value)
        db.flush()
    return result


def require_fresh_quorum(db: Session, checkpoint_id: UUID, *, now: datetime | None = None) -> QuorumResult:
    result = evaluate_checkpoint_quorum(db, checkpoint_id, now=now, persist=True)
    current = utc(now or database_now(db))
    if not result.destructive_allowed or result.fresh_until is None or result.fresh_until <= current:
        raise QuorumError(f"destructive operation blocked by {result.state}")
    return result


def destructive_operation_allowed(result: QuorumResult, *, now: datetime | None = None) -> bool:
    """Small policy gate suitable for every V16/V17/V19 destructive caller."""
    if not result.destructive_allowed or result.fresh_until is None:
        return False
    return result.fresh_until > utc(now or datetime.now(timezone.utc))


def worker_backoff(attempt_count: int, *, base_seconds: int = 1, max_seconds: int = 60) -> int:
    return min(max_seconds, base_seconds * (2 ** max(0, min(attempt_count - 1, 20))))


def claim_publish_job(db: Session, *, now: datetime | None = None, worker_id: str | None = None,
                     lease_seconds: int = 30) -> WitnessPublishJob | None:
    current = utc(now or database_now(db)); worker = worker_id or secrets.token_hex(8)
    job = db.scalar(select(WitnessPublishJob).where(
        or_(and_(WitnessPublishJob.status.in_(["PENDING", "RETRY_WAIT"]),
                 or_(WitnessPublishJob.next_attempt_at.is_(None), WitnessPublishJob.next_attempt_at <= current)),
            and_(WitnessPublishJob.status == "IN_FLIGHT", WitnessPublishJob.lease_expires_at < current))
    ).order_by(case((WitnessPublishJob.status == "IN_FLIGHT", 0), else_=1), WitnessPublishJob.created_at).limit(1).with_for_update(skip_locked=True))
    if job is None:
        return None
    job.status, job.claimed_by, job.claim_token = "IN_FLIGHT", worker, secrets.token_hex(16)
    job.claimed_at, job.lease_expires_at = current, current + timedelta(seconds=lease_seconds)
    job.attempt_count += 1; job.updated_at = current
    db.flush()
    return job


class WitnessClient(Protocol):
    def publish(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


def process_publish_job(db: Session, job: WitnessPublishJob, *, client: WitnessClient,
                       checkpoint: IntegrityCheckpoint, policy: WitnessQuorumPolicy,
                       now: datetime | None = None, max_attempts: int = 5,
                       base_seconds: int = 1, max_backoff_seconds: int = 60) -> CheckpointWitnessReceipt | None:
    current = utc(now or database_now(db))
    request = {"receipt_version": RECEIPT_VERSION, "witness_id": job.witness_id,
               "policy_epoch": policy.policy_epoch, "checkpoint_sequence": checkpoint.checkpoint_sequence,
               "checkpoint_digest": checkpoint.checkpoint_digest}
    try:
        response = client.publish(request)
        receipt = record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=response, now=current)
        job.status, job.last_error_category, job.updated_at = "SUCCEEDED", None, current
        job.claim_token = job.claimed_by = None
        db.commit()
        return receipt
    except (WitnessUnavailable, ReceiptValidationError, QuorumError, TimeoutError, OSError) as exc:
        job.last_error_category = type(exc).__name__
        if isinstance(exc, ReceiptValidationError):
            job.status = "FAILED"
        elif job.attempt_count >= max_attempts:
            job.status = "FAILED"
        else:
            job.status = "RETRY_WAIT"
            job.next_attempt_at = current + timedelta(seconds=worker_backoff(job.attempt_count, base_seconds=base_seconds, max_seconds=max_backoff_seconds))
        job.claim_token = job.claimed_by = None; job.lease_expires_at = None; job.updated_at = current
        db.commit()
        if job.status == "FAILED" and isinstance(exc, ReceiptValidationError):
            raise
        return None


def health_snapshot(db: Session, *, witness_id: str, policy_epoch: int, state: str,
                    detail_code: str | None = None, now: datetime | None = None) -> WitnessHealthSnapshot:
    row = WitnessHealthSnapshot(witness_id=canonical_witness_id(witness_id), policy_epoch=policy_epoch,
                                health_state=state, observed_at=utc(now or database_now(db)), detail_code=detail_code)
    db.add(row); db.flush(); return row


def run_quorum_cycle(db: Session, *, now: datetime | None = None,
                     limit: int = 100) -> list[QuorumResult]:
    """Persist fresh evaluations for policy-bound checkpoints.

    Network publication is intentionally per-witness and is driven through
    ``process_publish_job``; this cycle never turns an unavailable witness
    into a successful vote.
    """
    checkpoints = list(db.scalars(select(IntegrityCheckpoint).where(
        IntegrityCheckpoint.policy_epoch.is_not(None)).order_by(IntegrityCheckpoint.checkpoint_sequence.desc()).limit(limit)))
    results = [evaluate_checkpoint_quorum(db, row.id, now=now, persist=True) for row in checkpoints]
    db.commit()
    return results
