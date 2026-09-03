"""V20 multi-witness quorum catalog and evidence models.

Only trusted public verification material and bounded receipt fields are
stored. Witness signing private keys never belong in AgentGuard.
"""

from datetime import datetime
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid, event, inspect
from sqlalchemy.orm import Mapped, mapped_column

from agentguard_server.db.base import Base


class Witness(Base):
    __tablename__ = "witnesses"
    __table_args__ = (UniqueConstraint("witness_id", name="uq_witnesses_canonical_id"), Index("ix_witnesses_enabled", "enabled"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    witness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    verification_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint_config_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WitnessVerificationKey(Base):
    __tablename__ = "witness_verification_keys"
    __table_args__ = (UniqueConstraint("witness_id", "verification_key_id", name="uq_witness_verification_key"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    witness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    key_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WitnessQuorumPolicy(Base):
    __tablename__ = "witness_quorum_policies"
    __table_args__ = (UniqueConstraint("policy_epoch", name="uq_witness_quorum_policies_epoch"), CheckConstraint("threshold >= 1", name="ck_witness_quorum_threshold_positive"), CheckConstraint("member_count >= threshold", name="ck_witness_quorum_threshold_lte_members"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, nullable=False)
    strict_conflict_blocking: Mapped[bool] = mapped_column(nullable=False, default=True)
    allow_degraded_match: Mapped[bool] = mapped_column(nullable=False, default=True)
    receipt_freshness_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    quorum_freshness_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    conflict_behavior: Mapped[str] = mapped_column(String(64), nullable=False, default="BLOCK_ANY_VALID_CONTRADICTION")
    policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WitnessQuorumPolicyMember(Base):
    __tablename__ = "witness_quorum_policy_members"
    __table_args__ = (UniqueConstraint("policy_epoch", "witness_id", name="uq_witness_quorum_policy_member"), Index("ix_witness_quorum_policy_members_epoch", "policy_epoch", "enabled"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    witness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    position: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)


class CheckpointWitnessReceipt(Base):
    __tablename__ = "checkpoint_witness_receipts"
    __table_args__ = (UniqueConstraint("checkpoint_id", "policy_epoch", "witness_id", name="uq_checkpoint_witness_receipt"), Index("ix_checkpoint_witness_receipts_lookup", "checkpoint_id", "policy_epoch", "created_at"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id", ondelete="CASCADE"), nullable=False)
    checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    checkpoint_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    witness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
    witness_head_sequence: Mapped[int | None] = mapped_column(Integer)
    witness_head_digest: Mapped[str | None] = mapped_column(String(64))
    continuity_state: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WitnessPublishJob(Base):
    __tablename__ = "witness_publish_jobs"
    __table_args__ = (UniqueConstraint("checkpoint_id", "policy_epoch", "witness_id", name="uq_witness_publish_job"), Index("ix_witness_publish_jobs_claimable", "status", "next_attempt_at", "lease_expires_at"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id", ondelete="CASCADE"), nullable=False)
    witness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    claim_token: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_category: Mapped[str | None] = mapped_column(String(96))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CheckpointQuorumEvaluation(Base):
    __tablename__ = "checkpoint_quorum_evaluations"
    __table_args__ = (UniqueConstraint("checkpoint_id", "policy_epoch", name="uq_checkpoint_quorum_evaluation"), Index("ix_checkpoint_quorum_evaluations_fresh", "checkpoint_id", "fresh_until"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id", ondelete="CASCADE"), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    evaluation_state: Mapped[str] = mapped_column(String(64), nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, nullable=False)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unavailable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflict_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    invalid_signature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    valid_receipt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    receipt_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blocking_reason: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WitnessHealthSnapshot(Base):
    __tablename__ = "witness_health_snapshots"
    __table_args__ = (Index("ix_witness_health_snapshots_latest", "witness_id", "observed_at"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    witness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    health_state: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detail_code: Mapped[str | None] = mapped_column(String(96))


@event.listens_for(WitnessQuorumPolicy, "before_update")
def _policy_semantics_are_immutable(mapper, connection, target) -> None:
    immutable = ("policy_version", "policy_epoch", "threshold", "member_count",
                 "strict_conflict_blocking", "allow_degraded_match",
                 "receipt_freshness_seconds", "quorum_freshness_seconds",
                 "conflict_behavior", "policy_digest", "created_at")
    state = inspect(target)
    if any(state.attrs[name].history.has_changes() for name in immutable):
        raise ValueError("quorum policy semantics are immutable; create a new policy epoch")


@event.listens_for(Witness, "before_update")
def _witness_key_is_immutable(mapper, connection, target) -> None:
    state = inspect(target)
    for name in ("witness_id", "verification_key_id", "verification_public_key", "endpoint_config_ref"):
        if state.attrs[name].history.has_changes():
            raise ValueError("witness identity and key bindings are immutable; rotate in a new policy epoch")
