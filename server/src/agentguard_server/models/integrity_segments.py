"""V19 verifiable archive catalog for historical V3 integrity metadata."""

from datetime import datetime
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from agentguard_server.db.base import Base


INTEGRITY_SEGMENT_STATES = (
    "PLANNED", "BUILDING", "ARCHIVED", "VERIFYING", "ARCHIVED_VERIFIED",
    "REPLICA_POLICY_PENDING", "READY_TO_COMPACT", "COMPACTING", "COMPACTED",
    "BLOCKED", "FAILED",
)


class IntegrityArchiveSegment(Base):
    __tablename__ = "integrity_archive_segments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", "segment_sequence", name="uq_integrity_segments_trace_sequence"),
        UniqueConstraint("tenant_id", "trace_id", "source_start_sequence", name="uq_integrity_segments_trace_start"),
        UniqueConstraint("tenant_id", "trace_id", "source_end_sequence", name="uq_integrity_segments_trace_end"),
        Index("ix_integrity_segments_tenant_trace_state", "tenant_id", "trace_id", "state"),
        Index("ix_integrity_segments_candidate", "state", "created_at"),
        CheckConstraint("source_start_sequence <= source_end_sequence", name="ck_integrity_segments_range"),
        CheckConstraint("record_count > 0", name="ck_integrity_segments_record_count"),
        CheckConstraint(
            "state IN ('PLANNED','BUILDING','ARCHIVED','VERIFYING','ARCHIVED_VERIFIED','REPLICA_POLICY_PENDING','READY_TO_COMPACT','COMPACTING','COMPACTED','BLOCKED','FAILED')",
            name="ck_integrity_segments_state",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    segment_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    segment_version: Mapped[str] = mapped_column(String(32), nullable=False)
    envelope_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_start_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    source_end_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_record_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    last_record_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    first_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    last_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    predecessor_boundary_hash: Mapped[str | None] = mapped_column(String(64))
    successor_boundary_hash: Mapped[str | None] = mapped_column(String(64))
    records_manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    logical_segment_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    plaintext_sha256: Mapped[str | None] = mapped_column(String(64))
    ciphertext_sha256: Mapped[str | None] = mapped_column(String(64))
    archive_key_id: Mapped[str | None] = mapped_column(String(128))
    archive_object_key: Mapped[str | None] = mapped_column(String(512), unique=True)
    archive_logical_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), unique=True)
    v17_ledger_segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ledger_segments.id"), nullable=False)
    v17_ledger_segment_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    v15_checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id"), nullable=False)
    v15_checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    v15_continuity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    v20_policy_epoch: Mapped[int | None] = mapped_column(Integer)
    v20_quorum_evaluation_digest: Mapped[str | None] = mapped_column(String(64))
    v20_quorum_state: Mapped[str | None] = mapped_column(String(64))
    v20_receipt_set_digest: Mapped[str | None] = mapped_column(String(64))
    v20_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    v20_fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="PLANNED")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    compacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IntegrityCompactionJob(Base):
    __tablename__ = "integrity_compaction_jobs"
    __table_args__ = (Index("ix_integrity_compaction_jobs_claimable", "status", "next_attempt_at", "lease_expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_archive_segments.id", ondelete="CASCADE"), nullable=False)
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


class IntegrityCompactionAuthorization(Base):
    __tablename__ = "integrity_compaction_authorizations"
    __table_args__ = (Index("ix_integrity_compaction_auth_expiry", "segment_id", "expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_archive_segments.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_start_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    source_end_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    logical_segment_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    predecessor_boundary_hash: Mapped[str | None] = mapped_column(String(64))
    successor_boundary_hash: Mapped[str | None] = mapped_column(String(64))
    replica_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_replica_count: Mapped[int] = mapped_column(Integer, nullable=False)
    v17_ledger_segment_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    v15_checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    v15_continuity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    # V20 binds destructive V19 authorization to the exact policy evaluation
    # and receipt set that was checked immediately before authorization.
    # These columns are nullable so pre-V20 authorization rows remain
    # readable, matching migration 0017's compatibility contract.
    v20_policy_epoch: Mapped[int | None] = mapped_column(Integer)
    v20_quorum_evaluation_digest: Mapped[str | None] = mapped_column(String(64))
    v20_quorum_state: Mapped[str | None] = mapped_column(String(64))
    v20_receipt_set_digest: Mapped[str | None] = mapped_column(String(64))
    v20_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    v20_fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authorized_by_instance: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
