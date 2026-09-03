"""V17 verifiable ledger segment catalog and compaction state."""

from datetime import datetime
import uuid

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentguard_server.db.base import Base


class LedgerSegment(Base):
    __tablename__ = "ledger_segments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", "segment_sequence", name="uq_ledger_segments_trace_sequence"),
        UniqueConstraint("tenant_id", "trace_id", "start_event_sequence", name="uq_ledger_segments_trace_start"),
        UniqueConstraint("tenant_id", "trace_id", "end_event_sequence", name="uq_ledger_segments_trace_end"),
        Index("ix_ledger_segments_tenant_trace_status", "tenant_id", "trace_id", "segment_sequence"),
        CheckConstraint("start_event_sequence <= end_event_sequence", name="ck_ledger_segments_range"),
        CheckConstraint("event_count > 0", name="ck_ledger_segments_event_count"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    segment_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    segment_version: Mapped[str] = mapped_column(String(32), nullable=False)
    start_event_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    end_event_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    start_previous_hash: Mapped[str | None] = mapped_column(String(64))
    end_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    events_manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    segment_manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    archive_plaintext_sha256: Mapped[str | None] = mapped_column(String(64))
    archive_ciphertext_sha256: Mapped[str | None] = mapped_column(String(64))
    archive_object_key: Mapped[str | None] = mapped_column(String(512), unique=True)
    archive_encryption_key_id: Mapped[str | None] = mapped_column(String(128))
    covering_checkpoint_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("integrity_checkpoints.id"))
    covering_checkpoint_sequence: Mapped[int | None] = mapped_column(Integer)
    covering_checkpoint_digest: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    archived_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lifecycle: Mapped["LedgerSegmentLifecycle"] = relationship(back_populates="segment", cascade="all, delete-orphan", uselist=False)


class LedgerSegmentLifecycle(Base):
    __tablename__ = "ledger_segment_lifecycle"
    __table_args__ = (
        CheckConstraint(
            "status IN ('CANDIDATE','CLOSED','ARCHIVING','ARCHIVED_VERIFIED','COMPACTION_AUTHORIZED','COMPACTED','FAILED')",
            name="ck_ledger_segment_lifecycle_status",
        ),
    )

    segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ledger_segments.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="CANDIDATE")
    last_error_category: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    segment: Mapped[LedgerSegment] = relationship(back_populates="lifecycle")


class LedgerEventArchiveIndex(Base):
    __tablename__ = "ledger_event_archive_index"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", "event_sequence", name="uq_ledger_event_index_trace_sequence"),
        UniqueConstraint("tenant_id", "trace_id", "event_id", name="uq_ledger_event_index_trace_event"),
        Index("ix_ledger_event_index_segment", "segment_id", "event_sequence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ledger_segments.id", ondelete="CASCADE"), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    original_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LedgerCompactionJob(Base):
    __tablename__ = "ledger_compaction_jobs"
    __table_args__ = (Index("ix_ledger_compaction_jobs_claimable", "status", "next_attempt_at", "lease_expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ledger_segments.id", ondelete="CASCADE"), nullable=False)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPACT")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    claim_token: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_category: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LedgerCompactionAuthorization(Base):
    __tablename__ = "ledger_compaction_authorizations"
    __table_args__ = (Index("ix_ledger_compaction_auth_expiry", "segment_id", "expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    segment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ledger_segments.id", ondelete="CASCADE"), nullable=False)
    segment_manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    archive_ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    covering_checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    remote_continuity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    v20_policy_epoch: Mapped[int | None] = mapped_column(Integer)
    v20_quorum_evaluation_digest: Mapped[str | None] = mapped_column(String(64))
    v20_quorum_state: Mapped[str | None] = mapped_column(String(64))
    v20_receipt_set_digest: Mapped[str | None] = mapped_column(String(64))
    v20_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    v20_fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Nullable keeps rows created by the sealed V17 schema readable.  V18
    # strict authorization always writes and checks these bindings.
    replica_policy_version: Mapped[str | None] = mapped_column(String(64))
    verified_replica_count: Mapped[int | None] = mapped_column(Integer)
    required_store_ids: Mapped[str | None] = mapped_column(Text)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authorized_by_instance: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
