"""V16 retention catalog and durable coordination state.

The catalog deliberately stores metadata and digests only. Archive encryption
keys and object-store credentials are never persisted here.
"""

from datetime import datetime
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentguard_server.db.base import Base


class ArchiveRecord(Base):
    __tablename__ = "archive_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", "archive_version", name="uq_archive_records_tenant_trace_version"),
        Index("ix_archive_records_tenant_trace", "tenant_id", "trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    archive_version: Mapped[str] = mapped_column(String(32), nullable=False)
    envelope_version: Mapped[str] = mapped_column(String(32), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    archive_encryption_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plaintext_sha256: Mapped[str | None] = mapped_column(String(64))
    compressed_sha256: Mapped[str | None] = mapped_column(String(64))
    ciphertext_sha256: Mapped[str | None] = mapped_column(String(64))
    source_projection_digest: Mapped[str | None] = mapped_column(String(64))
    source_v3_min_sequence: Mapped[int | None] = mapped_column(Integer)
    source_v3_max_sequence: Mapped[int | None] = mapped_column(Integer)
    covering_checkpoint_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("integrity_checkpoints.id"))
    covering_checkpoint_sequence: Mapped[int | None] = mapped_column(Integer)
    covering_checkpoint_digest: Mapped[str | None] = mapped_column(String(64))
    trace_span_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    plaintext_size: Mapped[int | None] = mapped_column(Integer)
    compressed_size: Mapped[int | None] = mapped_column(Integer)
    ciphertext_size: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lifecycle: Mapped["ArchiveLifecycle"] = relationship(back_populates="archive_record", cascade="all, delete-orphan", uselist=False)


class ArchiveLifecycle(Base):
    __tablename__ = "archive_lifecycle"
    __table_args__ = (Index("ix_archive_lifecycle_status", "status", "updated_at"),)

    archive_record_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("archive_records.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    last_error_category: Mapped[str | None] = mapped_column(String(64))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    archive_record: Mapped[ArchiveRecord] = relationship(back_populates="lifecycle")


class RetentionJob(Base):
    __tablename__ = "retention_jobs"
    __table_args__ = (
        Index("ix_retention_jobs_claimable", "job_type", "status", "next_attempt_at", "lease_expires_at"),
        Index("ix_retention_jobs_tenant_trace", "tenant_id", "trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    claim_token: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archive_record_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("archive_records.id", ondelete="SET NULL"))
    last_error_category: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RetentionHold(Base):
    __tablename__ = "retention_holds"
    __table_args__ = (
        Index("ix_retention_holds_tenant_trace_release", "tenant_id", "trace_id", "released_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False, default="TRACE")
    trace_id: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by_principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by_principal_type: Mapped[str | None] = mapped_column(String(32))
    released_by_principal_id: Mapped[str | None] = mapped_column(String(128))

