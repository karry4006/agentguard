"""SQLAlchemy models for externally anchored V3 checkpoints."""

from datetime import datetime
import uuid

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentguard_server.db.base import Base


class IntegrityCheckpoint(Base):
    __tablename__ = "integrity_checkpoints"
    __table_args__ = (
        UniqueConstraint("namespace", "checkpoint_sequence", name="uq_integrity_checkpoints_namespace_sequence"),
        Index("ix_integrity_checkpoints_digest", "checkpoint_digest"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    namespace: Mapped[str] = mapped_column(String(128), nullable=False)
    checkpoint_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    checkpoint_version: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_checkpoint_digest: Mapped[str | None] = mapped_column(String(64))
    checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # V15 checkpoints remain valid when this is NULL; V20 checkpoints bind to
    # an immutable policy epoch and digest.
    policy_epoch: Mapped[int | None] = mapped_column(Integer)
    policy_digest: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    entries: Mapped[list["IntegrityCheckpointEntry"]] = relationship(
        back_populates="checkpoint", cascade="all, delete-orphan"
    )
    receipts: Mapped[list["ExternalAnchorReceipt"]] = relationship(back_populates="checkpoint")
    jobs: Mapped[list["IntegrityAnchorJob"]] = relationship(back_populates="checkpoint")


class IntegrityCheckpointEntry(Base):
    __tablename__ = "integrity_checkpoint_entries"
    __table_args__ = (
        UniqueConstraint("checkpoint_id", "tenant_id", "trace_id", name="uq_integrity_checkpoint_entries_chain"),
        Index("ix_integrity_checkpoint_entries_checkpoint", "checkpoint_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_chain_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    tenant_chain_head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    checkpoint: Mapped[IntegrityCheckpoint] = relationship(back_populates="entries")


class ExternalAnchorReceipt(Base):
    __tablename__ = "external_anchor_receipts"
    __table_args__ = (
        UniqueConstraint("namespace", "checkpoint_sequence", name="uq_external_anchor_receipts_namespace_sequence"),
        UniqueConstraint("external_anchor_id", name="uq_external_anchor_receipts_external_id"),
        Index("ix_external_anchor_receipts_checkpoint", "checkpoint_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id"), nullable=False)
    anchor_protocol_version: Mapped[str] = mapped_column(String(64), nullable=False)
    external_anchor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    namespace: Mapped[str] = mapped_column(String(128), nullable=False)
    checkpoint_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    witness_received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signer_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    checkpoint: Mapped[IntegrityCheckpoint] = relationship(back_populates="receipts")


class IntegrityAnchorState(Base):
    __tablename__ = "integrity_anchor_state"

    namespace: Mapped[str] = mapped_column(String(128), primary_key=True)
    latest_checkpoint_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latest_checkpoint_digest: Mapped[str | None] = mapped_column(String(64))
    last_checkpoint_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_checkpoint_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IntegrityAnchorJob(Base):
    __tablename__ = "integrity_anchor_jobs"
    __table_args__ = (
        UniqueConstraint("checkpoint_id", name="uq_integrity_anchor_jobs_checkpoint"),
        Index("ix_integrity_anchor_jobs_claimable", "status", "next_attempt_at", "lease_expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("integrity_checkpoints.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    claim_token: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_category: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    checkpoint: Mapped[IntegrityCheckpoint] = relationship(back_populates="jobs")


