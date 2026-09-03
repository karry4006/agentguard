"""V18 archive replica catalog.

The tables contain immutable identity and verification evidence only.  Store
credentials and endpoints remain trusted process configuration.
"""

from datetime import datetime
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, Uuid, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from agentguard_server.db.base import Base


class ArchiveStore(Base):
    __tablename__ = "archive_stores"
    __table_args__ = (Index("ix_archive_stores_enabled_priority", "enabled", "priority"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    store_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    provider_type: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    read_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    write_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    replication_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scrub_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ArchiveReplica(Base):
    __tablename__ = "archive_replicas"
    __table_args__ = (
        UniqueConstraint("logical_archive_type", "logical_archive_id", "store_id", name="uq_archive_replicas_logical_store"),
        Index("ix_archive_replicas_logical", "tenant_id", "logical_archive_type", "logical_archive_id"),
        Index("ix_archive_replicas_store_state", "store_id", "state"),
        Index("ix_archive_replicas_verification", "state", "verified_at"),
        CheckConstraint("state IN ('PENDING','REPLICATING','VERIFYING','VALID','MISSING','UNAVAILABLE','CORRUPT','CONFLICT','UNVERIFIABLE_KEY_MISSING','REPAIR_PENDING','REPAIRING','FAILED')", name="ck_archive_replica_state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    logical_archive_type: Mapped[str] = mapped_column(String(32), nullable=False)
    logical_archive_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    store_id: Mapped[str] = mapped_column(String(128), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    expected_ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_plaintext_sha256: Mapped[str | None] = mapped_column(String(64))
    expected_logical_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scrubbed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_category: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ArchiveReplicationJob(Base):
    __tablename__ = "archive_replication_jobs"
    __table_args__ = (Index("ix_archive_replication_jobs_claimable", "status", "next_attempt_at", "lease_expires_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    logical_archive_type: Mapped[str] = mapped_column(String(32), nullable=False)
    logical_archive_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    source_store_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_store_id: Mapped[str] = mapped_column(String(128), nullable=False)
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


class ArchiveScrubRun(Base):
    __tablename__ = "archive_scrub_runs"
    __table_args__ = (Index("ix_archive_scrub_runs_lookup", "store_id", "checked_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    store_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    logical_archive_type: Mapped[str] = mapped_column(String(32), nullable=False)
    logical_archive_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    result: Mapped[str] = mapped_column(String(48), nullable=False)
    verification_depth: Mapped[str] = mapped_column(String(8), nullable=False, default="FULL")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    error_category: Mapped[str | None] = mapped_column(String(64))
    worker_instance_id: Mapped[str] = mapped_column(String(128), nullable=False)


class ArchiveReplicaPolicy(Base):
    __tablename__ = "archive_replica_policy"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    minimum_verified_replicas: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    required_store_ids: Mapped[str | None] = mapped_column(Text)
    repair_missing_replicas: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scrub_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    max_replication_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    write_targets: Mapped[str | None] = mapped_column(Text)
    read_order: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
