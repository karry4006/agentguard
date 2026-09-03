"""add V16 evidence retention and cold archive catalog"""
from alembic import op
import os
import sqlalchemy as sa

revision = "0013_evidence_retention_archival"
down_revision = "0012_external_integrity_anchoring"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid retention role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table("archive_records",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False), sa.Column("archive_version", sa.String(length=32), nullable=False),
        sa.Column("envelope_version", sa.String(length=32), nullable=False), sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("archive_encryption_key_id", sa.String(length=128), nullable=False), sa.Column("plaintext_sha256", sa.String(length=64)),
        sa.Column("compressed_sha256", sa.String(length=64)), sa.Column("ciphertext_sha256", sa.String(length=64)),
        sa.Column("source_projection_digest", sa.String(length=64)), sa.Column("source_v3_min_sequence", sa.Integer()),
        sa.Column("source_v3_max_sequence", sa.Integer()), sa.Column("covering_checkpoint_id", sa.Uuid()),
        sa.Column("covering_checkpoint_sequence", sa.Integer()), sa.Column("covering_checkpoint_digest", sa.String(length=64)),
        sa.Column("trace_span_count", sa.Integer(), nullable=False), sa.Column("plaintext_size", sa.Integer()),
        sa.Column("compressed_size", sa.Integer()), sa.Column("ciphertext_size", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["covering_checkpoint_id"], ["integrity_checkpoints.id"]),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("object_key"),
        sa.UniqueConstraint("tenant_id", "trace_id", "archive_version", name="uq_archive_records_tenant_trace_version"))
    op.create_index("ix_archive_records_tenant_trace", "archive_records", ["tenant_id", "trace_id"])
    op.create_table("archive_lifecycle", sa.Column("archive_record_id", sa.Uuid(), nullable=False), sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("last_error_category", sa.String(length=64)), sa.Column("last_verified_at", sa.DateTime(timezone=True)), sa.Column("purged_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.ForeignKeyConstraint(["archive_record_id"], ["archive_records.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("archive_record_id"))
    op.create_index("ix_archive_lifecycle_status", "archive_lifecycle", ["status", "updated_at"])
    op.create_table("retention_jobs", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False), sa.Column("job_type", sa.String(length=32), nullable=False), sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False), sa.Column("next_attempt_at", sa.DateTime(timezone=True)), sa.Column("claimed_by", sa.String(length=128)),
        sa.Column("claim_token", sa.String(length=64)), sa.Column("claimed_at", sa.DateTime(timezone=True)), sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("archive_record_id", sa.Uuid()), sa.Column("last_error_category", sa.String(length=64)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["archive_record_id"], ["archive_records.id"], ondelete="SET NULL"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_retention_jobs_claimable", "retention_jobs", ["job_type", "status", "next_attempt_at", "lease_expires_at"])
    op.create_index("ix_retention_jobs_tenant_trace", "retention_jobs", ["tenant_id", "trace_id"])
    op.create_table("retention_holds", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False), sa.Column("subject_type", sa.String(length=16), nullable=False),
        sa.Column("trace_id", sa.String(length=255)), sa.Column("reason", sa.Text(), nullable=False), sa.Column("created_by_principal_type", sa.String(length=32), nullable=False), sa.Column("created_by_principal_id", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("released_at", sa.DateTime(timezone=True)), sa.Column("released_by_principal_type", sa.String(length=32)), sa.Column("released_by_principal_id", sa.String(length=128)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_retention_holds_tenant_trace_release", "retention_holds", ["tenant_id", "trace_id", "released_at"])

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
        retention = _identifier(os.getenv("AGENTGUARD_RETENTION_USER", "agentguard_retention"))
        for table in ("archive_records", "archive_lifecycle", "retention_jobs", "retention_holds"):
            # API operations use the catalog, but the runtime identity never
            # needs to delete catalog rows or change the immutable source.
            bind.execute(sa.text(f"REVOKE DELETE, TRUNCATE ON {table} FROM {runtime}"))
            bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {runtime}"))
        for table in ("traces", "spans", "event_log", "integrity_records", "integrity_chain_heads", "integrity_checkpoints", "integrity_checkpoint_entries", "external_anchor_receipts"):
            bind.execute(sa.text(f"GRANT SELECT ON {table} TO {retention}"))
        for table in ("archive_records", "archive_lifecycle", "retention_jobs", "retention_holds"):
            bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {retention}"))
        bind.execute(sa.text(f"GRANT DELETE ON spans TO {retention}"))
        for table in ("event_log", "integrity_records", "integrity_chain_heads", "integrity_checkpoints", "integrity_checkpoint_entries", "external_anchor_receipts", "traces"):
            bind.execute(sa.text(f"REVOKE DELETE, TRUNCATE ON {table} FROM {retention}"))


def downgrade() -> None:
    op.drop_index("ix_retention_holds_tenant_trace_release", table_name="retention_holds")
    op.drop_table("retention_holds")
    op.drop_index("ix_retention_jobs_tenant_trace", table_name="retention_jobs")
    op.drop_index("ix_retention_jobs_claimable", table_name="retention_jobs")
    op.drop_table("retention_jobs")
    op.drop_index("ix_archive_lifecycle_status", table_name="archive_lifecycle")
    op.drop_table("archive_lifecycle")
    op.drop_index("ix_archive_records_tenant_trace", table_name="archive_records")
    op.drop_table("archive_records")
