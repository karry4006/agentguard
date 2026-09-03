"""add externally witnessed V3 checkpoints and durable anchor work"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012_external_integrity_anchoring"
down_revision = "0011_distributed_coordination"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "integrity_checkpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("namespace", sa.String(length=128), nullable=False),
        sa.Column("checkpoint_sequence", sa.Integer(), nullable=False),
        sa.Column("checkpoint_version", sa.String(length=32), nullable=False),
        sa.Column("manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("previous_checkpoint_digest", sa.String(length=64)),
        sa.Column("checkpoint_digest", sa.String(length=64), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("namespace", "checkpoint_sequence", name="uq_integrity_checkpoints_namespace_sequence"),
    )
    op.create_index("ix_integrity_checkpoints_digest", "integrity_checkpoints", ["checkpoint_digest"])
    op.create_table(
        "integrity_checkpoint_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("tenant_chain_sequence", sa.Integer(), nullable=False),
        sa.Column("tenant_chain_head_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["checkpoint_id"], ["integrity_checkpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("checkpoint_id", "tenant_id", "trace_id", name="uq_integrity_checkpoint_entries_chain"),
    )
    op.create_index("ix_integrity_checkpoint_entries_checkpoint", "integrity_checkpoint_entries", ["checkpoint_id"])
    op.create_table(
        "external_anchor_receipts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("anchor_protocol_version", sa.String(length=64), nullable=False),
        sa.Column("external_anchor_id", sa.String(length=128), nullable=False),
        sa.Column("namespace", sa.String(length=128), nullable=False),
        sa.Column("checkpoint_sequence", sa.Integer(), nullable=False),
        sa.Column("checkpoint_digest", sa.String(length=64), nullable=False),
        sa.Column("witness_received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signer_key_id", sa.String(length=128), nullable=False),
        sa.Column("signature", sa.String(length=256), nullable=False),
        sa.Column("receipt_digest", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["checkpoint_id"], ["integrity_checkpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("namespace", "checkpoint_sequence", name="uq_external_anchor_receipts_namespace_sequence"),
        sa.UniqueConstraint("external_anchor_id", name="uq_external_anchor_receipts_external_id"),
    )
    op.create_index("ix_external_anchor_receipts_checkpoint", "external_anchor_receipts", ["checkpoint_id"])
    op.create_table(
        "integrity_anchor_state",
        sa.Column("namespace", sa.String(length=128), nullable=False),
        sa.Column("latest_checkpoint_sequence", sa.Integer(), nullable=False),
        sa.Column("latest_checkpoint_digest", sa.String(length=64)),
        sa.Column("last_checkpoint_at", sa.DateTime(timezone=True)),
        sa.Column("next_checkpoint_due_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("namespace"),
    )
    op.create_table(
        "integrity_anchor_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_by", sa.String(length=128)),
        sa.Column("claim_token", sa.String(length=64)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_failure_category", sa.String(length=64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["checkpoint_id"], ["integrity_checkpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("checkpoint_id", name="uq_integrity_anchor_jobs_checkpoint"),
    )
    op.create_index("ix_integrity_anchor_jobs_claimable", "integrity_anchor_jobs", ["status", "next_attempt_at", "lease_expires_at"])
    bind = op.get_bind()
    # The pre-V15 schema used VARCHAR(32); this revision id is longer.
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "alembic_version",
            "version_num",
            existing_type=sa.String(length=32),
            type_=sa.String(length=64),
            existing_nullable=False,
        )
    if bind.dialect.name == "postgresql":
        runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
        for table in ("integrity_checkpoints", "integrity_checkpoint_entries", "external_anchor_receipts"):
            bind.execute(sa.text(f"REVOKE UPDATE, DELETE ON {table} FROM {runtime}"))
            bind.execute(sa.text(f"GRANT SELECT, INSERT ON {table} TO {runtime}"))
        bind.execute(sa.text(f"REVOKE DELETE ON integrity_anchor_state FROM {runtime}"))
        bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON integrity_anchor_state TO {runtime}"))
        bind.execute(sa.text(f"REVOKE DELETE ON integrity_anchor_jobs FROM {runtime}"))
        bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON integrity_anchor_jobs TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_integrity_anchor_jobs_claimable", table_name="integrity_anchor_jobs")
    op.drop_table("integrity_anchor_jobs")
    op.drop_table("integrity_anchor_state")
    op.drop_index("ix_external_anchor_receipts_checkpoint", table_name="external_anchor_receipts")
    op.drop_table("external_anchor_receipts")
    op.drop_index("ix_integrity_checkpoint_entries_checkpoint", table_name="integrity_checkpoint_entries")
    op.drop_table("integrity_checkpoint_entries")
    op.drop_index("ix_integrity_checkpoints_digest", table_name="integrity_checkpoints")
    op.drop_table("integrity_checkpoints")



