"""add append-only evidence integrity ledger"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import os

revision = "0003_evidence_integrity"
down_revision = "0002_trust_boundary"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.add_column("event_log", sa.Column("trace_id", sa.String(length=255), nullable=True))
    op.add_column("event_log", sa.Column("payload_json", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True))
    op.add_column("event_log", sa.Column("event_digest", sa.String(length=64), nullable=True))
    op.create_table(
        "integrity_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("event_digest", sa.String(length=64), nullable=False),
        sa.Column("previous_chain_mac", sa.String(length=64)),
        sa.Column("chain_mac", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("canonicalization_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "trace_id", "sequence", name="uq_integrity_trace_sequence"),
    )
    op.create_index("ix_integrity_tenant_trace", "integrity_records", ["tenant_id", "trace_id"])
    op.create_index("ix_integrity_event", "integrity_records", ["tenant_id", "event_type", "event_id"])
    op.create_index("ix_event_log_tenant_trace", "event_log", ["tenant_id", "trace_id"])
    op.create_table(
        "integrity_chain_heads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("next_sequence", sa.Integer(), nullable=False),
        sa.Column("head_mac", sa.String(length=64)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "trace_id", name="uq_integrity_chain_head"),
    )

    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    bind.execute(sa.text(f"REVOKE UPDATE, DELETE ON event_log FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT ON event_log TO {runtime}"))
    bind.execute(sa.text(f"GRANT USAGE, SELECT ON SEQUENCE event_log_id_seq TO {runtime}"))
    bind.execute(sa.text(f"REVOKE UPDATE, DELETE ON integrity_records FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT ON integrity_records TO {runtime}"))
    bind.execute(sa.text(f"REVOKE DELETE ON integrity_chain_heads FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON integrity_chain_heads TO {runtime}"))


def downgrade() -> None:
    op.drop_table("integrity_chain_heads")
    op.drop_index("ix_integrity_event", table_name="integrity_records")
    op.drop_index("ix_integrity_tenant_trace", table_name="integrity_records")
    op.drop_table("integrity_records")
    op.drop_index("ix_event_log_tenant_trace", table_name="event_log")
    op.drop_column("event_log", "event_digest")
    op.drop_column("event_log", "payload_json")
    op.drop_column("event_log", "trace_id")
