"""add safe dry-run replay tables"""
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0004_safe_replay"
down_revision = "0003_evidence_integrity"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "replay_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("source_trace_id", sa.String(255), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("integrity_status", sa.String(32), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("failure_reason", sa.Text()),
        sa.Column("idempotency_key", sa.String(255)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_replay_tenant_idempotency"),
    )
    op.create_index("ix_replay_sessions_tenant_source", "replay_sessions", ["tenant_id", "source_trace_id"])
    op.create_table(
        "replay_steps",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("replay_session_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("source_event_id", sa.String(255), nullable=False),
        sa.Column("source_span_id", sa.String(255)),
        sa.Column("step_type", sa.String(64), nullable=False),
        sa.Column("tool_name", sa.String(255)),
        sa.Column("classification", sa.String(32), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("recorded_input_digest", sa.String(64)),
        sa.Column("simulated_input_digest", sa.String(64)),
        sa.Column("recorded_output_digest", sa.String(64)),
        sa.Column("simulated_output_digest", sa.String(64)),
        sa.Column("comparison_status", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["replay_session_id"], ["replay_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("replay_session_id", "sequence", name="uq_replay_step_sequence"),
    )
    op.create_index("ix_replay_steps_session", "replay_steps", ["replay_session_id"])

    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    bind.execute(sa.text(f"REVOKE DELETE ON replay_sessions, replay_steps FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON replay_sessions, replay_steps TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_replay_steps_session", table_name="replay_steps")
    op.drop_table("replay_steps")
    op.drop_index("ix_replay_sessions_tenant_source", table_name="replay_sessions")
    op.drop_table("replay_sessions")
