"""add evidence-grounded failure analysis artifacts"""
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0005_failure_analysis"
down_revision = "0004_safe_replay"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(255), nullable=False), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("taxonomy_version", sa.String(32), nullable=False), sa.Column("analysis_version", sa.String(32), nullable=False),
        sa.Column("provider", sa.String(64)), sa.Column("model", sa.String(128)), sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("deterministic_status", sa.String(32), nullable=False), sa.Column("ai_status", sa.String(32), nullable=False),
        sa.Column("failure_reason", sa.Text()), sa.Column("model_calls", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer()), sa.Column("output_tokens", sa.Integer()), sa.Column("latency_ms", sa.Float()),
        sa.Column("idempotency_key", sa.String(255)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_analysis_tenant_idempotency"),
    )
    op.create_index("ix_analysis_runs_tenant_trace", "analysis_runs", ["tenant_id", "trace_id"])
    op.create_table(
        "analysis_findings",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("detector_id", sa.String(64), nullable=False), sa.Column("category", sa.String(64), nullable=False),
        sa.Column("root_cause_span_id", sa.String(255)), sa.Column("symptom_span_id", sa.String(255)),
        sa.Column("severity", sa.String(16), nullable=False), sa.Column("model_confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False), sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("recommended_next_step", sa.String(255)), sa.Column("evidence_span_ids", json_type, nullable=False),
        sa.Column("evidence_event_ids", json_type, nullable=False), sa.Column("replay_ids", json_type, nullable=False),
        sa.Column("primary_hypothesis", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_runs.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analysis_findings_run", "analysis_findings", ["analysis_run_id"])
    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    bind.execute(sa.text(f"REVOKE DELETE ON analysis_runs, analysis_findings FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON analysis_runs, analysis_findings TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_analysis_findings_run", table_name="analysis_findings")
    op.drop_table("analysis_findings")
    op.drop_index("ix_analysis_runs_tenant_trace", table_name="analysis_runs")
    op.drop_table("analysis_runs")
