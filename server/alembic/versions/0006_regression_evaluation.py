"""add offline regression evaluation and advisory release gate tables"""

import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006_regression_evaluation"
down_revision = "0005_failure_analysis"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "evaluation_suites",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False), sa.Column("version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("configuration", json_type, nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", "version", name="uq_evaluation_suite_tenant_name_version"),
    )
    op.create_index("ix_evaluation_suites_tenant", "evaluation_suites", ["tenant_id"])
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("suite_id", sa.Uuid(), nullable=False), sa.Column("variant", sa.String(16), nullable=False),
        sa.Column("agent_version", sa.String(128), nullable=False), sa.Column("prompt_version", sa.String(128)),
        sa.Column("model", sa.String(128)), sa.Column("environment", json_type, nullable=False),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)), sa.Column("idempotency_key", sa.String(255)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["suite_id"], ["evaluation_suites.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_evaluation_run_tenant_idempotency"),
    )
    op.create_index("ix_evaluation_runs_tenant_suite", "evaluation_runs", ["tenant_id", "suite_id"])
    op.create_table(
        "evaluation_case_results",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False), sa.Column("case_id", sa.String(255), nullable=False),
        sa.Column("trace_id", sa.String(255), nullable=False), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("integrity_status", sa.String(32), nullable=False), sa.Column("metrics", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["evaluation_runs.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "run_id", "case_id", name="uq_evaluation_case_tenant_run_case"),
    )
    op.create_index("ix_evaluation_case_results_tenant_run", "evaluation_case_results", ["tenant_id", "run_id"])
    op.create_table(
        "evaluation_comparisons",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("suite_id", sa.Uuid(), nullable=False), sa.Column("baseline_run_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_run_id", sa.Uuid(), nullable=False), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("metrics", json_type, nullable=False), sa.Column("reasons", json_type, nullable=False),
        sa.Column("case_diffs", json_type, nullable=False), sa.Column("rule_results", json_type, nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=False), sa.Column("evaluator_version", sa.String(32), nullable=False),
        sa.Column("taxonomy_version", sa.String(32), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(255)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["suite_id"], ["evaluation_suites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["baseline_run_id"], ["evaluation_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["candidate_run_id"], ["evaluation_runs.id"], ondelete="RESTRICT"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "baseline_run_id", "candidate_run_id", name="uq_evaluation_comparison_pair"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_evaluation_comparison_tenant_idempotency"),
    )
    op.create_index("ix_evaluation_comparisons_tenant_suite", "evaluation_comparisons", ["tenant_id", "suite_id"])
    op.create_table(
        "release_gate_results",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("comparison_id", sa.Uuid(), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False), sa.Column("reasons", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["comparison_id"], ["evaluation_comparisons.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("comparison_id"),
    )
    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    tables = "evaluation_suites, evaluation_runs, evaluation_case_results, evaluation_comparisons, release_gate_results"
    bind.execute(sa.text(f"REVOKE DELETE ON {tables} FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {tables} TO {runtime}"))


def downgrade() -> None:
    op.drop_table("release_gate_results")
    op.drop_index("ix_evaluation_comparisons_tenant_suite", table_name="evaluation_comparisons")
    op.drop_table("evaluation_comparisons")
    op.drop_index("ix_evaluation_case_results_tenant_run", table_name="evaluation_case_results")
    op.drop_table("evaluation_case_results")
    op.drop_index("ix_evaluation_runs_tenant_suite", table_name="evaluation_runs")
    op.drop_table("evaluation_runs")
    op.drop_index("ix_evaluation_suites_tenant", table_name="evaluation_suites")
    op.drop_table("evaluation_suites")
