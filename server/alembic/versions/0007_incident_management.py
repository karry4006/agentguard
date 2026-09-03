"""add derived incident detection and management projections"""

import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007_incident_management"
down_revision = "0006_regression_evaluation"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("fingerprint_version", sa.String(64), nullable=False), sa.Column("title", sa.String(255), nullable=False),
        sa.Column("status", sa.String(24), nullable=False), sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("severity_policy_version", sa.String(32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False), sa.Column("affected_trace_count", sa.Integer(), nullable=False),
        sa.Column("primary_category", sa.String(64), nullable=False), sa.Column("dimensions", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "fingerprint", "fingerprint_version", name="uq_incident_tenant_fingerprint_version"),
    )
    op.create_index("ix_incidents_tenant_status", "incidents", ["tenant_id", "status"])
    op.create_index("ix_incidents_tenant_last_seen", "incidents", ["tenant_id", "last_seen_at"])
    op.create_index("ix_incidents_tenant_severity", "incidents", ["tenant_id", "severity"])
    op.create_table(
        "incident_occurrences",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False), sa.Column("trace_id", sa.String(255), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False), sa.Column("finding_key", sa.String(128), nullable=False),
        sa.Column("failure_category", sa.String(64), nullable=False), sa.Column("root_cause_span_id", sa.String(255)),
        sa.Column("symptom_span_id", sa.String(255)), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_name", sa.String(128)), sa.Column("workflow_name", sa.String(128)),
        sa.Column("agent_version", sa.String(128)), sa.Column("provider", sa.String(128)), sa.Column("model", sa.String(128)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "trace_id", "analysis_id", "finding_key", name="uq_incident_occurrence_idempotency"),
    )
    op.create_index("ix_incident_occurrences_tenant_incident", "incident_occurrences", ["tenant_id", "incident_id"])
    op.create_index("ix_incident_occurrences_tenant_observed", "incident_occurrences", ["tenant_id", "observed_at"])
    op.create_table(
        "incident_events",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False), sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False), sa.Column("actor_id", sa.String(128)),
        sa.Column("metadata", json_type, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incident_events_tenant_incident", "incident_events", ["tenant_id", "incident_id", "created_at"])
    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    tables = "incidents, incident_occurrences, incident_events"
    bind.execute(sa.text(f"REVOKE DELETE ON {tables} FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {tables} TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_incident_events_tenant_incident", table_name="incident_events")
    op.drop_table("incident_events")
    op.drop_index("ix_incident_occurrences_tenant_observed", table_name="incident_occurrences")
    op.drop_index("ix_incident_occurrences_tenant_incident", table_name="incident_occurrences")
    op.drop_table("incident_occurrences")
    op.drop_index("ix_incidents_tenant_severity", table_name="incidents")
    op.drop_index("ix_incidents_tenant_last_seen", table_name="incidents")
    op.drop_index("ix_incidents_tenant_status", table_name="incidents")
    op.drop_table("incidents")
