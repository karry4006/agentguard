"""add secure notification alerting tables"""

import os
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_notification_alerting"
down_revision = "0007_incident_management"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table("notification_destinations",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False), sa.Column("type", sa.String(32), nullable=False), sa.Column("endpoint_scheme", sa.String(8), nullable=False),
        sa.Column("endpoint_host", sa.String(255), nullable=False), sa.Column("endpoint_port", sa.Integer(), nullable=False),
        sa.Column("endpoint_path", sa.String(1024), nullable=False), sa.Column("signing_secret_reference", sa.String(128)),
        sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_notification_destinations_tenant_enabled", "notification_destinations", ["tenant_id", "enabled"])
    op.create_table("alert_policies",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False), sa.Column("minimum_severity", sa.String(16), nullable=False),
        sa.Column("incident_status_filter", json_type, nullable=False), sa.Column("failure_categories", json_type, nullable=False),
        sa.Column("event_types", json_type, nullable=False), sa.Column("cooldown_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_alert_policies_tenant_enabled", "alert_policies", ["tenant_id", "enabled"])
    op.create_table("notification_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False), sa.Column("destination_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False), sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("lifecycle_version", sa.Integer(), nullable=False), sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False), sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("payload", json_type, nullable=False), sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("failure_category", sa.String(32)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)), sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["destination_id"], ["notification_destinations.id"], ondelete="RESTRICT"), sa.ForeignKeyConstraint(["policy_id"], ["alert_policies.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_notification_delivery_idempotency"))
    op.create_index("ix_notification_deliveries_tenant_status", "notification_deliveries", ["tenant_id", "status", "next_retry_at"])
    op.create_index("ix_notification_deliveries_tenant_incident", "notification_deliveries", ["tenant_id", "incident_id", "created_at"])
    op.create_table("notification_events",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("delivery_id", sa.Uuid(), nullable=False), sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("metadata", json_type, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["delivery_id"], ["notification_deliveries.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"))
    op.create_index("ix_notification_events_tenant_delivery", "notification_events", ["tenant_id", "delivery_id", "created_at"])
    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    tables = "notification_destinations, alert_policies, notification_deliveries, notification_events"
    bind = op.get_bind()
    bind.execute(sa.text(f"REVOKE DELETE ON {tables} FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {tables} TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_notification_events_tenant_delivery", table_name="notification_events")
    op.drop_table("notification_events")
    op.drop_index("ix_notification_deliveries_tenant_incident", table_name="notification_deliveries")
    op.drop_index("ix_notification_deliveries_tenant_status", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_index("ix_alert_policies_tenant_enabled", table_name="alert_policies")
    op.drop_table("alert_policies")
    op.drop_index("ix_notification_destinations_tenant_enabled", table_name="notification_destinations")
    op.drop_table("notification_destinations")
