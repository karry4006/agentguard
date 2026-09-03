"""add PostgreSQL-backed distributed coordination state"""

import os

from alembic import op
import sqlalchemy as sa


revision = "0011_distributed_coordination"
down_revision = "0010_human_identity_rbac"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "distributed_rate_limit_buckets",
        sa.Column("bucket_key_hash", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_type", sa.String(64), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("bucket_key_hash", "window_start"),
    )
    op.create_index(
        "ix_rate_limit_buckets_type_window", "distributed_rate_limit_buckets",
        ["bucket_type", "window_start"],
    )

    op.add_column("notification_deliveries", sa.Column("claimed_by", sa.String(128)))
    op.add_column("notification_deliveries", sa.Column("claim_token", sa.String(64)))
    op.add_column("notification_deliveries", sa.Column("claimed_at", sa.DateTime(timezone=True)))
    op.add_column("notification_deliveries", sa.Column("lease_expires_at", sa.DateTime(timezone=True)))
    op.add_column("notification_deliveries", sa.Column("claim_attempt", sa.Integer(), nullable=False, server_default="0"))
    op.create_index(
        "ix_notification_deliveries_claimable", "notification_deliveries",
        ["status", "next_retry_at", "lease_expires_at"],
    )

    op.create_table(
        "notification_circuit_states",
        sa.Column("destination_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="CLOSED"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("opened_at", sa.DateTime(timezone=True)),
        sa.Column("next_probe_at", sa.DateTime(timezone=True)),
        sa.Column("half_open_probe_owner", sa.String(64)),
        sa.Column("half_open_lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["destination_id"], ["notification_destinations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("destination_id"),
    )
    op.create_index(
        "ix_notification_circuit_states_state_probe", "notification_circuit_states",
        ["state", "next_probe_at"],
    )

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
        bind.execute(sa.text(
            f"REVOKE DELETE ON distributed_rate_limit_buckets, notification_circuit_states FROM {runtime}"
        ))
        bind.execute(sa.text(
            f"GRANT SELECT, INSERT, UPDATE ON distributed_rate_limit_buckets, notification_circuit_states TO {runtime}"
        ))
        bind.execute(sa.text(
            f"REVOKE DELETE ON notification_deliveries FROM {runtime}"
        ))
        bind.execute(sa.text(
            f"GRANT SELECT, INSERT, UPDATE ON notification_deliveries TO {runtime}"
        ))


def downgrade() -> None:
    op.drop_index("ix_notification_circuit_states_state_probe", table_name="notification_circuit_states")
    op.drop_table("notification_circuit_states")
    op.drop_index("ix_notification_deliveries_claimable", table_name="notification_deliveries")
    op.drop_column("notification_deliveries", "claim_attempt")
    op.drop_column("notification_deliveries", "lease_expires_at")
    op.drop_column("notification_deliveries", "claimed_at")
    op.drop_column("notification_deliveries", "claim_token")
    op.drop_column("notification_deliveries", "claimed_by")
    op.drop_index("ix_rate_limit_buckets_type_window", table_name="distributed_rate_limit_buckets")
    op.drop_table("distributed_rate_limit_buckets")