"""add opaque operator dashboard sessions"""

import os
from alembic import op
import sqlalchemy as sa

revision = "0009_dashboard_sessions"
down_revision = "0008_notification_alerting"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "dashboard_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("api_key_id", sa.Uuid(), nullable=False),
        sa.Column("session_token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_token_hash", name="uq_dashboard_sessions_token_hash"),
    )
    op.create_index("ix_dashboard_sessions_tenant_active", "dashboard_sessions", ["tenant_id", "expires_at", "revoked_at"])
    op.create_index("ix_dashboard_sessions_api_key_active", "dashboard_sessions", ["api_key_id", "expires_at", "revoked_at"])
    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    bind.execute(sa.text(f"REVOKE DELETE ON dashboard_sessions FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON dashboard_sessions TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_dashboard_sessions_api_key_active", table_name="dashboard_sessions")
    op.drop_index("ix_dashboard_sessions_tenant_active", table_name="dashboard_sessions")
    op.drop_table("dashboard_sessions")
