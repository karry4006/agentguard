"""add human identity, organizations, and fixed-role RBAC"""

import os

from alembic import op
import sqlalchemy as sa

revision = "0010_human_identity_rbac"
down_revision = "0009_dashboard_sessions"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "human_users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("external_issuer", sa.String(512), nullable=False),
        sa.Column("external_subject", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255)),
        sa.Column("email", sa.String(320)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("external_issuer", "external_subject", name="uq_human_users_external_identity"),
    )
    op.create_index("ix_human_users_external_identity", "human_users", ["external_issuer", "external_subject"])
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_organizations_tenant_id"),
    )
    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("role IN ('VIEWER','ENGINEER','ADMIN')", name="ck_organization_memberships_role"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["human_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_organization_memberships_org_user"),
    )
    op.create_index("ix_organization_memberships_user_active", "organization_memberships", ["user_id", "disabled_at"])
    op.create_table(
        "oidc_login_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("code_verifier", sa.String(128)),
        sa.Column("return_to", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("state_hash", name="uq_oidc_login_attempts_state_hash"),
    )
    op.create_index("ix_oidc_login_attempts_expiry", "oidc_login_attempts", ["expires_at", "used_at"])
    op.create_table(
        "identity_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid()),
        sa.Column("organization_id", sa.Uuid()),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(128)),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("target_user_id", sa.Uuid()),
        sa.Column("target_membership_id", sa.Uuid()),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_user_id"], ["human_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_membership_id"], ["organization_memberships.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_identity_audit_org_created", "identity_audit_events", ["organization_id", "created_at"])

    op.alter_column("dashboard_sessions", "tenant_id", existing_type=sa.Uuid(), nullable=True)
    op.alter_column("dashboard_sessions", "api_key_id", existing_type=sa.Uuid(), nullable=True)
    op.add_column("dashboard_sessions", sa.Column("human_user_id", sa.Uuid()))
    op.add_column("dashboard_sessions", sa.Column("organization_id", sa.Uuid()))
    op.create_foreign_key("fk_dashboard_sessions_human_user", "dashboard_sessions", "human_users",
                          ["human_user_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("fk_dashboard_sessions_organization", "dashboard_sessions", "organizations",
                          ["organization_id"], ["id"], ondelete="CASCADE")
    op.create_check_constraint("ck_dashboard_sessions_one_principal", "dashboard_sessions",
        "(api_key_id IS NOT NULL AND human_user_id IS NULL) OR (api_key_id IS NULL AND human_user_id IS NOT NULL)")
    op.create_index("ix_dashboard_sessions_human_active", "dashboard_sessions", ["human_user_id", "expires_at", "revoked_at"])

    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    bind = op.get_bind()
    for table in ("human_users", "organizations", "organization_memberships", "oidc_login_attempts"):
        bind.execute(sa.text(f"REVOKE DELETE ON {table} FROM {runtime}"))
        bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {runtime}"))
    bind.execute(sa.text(f"REVOKE UPDATE, DELETE ON identity_audit_events FROM {runtime}"))
    bind.execute(sa.text(f"GRANT SELECT, INSERT ON identity_audit_events TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_dashboard_sessions_human_active", table_name="dashboard_sessions")
    op.drop_constraint("ck_dashboard_sessions_one_principal", "dashboard_sessions", type_="check")
    op.drop_constraint("fk_dashboard_sessions_organization", "dashboard_sessions", type_="foreignkey")
    op.drop_constraint("fk_dashboard_sessions_human_user", "dashboard_sessions", type_="foreignkey")
    op.drop_column("dashboard_sessions", "organization_id")
    op.drop_column("dashboard_sessions", "human_user_id")
    op.alter_column("dashboard_sessions", "api_key_id", existing_type=sa.Uuid(), nullable=False)
    op.alter_column("dashboard_sessions", "tenant_id", existing_type=sa.Uuid(), nullable=False)
    op.drop_index("ix_identity_audit_org_created", table_name="identity_audit_events")
    op.drop_table("identity_audit_events")
    op.drop_index("ix_oidc_login_attempts_expiry", table_name="oidc_login_attempts")
    op.drop_table("oidc_login_attempts")
    op.drop_index("ix_organization_memberships_user_active", table_name="organization_memberships")
    op.drop_table("organization_memberships")
    op.drop_table("organizations")
    op.drop_index("ix_human_users_external_identity", table_name="human_users")
    op.drop_table("human_users")
