"""add tenants, API keys, and tenant-aware telemetry constraints"""
from datetime import datetime, timezone
import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_trust_boundary"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=False)
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("public_id", sa.String(length=64), nullable=False),
        sa.Column("secret_digest", sa.String(length=64), nullable=False),
        sa.Column("scopes", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"], unique=False)
    op.create_index("ix_api_keys_public_id", "api_keys", ["public_id"], unique=False)

    bind = op.get_bind()
    local_id = uuid.uuid4()
    bind.execute(
        sa.text("INSERT INTO tenants (id, slug, name, created_at) VALUES (:id, :slug, :name, :created_at)"),
        {"id": local_id, "slug": "local", "name": "Local legacy tenant", "created_at": datetime.now(timezone.utc)},
    )

    op.add_column("traces", sa.Column("tenant_id", sa.Uuid(), nullable=True))
    op.add_column("spans", sa.Column("tenant_id", sa.Uuid(), nullable=True))
    op.add_column("event_log", sa.Column("tenant_id", sa.Uuid(), nullable=True))
    op.add_column("event_log", sa.Column("event_id", sa.String(length=255), nullable=True))
    bind.execute(sa.text("UPDATE traces SET tenant_id = :tenant_id"), {"tenant_id": local_id})
    bind.execute(sa.text("UPDATE spans SET tenant_id = :tenant_id"), {"tenant_id": local_id})
    bind.execute(sa.text("UPDATE event_log SET tenant_id = :tenant_id, event_id = event_key"), {"tenant_id": local_id})

    op.alter_column("traces", "tenant_id", nullable=False)
    op.alter_column("spans", "tenant_id", nullable=False)
    op.alter_column("event_log", "tenant_id", nullable=False)
    op.alter_column("event_log", "event_id", nullable=False)

    # The V0 span FK depended on the global trace_id unique constraint.
    op.drop_constraint("spans_trace_id_fkey", "spans", type_="foreignkey")
    op.drop_constraint("traces_trace_id_key", "traces", type_="unique")
    # V0 left these constraints unnamed; PostgreSQL generated these names.
    op.drop_constraint("spans_span_id_key", "spans", type_="unique")
    op.drop_constraint("event_log_event_key_key", "event_log", type_="unique")
    op.create_unique_constraint("uq_traces_tenant_trace_id", "traces", ["tenant_id", "trace_id"])
    op.create_unique_constraint("uq_spans_tenant_span_id", "spans", ["tenant_id", "span_id"])
    op.create_unique_constraint("uq_event_log_tenant_event", "event_log", ["tenant_id", "event_type", "event_id"])
    op.create_foreign_key("fk_traces_tenant", "traces", "tenants", ["tenant_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("fk_spans_tenant_trace", "spans", "traces", ["tenant_id", "trace_id"], ["tenant_id", "trace_id"], ondelete="CASCADE")
    op.create_foreign_key("fk_event_log_tenant", "event_log", "tenants", ["tenant_id"], ["id"], ondelete="CASCADE")

    for index_name, table_name in (("ix_traces_trace_id", "traces"), ("ix_spans_trace_id", "spans"), ("ix_spans_parent_span_id", "spans")):
        op.drop_index(index_name, table_name=table_name)
    op.create_index("ix_traces_tenant_trace", "traces", ["tenant_id", "trace_id"], unique=False)
    op.create_index("ix_spans_tenant_trace", "spans", ["tenant_id", "trace_id"], unique=False)
    op.create_index("ix_spans_tenant_parent", "spans", ["tenant_id", "parent_span_id"], unique=False)
    op.create_index("ix_event_log_tenant_key", "event_log", ["tenant_id", "event_type", "event_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_event_log_tenant_key", table_name="event_log")
    op.drop_index("ix_spans_tenant_parent", table_name="spans")
    op.drop_index("ix_spans_tenant_trace", table_name="spans")
    op.drop_index("ix_traces_tenant_trace", table_name="traces")
    op.drop_constraint("fk_event_log_tenant", "event_log", type_="foreignkey")
    op.drop_constraint("fk_spans_tenant_trace", "spans", type_="foreignkey")
    op.drop_constraint("fk_traces_tenant", "traces", type_="foreignkey")
    op.drop_constraint("uq_event_log_tenant_event", "event_log", type_="unique")
    op.drop_constraint("uq_spans_tenant_span_id", "spans", type_="unique")
    op.drop_constraint("uq_traces_tenant_trace_id", "traces", type_="unique")
    op.create_unique_constraint("event_log_event_key_key", "event_log", ["event_key"])
    op.create_unique_constraint("spans_span_id_key", "spans", ["span_id"])
    op.create_unique_constraint("traces_trace_id_key", "traces", ["trace_id"])
    op.drop_column("event_log", "event_id")
    op.drop_column("event_log", "tenant_id")
    op.drop_column("spans", "tenant_id")
    op.drop_column("traces", "tenant_id")
    op.drop_index("ix_api_keys_public_id", table_name="api_keys")
    op.drop_index("ix_api_keys_tenant_id", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_table("tenants")
