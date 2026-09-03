"""create AgentGuard telemetry tables"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table("traces",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("workflow_name", sa.String(length=255)),
        sa.Column("group_id", sa.String(length=255)),
        sa.Column("provider", sa.String(length=100)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("metadata", json_type, nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("trace_id"))
    op.create_index("ix_traces_trace_id", "traces", ["trace_id"], unique=False)
    op.create_table("spans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("span_id", sa.String(length=255), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("parent_span_id", sa.String(length=255)),
        sa.Column("span_type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Float()),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_type", sa.String(length=255)),
        sa.Column("error_message", sa.Text()),
        sa.Column("attributes", json_type, nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["trace_id"], ["traces.trace_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("span_id"))
    op.create_index("ix_spans_trace_id", "spans", ["trace_id"], unique=False)
    op.create_index("ix_spans_parent_span_id", "spans", ["parent_span_id"], unique=False)
    op.create_table("event_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_key", sa.String(length=600), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("event_key"))


def downgrade() -> None:
    op.drop_table("event_log")
    op.drop_index("ix_spans_parent_span_id", table_name="spans")
    op.drop_index("ix_spans_trace_id", table_name="spans")
    op.drop_table("spans")
    op.drop_index("ix_traces_trace_id", table_name="traces")
    op.drop_table("traces")

