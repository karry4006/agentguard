"""add V20 quorum bindings to the V19 integrity archive catalog"""

from alembic import op
import sqlalchemy as sa


revision = "0018_v20_archive_quorum_bindings"
down_revision = "0017_multi_witness_quorum"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IntegrityArchiveSegment is queried by the dashboard and is re-authorized
    # by the V19 compactor.  Keep these nullable so pre-V20 archive history
    # remains readable while allowing V20 to bind new archive work to the
    # policy evaluation that authorized it.
    table = "integrity_archive_segments"
    op.add_column(table, sa.Column("v20_policy_epoch", sa.Integer(), nullable=True))
    op.add_column(table, sa.Column("v20_quorum_evaluation_digest", sa.String(64), nullable=True))
    op.add_column(table, sa.Column("v20_quorum_state", sa.String(64), nullable=True))
    op.add_column(table, sa.Column("v20_receipt_set_digest", sa.String(64), nullable=True))
    op.add_column(table, sa.Column("v20_evaluated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(table, sa.Column("v20_fresh_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    table = "integrity_archive_segments"
    for column in (
        "v20_fresh_until",
        "v20_evaluated_at",
        "v20_receipt_set_digest",
        "v20_quorum_state",
        "v20_quorum_evaluation_digest",
        "v20_policy_epoch",
    ):
        op.drop_column(table, column)
