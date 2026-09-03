"""add V20 multi-witness quorum evidence and durable publication jobs"""

from alembic import op
import os
import sqlalchemy as sa


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'

revision = "0017_multi_witness_quorum"
down_revision = "0016_integrity_metadata_segmentation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # These nullable bindings preserve all V15/V19 rows and their historical
    # single-witness interpretation.
    op.add_column("integrity_checkpoints", sa.Column("policy_epoch", sa.Integer(), nullable=True))
    op.add_column("integrity_checkpoints", sa.Column("policy_digest", sa.String(64), nullable=True))
    for table in ("ledger_compaction_authorizations", "integrity_compaction_authorizations"):
        op.add_column(table, sa.Column("v20_policy_epoch", sa.Integer(), nullable=True))
        op.add_column(table, sa.Column("v20_quorum_evaluation_digest", sa.String(64), nullable=True))
        op.add_column(table, sa.Column("v20_quorum_state", sa.String(64), nullable=True))
        op.add_column(table, sa.Column("v20_receipt_set_digest", sa.String(64), nullable=True))
        op.add_column(table, sa.Column("v20_evaluated_at", sa.DateTime(timezone=True), nullable=True))
        op.add_column(table, sa.Column("v20_fresh_until", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "witnesses",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("witness_id", sa.String(128), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False), sa.Column("verification_key_id", sa.String(128), nullable=False),
        sa.Column("verification_public_key", sa.Text(), nullable=False), sa.Column("endpoint_config_ref", sa.String(255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("witness_id", name="uq_witnesses_canonical_id"),
    )
    op.create_index("ix_witnesses_enabled", "witnesses", ["enabled"])
    op.create_table(
        "witness_verification_keys",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("witness_id", sa.String(128), nullable=False),
        sa.Column("verification_key_id", sa.String(128), nullable=False), sa.Column("verification_public_key", sa.Text(), nullable=False),
        sa.Column("key_epoch", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("witness_id", "verification_key_id", name="uq_witness_verification_key"),
    )
    op.create_table(
        "witness_quorum_policies",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False), sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False), sa.Column("strict_conflict_blocking", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allow_degraded_match", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("receipt_freshness_seconds", sa.Integer(), nullable=False, server_default="900"),
        sa.Column("quorum_freshness_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("conflict_behavior", sa.String(64), nullable=False, server_default="BLOCK_ANY_VALID_CONTRADICTION"),
        sa.Column("policy_digest", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)), sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("policy_epoch", name="uq_witness_quorum_policies_epoch"),
        sa.CheckConstraint("threshold >= 1", name="ck_witness_quorum_threshold_positive"),
        sa.CheckConstraint("member_count >= threshold", name="ck_witness_quorum_threshold_lte_members"),
    )
    op.create_table(
        "witness_quorum_policy_members",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("witness_id", sa.String(128), nullable=False), sa.Column("verification_key_id", sa.String(128), nullable=False),
        sa.Column("key_epoch", sa.Integer(), nullable=False, server_default="1"), sa.Column("position", sa.Integer()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_epoch", "witness_id", name="uq_witness_quorum_policy_member"),
    )
    op.create_index("ix_witness_quorum_policy_members_epoch", "witness_quorum_policy_members", ["policy_epoch", "enabled"])
    op.create_table(
        "checkpoint_witness_receipts",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("checkpoint_digest", sa.String(64), nullable=False), sa.Column("checkpoint_sequence", sa.Integer(), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False), sa.Column("witness_id", sa.String(128), nullable=False),
        sa.Column("verification_key_id", sa.String(128), nullable=False), sa.Column("receipt_version", sa.String(64), nullable=False),
        sa.Column("receipt_payload_hash", sa.String(64), nullable=False), sa.Column("signature", sa.String(256), nullable=False),
        sa.Column("witness_head_sequence", sa.Integer()), sa.Column("witness_head_digest", sa.String(64)),
        sa.Column("continuity_state", sa.String(32), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["checkpoint_id"], ["integrity_checkpoints.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("checkpoint_id", "policy_epoch", "witness_id", name="uq_checkpoint_witness_receipt"),
    )
    op.create_index("ix_checkpoint_witness_receipts_lookup", "checkpoint_witness_receipts", ["checkpoint_id", "policy_epoch", "created_at"])
    op.create_table(
        "witness_publish_jobs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("witness_id", sa.String(128), nullable=False), sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="PENDING"), sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)), sa.Column("claimed_by", sa.String(128)), sa.Column("claim_token", sa.String(64)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)), sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_category", sa.String(96)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.ForeignKeyConstraint(["checkpoint_id"], ["integrity_checkpoints.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("checkpoint_id", "policy_epoch", "witness_id", name="uq_witness_publish_job"),
    )
    op.create_index("ix_witness_publish_jobs_claimable", "witness_publish_jobs", ["status", "next_attempt_at", "lease_expires_at"])
    op.create_table(
        "checkpoint_quorum_evaluations",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("checkpoint_id", sa.Uuid(), nullable=False), sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("evaluation_state", sa.String(64), nullable=False), sa.Column("threshold", sa.Integer(), nullable=False), sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("unavailable_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("conflict_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("invalid_signature_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("valid_receipt_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("receipt_set_digest", sa.String(64), nullable=False),
        sa.Column("evaluation_digest", sa.String(64), nullable=False), sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fresh_until", sa.DateTime(timezone=True)), sa.Column("blocking_reason", sa.String(128)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["checkpoint_id"], ["integrity_checkpoints.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("checkpoint_id", "policy_epoch", name="uq_checkpoint_quorum_evaluation"),
    )
    op.create_index("ix_checkpoint_quorum_evaluations_fresh", "checkpoint_quorum_evaluations", ["checkpoint_id", "fresh_until"])
    op.create_table(
        "witness_health_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("witness_id", sa.String(128), nullable=False), sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("health_state", sa.String(64), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail_code", sa.String(96)), sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_witness_health_snapshots_latest", "witness_health_snapshots", ["witness_id", "observed_at"])

    # V15 intentionally makes checkpoint history append-only for the runtime
    # role. V20 adds only the two policy-binding columns as a controlled update
    # and gives the runtime/quorum workers DML on their new durable tables.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
        bind.execute(sa.text(
            f"GRANT UPDATE (policy_epoch, policy_digest) ON integrity_checkpoints TO {runtime}"
        ))
        for table in (
            "witnesses", "witness_verification_keys", "witness_quorum_policies",
            "witness_quorum_policy_members", "checkpoint_witness_receipts",
            "witness_publish_jobs", "checkpoint_quorum_evaluations", "witness_health_snapshots",
        ):
            bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {runtime}"))


def downgrade() -> None:
    op.drop_index("ix_witness_health_snapshots_latest", table_name="witness_health_snapshots"); op.drop_table("witness_health_snapshots")
    op.drop_index("ix_checkpoint_quorum_evaluations_fresh", table_name="checkpoint_quorum_evaluations"); op.drop_table("checkpoint_quorum_evaluations")
    op.drop_index("ix_witness_publish_jobs_claimable", table_name="witness_publish_jobs"); op.drop_table("witness_publish_jobs")
    op.drop_index("ix_checkpoint_witness_receipts_lookup", table_name="checkpoint_witness_receipts"); op.drop_table("checkpoint_witness_receipts")
    op.drop_index("ix_witness_quorum_policy_members_epoch", table_name="witness_quorum_policy_members"); op.drop_table("witness_quorum_policy_members")
    op.drop_table("witness_quorum_policies")
    op.drop_table("witness_verification_keys")
    op.drop_index("ix_witnesses_enabled", table_name="witnesses"); op.drop_table("witnesses")
    for table in ("ledger_compaction_authorizations", "integrity_compaction_authorizations"):
        for column in ("v20_fresh_until", "v20_evaluated_at", "v20_receipt_set_digest", "v20_quorum_state", "v20_quorum_evaluation_digest", "v20_policy_epoch"):
            op.drop_column(table, column)
    op.drop_column("integrity_checkpoints", "policy_digest"); op.drop_column("integrity_checkpoints", "policy_epoch")
