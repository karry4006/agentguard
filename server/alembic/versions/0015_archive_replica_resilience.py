"""add V18 archive replica resilience and verification policy"""

from alembic import op
import os
import sqlalchemy as sa

revision = "0015_archive_replica_resilience"
down_revision = "0014_ledger_segment_archival"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "archive_stores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("store_id", sa.String(128), nullable=False),
        sa.Column("provider_type", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(255)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("read_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("write_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("replication_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scrub_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("store_id"),
    )
    op.create_index("ix_archive_stores_enabled_priority", "archive_stores", ["enabled", "priority"])
    op.create_table(
        "archive_replicas",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("logical_archive_type", sa.String(32), nullable=False),
        sa.Column("logical_archive_id", sa.Uuid(), nullable=False),
        sa.Column("store_id", sa.String(128), nullable=False),
        sa.Column("object_key", sa.String(512), nullable=False),
        sa.Column("expected_ciphertext_sha256", sa.String(64), nullable=False),
        sa.Column("expected_plaintext_sha256", sa.String(64)),
        sa.Column("expected_logical_digest", sa.String(64), nullable=False),
        sa.Column("encryption_key_id", sa.String(128), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("last_scrubbed_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_category", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("logical_archive_type", "logical_archive_id", "store_id", name="uq_archive_replicas_logical_store"),
        sa.CheckConstraint("state IN ('PENDING','REPLICATING','VERIFYING','VALID','MISSING','UNAVAILABLE','CORRUPT','CONFLICT','UNVERIFIABLE_KEY_MISSING','REPAIR_PENDING','REPAIRING','FAILED')", name="ck_archive_replica_state"),
    )
    op.create_index("ix_archive_replicas_logical", "archive_replicas", ["tenant_id", "logical_archive_type", "logical_archive_id"])
    op.create_index("ix_archive_replicas_store_state", "archive_replicas", ["store_id", "state"])
    op.create_index("ix_archive_replicas_verification", "archive_replicas", ["state", "verified_at"])
    op.create_table(
        "archive_replication_jobs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("logical_archive_type", sa.String(32), nullable=False), sa.Column("logical_archive_id", sa.Uuid(), nullable=False),
        sa.Column("source_store_id", sa.String(128), nullable=False), sa.Column("target_store_id", sa.String(128), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="PENDING"), sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)), sa.Column("claimed_by", sa.String(128)), sa.Column("claim_token", sa.String(64)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)), sa.Column("lease_expires_at", sa.DateTime(timezone=True)), sa.Column("last_error_category", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_archive_replication_jobs_claimable", "archive_replication_jobs", ["status", "next_attempt_at", "lease_expires_at"])
    op.create_table(
        "archive_scrub_runs",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("store_id", sa.String(128), nullable=False), sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("logical_archive_type", sa.String(32), nullable=False), sa.Column("logical_archive_id", sa.Uuid(), nullable=False),
        sa.Column("result", sa.String(48), nullable=False), sa.Column("verification_depth", sa.String(8), nullable=False, server_default="FULL"),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False), sa.Column("error_category", sa.String(64)), sa.Column("worker_instance_id", sa.String(128), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_archive_scrub_runs_lookup", "archive_scrub_runs", ["store_id", "checked_at"])
    op.create_table(
        "archive_replica_policy",
        sa.Column("id", sa.Uuid(), nullable=False), sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("minimum_verified_replicas", sa.Integer(), nullable=False, server_default="1"), sa.Column("required_store_ids", sa.Text()),
        sa.Column("repair_missing_replicas", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("scrub_interval_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("max_replication_attempts", sa.Integer(), nullable=False, server_default="10"), sa.Column("write_targets", sa.Text()), sa.Column("read_order", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("policy_version"),
    )
    op.add_column("ledger_compaction_authorizations", sa.Column("replica_policy_version", sa.String(64)))
    op.add_column("ledger_compaction_authorizations", sa.Column("verified_replica_count", sa.Integer()))
    op.add_column("ledger_compaction_authorizations", sa.Column("required_store_ids", sa.Text()))

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
        retention = _identifier(os.getenv("AGENTGUARD_RETENTION_USER", "agentguard_retention"))
        replication_name = os.getenv("AGENTGUARD_ARCHIVE_REPLICATION_USER", "agentguard_replication_worker")
        replication = _identifier(replication_name)
        compactor_name = os.getenv("AGENTGUARD_LEDGER_COMPACTOR_USER", "agentguard_ledger_compactor")
        compactor = _identifier(compactor_name)
        database_name = _identifier(str(bind.engine.url.database or ""))
        bind.execute(sa.text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{replication_name}') THEN CREATE ROLE {replication} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $$"))
        bind.execute(sa.text(f"REVOKE CREATE, TEMPORARY ON DATABASE {database_name} FROM {replication}"))
        bind.execute(sa.text(f"REVOKE CREATE ON SCHEMA public FROM {replication}"))
        for table in ("archive_stores", "archive_replicas", "archive_replication_jobs", "archive_scrub_runs", "archive_replica_policy"):
            bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {replication}"))
            bind.execute(sa.text(f"GRANT SELECT ON {table} TO {runtime}"))
            bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {retention}"))
            # Compaction may read the V18 policy and replica evidence, but it
            # cannot mutate replica/job/scrub state.
            bind.execute(sa.text(f"GRANT SELECT ON {table} TO {compactor}"))
        bind.execute(sa.text(f"GRANT INSERT, UPDATE ON archive_replica_policy TO {compactor}"))
        bind.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {replication}"))
        # The V17 SECURITY DEFINER compaction function is sealed in 0014. A
        # V18 trigger adds an independent database-side fail-closed gate.
        bind.execute(sa.text("""
            CREATE OR REPLACE FUNCTION public.v18_guard_ledger_compaction()
            RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, public AS $fn$
            DECLARE required_count integer; actual_count integer;
            BEGIN
                IF NEW.status = 'COMPACTED' AND OLD.status <> 'COMPACTED'
                   AND EXISTS (SELECT 1 FROM public.archive_replica_policy) THEN
                    SELECT minimum_verified_replicas INTO required_count
                      FROM public.archive_replica_policy ORDER BY created_at DESC LIMIT 1;
                    SELECT count(*) INTO actual_count
                      FROM public.archive_replicas r
                     WHERE r.logical_archive_type = 'LEDGER_SEGMENT'
                       AND r.logical_archive_id = NEW.segment_id
                       AND r.state = 'VALID' AND r.verified_at IS NOT NULL
                       AND r.verified_at >= clock_timestamp() - interval '1 day';
                    IF actual_count < required_count THEN
                        RAISE EXCEPTION 'V18 minimum verified replicas not met';
                    END IF;
                END IF;
                RETURN NEW;
            END; $fn$;
        """))
        bind.execute(sa.text("DROP TRIGGER IF EXISTS v18_guard_ledger_compaction_trigger ON public.ledger_segment_lifecycle"))
        bind.execute(sa.text("CREATE TRIGGER v18_guard_ledger_compaction_trigger BEFORE UPDATE OF status ON public.ledger_segment_lifecycle FOR EACH ROW EXECUTE FUNCTION public.v18_guard_ledger_compaction()"))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("DROP TRIGGER IF EXISTS v18_guard_ledger_compaction_trigger ON public.ledger_segment_lifecycle"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS public.v18_guard_ledger_compaction()"))
    op.drop_column("ledger_compaction_authorizations", "required_store_ids")
    op.drop_column("ledger_compaction_authorizations", "verified_replica_count")
    op.drop_column("ledger_compaction_authorizations", "replica_policy_version")
    op.drop_index("ix_archive_scrub_runs_lookup", table_name="archive_scrub_runs")
    op.drop_table("archive_scrub_runs")
    op.drop_index("ix_archive_replication_jobs_claimable", table_name="archive_replication_jobs")
    op.drop_table("archive_replication_jobs")
    op.drop_index("ix_archive_replicas_verification", table_name="archive_replicas")
    op.drop_index("ix_archive_replicas_store_state", table_name="archive_replicas")
    op.drop_index("ix_archive_replicas_logical", table_name="archive_replicas")
    op.drop_table("archive_replicas")
    op.drop_index("ix_archive_stores_enabled_priority", table_name="archive_stores")
    op.drop_table("archive_stores")
    op.drop_table("archive_replica_policy")
