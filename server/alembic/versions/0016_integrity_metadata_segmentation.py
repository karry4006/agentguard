"""add V19 verifiable integrity metadata segmentation and compaction"""

import os

from alembic import op
import sqlalchemy as sa


revision = "0016_integrity_metadata_segmentation"
down_revision = "0015_archive_replica_resilience"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "integrity_archive_segments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(255), nullable=False),
        sa.Column("segment_sequence", sa.Integer(), nullable=False),
        sa.Column("segment_version", sa.String(32), nullable=False),
        sa.Column("envelope_version", sa.String(64), nullable=False),
        sa.Column("source_start_sequence", sa.Integer(), nullable=False),
        sa.Column("source_end_sequence", sa.Integer(), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("first_record_id", sa.Uuid(), nullable=False),
        sa.Column("last_record_id", sa.Uuid(), nullable=False),
        sa.Column("first_event_hash", sa.String(64), nullable=False),
        sa.Column("last_event_hash", sa.String(64), nullable=False),
        sa.Column("predecessor_boundary_hash", sa.String(64)),
        sa.Column("successor_boundary_hash", sa.String(64)),
        sa.Column("records_manifest_digest", sa.String(64), nullable=False),
        sa.Column("logical_segment_digest", sa.String(64), nullable=False),
        sa.Column("plaintext_sha256", sa.String(64)),
        sa.Column("ciphertext_sha256", sa.String(64)),
        sa.Column("archive_key_id", sa.String(128)),
        sa.Column("archive_object_key", sa.String(512)),
        sa.Column("archive_logical_id", sa.Uuid()),
        sa.Column("v17_ledger_segment_id", sa.Uuid(), nullable=False),
        sa.Column("v17_ledger_segment_digest", sa.String(64), nullable=False),
        sa.Column("v15_checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("v15_checkpoint_digest", sa.String(64), nullable=False),
        sa.Column("v15_continuity_status", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="PLANNED"),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("compacted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["v17_ledger_segment_id"], ["ledger_segments.id"]),
        sa.ForeignKeyConstraint(["v15_checkpoint_id"], ["integrity_checkpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "trace_id", "segment_sequence", name="uq_integrity_segments_trace_sequence"),
        sa.UniqueConstraint("tenant_id", "trace_id", "source_start_sequence", name="uq_integrity_segments_trace_start"),
        sa.UniqueConstraint("tenant_id", "trace_id", "source_end_sequence", name="uq_integrity_segments_trace_end"),
        sa.UniqueConstraint("archive_object_key", name="uq_integrity_segments_archive_object_key"),
        sa.UniqueConstraint("archive_logical_id", name="uq_integrity_segments_archive_logical_id"),
        sa.CheckConstraint("source_start_sequence <= source_end_sequence", name="ck_integrity_segments_range"),
        sa.CheckConstraint("record_count > 0", name="ck_integrity_segments_record_count"),
        sa.CheckConstraint("state IN ('PLANNED','BUILDING','ARCHIVED','VERIFYING','ARCHIVED_VERIFIED','REPLICA_POLICY_PENDING','READY_TO_COMPACT','COMPACTING','COMPACTED','BLOCKED','FAILED')", name="ck_integrity_segments_state"),
    )
    op.create_index("ix_integrity_segments_tenant_trace_state", "integrity_archive_segments", ["tenant_id", "trace_id", "state"])
    op.create_index("ix_integrity_segments_candidate", "integrity_archive_segments", ["state", "created_at"])

    op.create_table(
        "integrity_compaction_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("segment_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="PENDING"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_by", sa.String(128)),
        sa.Column("claim_token", sa.String(64)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_category", sa.String(96)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["segment_id"], ["integrity_archive_segments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_integrity_compaction_jobs_claimable", "integrity_compaction_jobs", ["status", "next_attempt_at", "lease_expires_at"])

    op.create_table(
        "integrity_compaction_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("segment_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("source_start_sequence", sa.Integer(), nullable=False),
        sa.Column("source_end_sequence", sa.Integer(), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("logical_segment_digest", sa.String(64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(64), nullable=False),
        sa.Column("predecessor_boundary_hash", sa.String(64)),
        sa.Column("successor_boundary_hash", sa.String(64)),
        sa.Column("replica_policy_version", sa.String(64), nullable=False),
        sa.Column("verified_replica_count", sa.Integer(), nullable=False),
        sa.Column("v17_ledger_segment_digest", sa.String(64), nullable=False),
        sa.Column("v15_checkpoint_digest", sa.String(64), nullable=False),
        sa.Column("v15_continuity_status", sa.String(32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_by_instance", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["segment_id"], ["integrity_archive_segments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_integrity_compaction_auth_expiry", "integrity_compaction_authorizations", ["segment_id", "expires_at"])

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
    retention = _identifier(os.getenv("AGENTGUARD_RETENTION_USER", "agentguard_retention"))
    replication = _identifier(os.getenv("AGENTGUARD_ARCHIVE_REPLICATION_USER", "agentguard_replication_worker"))
    ledger_compactor = _identifier(os.getenv("AGENTGUARD_LEDGER_COMPACTOR_USER", "agentguard_ledger_compactor"))
    integrity_compactor_name = os.getenv("AGENTGUARD_INTEGRITY_COMPACTOR_USER", "agentguard_integrity_compactor")
    integrity_compactor = _identifier(integrity_compactor_name)
    database_name = _identifier(str(bind.engine.url.database or ""))
    bind.execute(sa.text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{integrity_compactor_name}') THEN CREATE ROLE {integrity_compactor} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF; END $$"))
    bind.execute(sa.text(f"REVOKE CREATE, TEMPORARY ON DATABASE {database_name} FROM {integrity_compactor}"))
    bind.execute(sa.text(f"REVOKE DELETE ON public.integrity_records FROM {runtime}, {retention}, {replication}, {ledger_compactor}, {integrity_compactor}, PUBLIC"))
    for table in ("integrity_archive_segments", "integrity_compaction_jobs", "integrity_compaction_authorizations"):
        bind.execute(sa.text(f"GRANT SELECT ON {table} TO {runtime}, {retention}, {replication}"))
        bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {integrity_compactor}"))
        bind.execute(sa.text(f"REVOKE DELETE ON {table} FROM {runtime}, {retention}, {replication}, PUBLIC"))
    bind.execute(sa.text(f"GRANT INSERT, UPDATE ON public.archive_replica_policy TO {integrity_compactor}"))
    bind.execute(sa.text(f"GRANT SELECT ON public.integrity_records, public.ledger_segments, public.ledger_segment_lifecycle, public.integrity_checkpoints, public.integrity_checkpoint_entries, public.retention_holds, public.archive_replicas, public.archive_replica_policy TO {integrity_compactor}"))
    bind.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {integrity_compactor}"))
    bind.execute(sa.text("""
        CREATE OR REPLACE FUNCTION public.compact_verified_integrity_segment_v1(
            p_segment_id uuid, p_authorization_id uuid, p_expires_at timestamptz
        ) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public AS $fn$
        DECLARE s record; a record; policy record; actual_count integer; valid_replica_count integer; deleted_count integer;
        BEGIN
            SELECT * INTO s FROM public.integrity_archive_segments WHERE id = p_segment_id FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'V19_SEGMENT_NOT_FOUND'; END IF;
            IF s.state NOT IN ('READY_TO_COMPACT','COMPACTING') THEN RAISE EXCEPTION 'V19_SEGMENT_NOT_READY'; END IF;
            SELECT * INTO a FROM public.integrity_compaction_authorizations WHERE id = p_authorization_id AND segment_id = p_segment_id FOR UPDATE;
            IF NOT FOUND THEN RAISE EXCEPTION 'V19_AUTHORIZATION_NOT_FOUND'; END IF;
            IF a.expires_at <= clock_timestamp() OR p_expires_at <= clock_timestamp() THEN RAISE EXCEPTION 'V19_AUTHORIZATION_EXPIRED'; END IF;
            IF a.tenant_id <> s.tenant_id OR a.source_start_sequence <> s.source_start_sequence OR a.source_end_sequence <> s.source_end_sequence
               OR a.record_count <> s.record_count OR a.logical_segment_digest <> s.logical_segment_digest
               OR a.ciphertext_sha256 <> coalesce(s.ciphertext_sha256, '')
               OR a.v17_ledger_segment_digest <> s.v17_ledger_segment_digest
               OR a.v15_checkpoint_digest <> s.v15_checkpoint_digest OR a.v15_continuity_status <> 'MATCH'
               OR a.predecessor_boundary_hash IS DISTINCT FROM s.predecessor_boundary_hash
               OR a.successor_boundary_hash IS DISTINCT FROM s.successor_boundary_hash
            THEN RAISE EXCEPTION 'V19_AUTHORIZATION_BINDING_MISMATCH'; END IF;
            IF EXISTS (SELECT 1 FROM public.retention_holds h WHERE h.tenant_id = s.tenant_id AND h.released_at IS NULL
                       AND (h.subject_type = 'TENANT' OR (h.subject_type = 'TRACE' AND h.trace_id = s.trace_id)))
            THEN RAISE EXCEPTION 'V19_RETENTION_HOLD_ACTIVE'; END IF;
            SELECT * INTO policy FROM public.archive_replica_policy WHERE policy_version = a.replica_policy_version;
            IF NOT FOUND THEN RAISE EXCEPTION 'V19_REPLICA_POLICY_MISSING'; END IF;
            SELECT count(*) INTO valid_replica_count FROM public.archive_replicas r
             WHERE r.tenant_id = s.tenant_id AND r.logical_archive_type = 'INTEGRITY_SEGMENT'
               AND r.logical_archive_id = s.id AND r.state = 'VALID';
            IF valid_replica_count <> a.verified_replica_count OR valid_replica_count < policy.minimum_verified_replicas
            THEN RAISE EXCEPTION 'V19_REPLICA_POLICY_NOT_SATISFIED'; END IF;
            SELECT count(*) INTO actual_count FROM public.integrity_records r
             WHERE r.tenant_id = s.tenant_id AND r.trace_id = s.trace_id
               AND r.sequence BETWEEN s.source_start_sequence AND s.source_end_sequence;
            IF actual_count <> s.record_count THEN RAISE EXCEPTION 'V19_SOURCE_RANGE_CHANGED'; END IF;
            IF (SELECT r.previous_chain_mac FROM public.integrity_records r WHERE r.tenant_id = s.tenant_id AND r.trace_id = s.trace_id AND r.sequence = s.source_start_sequence) IS DISTINCT FROM s.predecessor_boundary_hash
            THEN RAISE EXCEPTION 'V19_PREDECESSOR_BOUNDARY_MISMATCH'; END IF;
            IF (SELECT r.chain_mac FROM public.integrity_records r WHERE r.tenant_id = s.tenant_id AND r.trace_id = s.trace_id AND r.sequence = s.source_end_sequence) IS DISTINCT FROM s.successor_boundary_hash
            THEN RAISE EXCEPTION 'V19_SUCCESSOR_BOUNDARY_MISMATCH'; END IF;
            UPDATE public.integrity_archive_segments SET state = 'COMPACTING', updated_at = clock_timestamp() WHERE id = s.id;
            DELETE FROM public.integrity_records WHERE tenant_id = s.tenant_id AND trace_id = s.trace_id AND sequence BETWEEN s.source_start_sequence AND s.source_end_sequence;
            GET DIAGNOSTICS deleted_count = ROW_COUNT;
            IF deleted_count <> s.record_count THEN RAISE EXCEPTION 'V19_SOURCE_RANGE_CHANGED'; END IF;
            UPDATE public.integrity_archive_segments SET state = 'COMPACTED', compacted_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = s.id;
            RETURN deleted_count;
        END; $fn$;
    """))
    bind.execute(sa.text(f"GRANT EXECUTE ON FUNCTION public.compact_verified_integrity_segment_v1(uuid, uuid, timestamptz) TO {integrity_compactor}"))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("DROP FUNCTION IF EXISTS public.compact_verified_integrity_segment_v1(uuid, uuid, timestamptz)"))
    op.drop_index("ix_integrity_compaction_auth_expiry", table_name="integrity_compaction_authorizations")
    op.drop_table("integrity_compaction_authorizations")
    op.drop_index("ix_integrity_compaction_jobs_claimable", table_name="integrity_compaction_jobs")
    op.drop_table("integrity_compaction_jobs")
    op.drop_index("ix_integrity_segments_candidate", table_name="integrity_archive_segments")
    op.drop_index("ix_integrity_segments_tenant_trace_state", table_name="integrity_archive_segments")
    op.drop_table("integrity_archive_segments")
