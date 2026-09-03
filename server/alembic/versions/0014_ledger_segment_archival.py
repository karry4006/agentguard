"""add verifiable ledger segment archival and narrow compaction state"""

from alembic import op
import os
import sqlalchemy as sa


revision = "0014_ledger_segment_archival"
down_revision = "0013_evidence_retention_archival"
branch_labels = None
depends_on = None


def _identifier(value: str) -> str:
    if not value or not value.replace("_", "").isalnum() or not value[0].isalpha():
        raise RuntimeError("invalid runtime role identifier")
    return '"' + value.replace('"', '""') + '"'


def upgrade() -> None:
    op.create_table(
        "ledger_segments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("segment_sequence", sa.Integer(), nullable=False),
        sa.Column("segment_version", sa.String(length=32), nullable=False),
        sa.Column("start_event_sequence", sa.Integer(), nullable=False),
        sa.Column("end_event_sequence", sa.Integer(), nullable=False),
        sa.Column("start_previous_hash", sa.String(length=64)),
        sa.Column("end_event_hash", sa.String(length=64), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("events_manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("segment_manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("archive_plaintext_sha256", sa.String(length=64)),
        sa.Column("archive_ciphertext_sha256", sa.String(length=64)),
        sa.Column("archive_object_key", sa.String(length=512)),
        sa.Column("archive_encryption_key_id", sa.String(length=128)),
        sa.Column("covering_checkpoint_id", sa.Uuid()),
        sa.Column("covering_checkpoint_sequence", sa.Integer()),
        sa.Column("covering_checkpoint_digest", sa.String(length=64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("archived_verified_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["covering_checkpoint_id"], ["integrity_checkpoints.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "trace_id", "segment_sequence", name="uq_ledger_segments_trace_sequence"),
        sa.UniqueConstraint("tenant_id", "trace_id", "start_event_sequence", name="uq_ledger_segments_trace_start"),
        sa.UniqueConstraint("tenant_id", "trace_id", "end_event_sequence", name="uq_ledger_segments_trace_end"),
        sa.CheckConstraint("start_event_sequence <= end_event_sequence", name="ck_ledger_segments_range"),
        sa.CheckConstraint("event_count > 0", name="ck_ledger_segments_event_count"),
    )
    op.create_index("ix_ledger_segments_tenant_trace_status", "ledger_segments", ["tenant_id", "trace_id", "segment_sequence"])
    op.create_table(
        "ledger_segment_lifecycle",
        sa.Column("segment_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_error_category", sa.String(length=64)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["segment_id"], ["ledger_segments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("segment_id"),
        sa.CheckConstraint("status IN ('CANDIDATE','CLOSED','ARCHIVING','ARCHIVED_VERIFIED','COMPACTION_AUTHORIZED','COMPACTED','FAILED')", name="ck_ledger_segment_lifecycle_status"),
    )
    op.create_table(
        "ledger_event_archive_index",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.String(length=255), nullable=False),
        sa.Column("event_id", sa.String(length=255), nullable=False),
        sa.Column("event_sequence", sa.Integer(), nullable=False),
        sa.Column("segment_id", sa.Uuid(), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("original_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["segment_id"], ["ledger_segments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "trace_id", "event_sequence", name="uq_ledger_event_index_trace_sequence"),
        sa.UniqueConstraint("tenant_id", "trace_id", "event_id", name="uq_ledger_event_index_trace_event"),
    )
    op.create_index("ix_ledger_event_index_segment", "ledger_event_archive_index", ["segment_id", "event_sequence"])
    op.create_table(
        "ledger_compaction_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("segment_id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("claimed_by", sa.String(length=128)),
        sa.Column("claim_token", sa.String(length=64)),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_category", sa.String(length=64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["segment_id"], ["ledger_segments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ledger_compaction_jobs_claimable", "ledger_compaction_jobs", ["status", "next_attempt_at", "lease_expires_at"])
    op.create_table(
        "ledger_compaction_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("segment_id", sa.Uuid(), nullable=False),
        sa.Column("segment_manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("archive_ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("covering_checkpoint_digest", sa.String(length=64), nullable=False),
        sa.Column("remote_continuity_status", sa.String(length=32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_by_instance", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["segment_id"], ["ledger_segments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ledger_compaction_auth_expiry", "ledger_compaction_authorizations", ["segment_id", "expires_at"])

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        runtime = _identifier(os.getenv("AGENTGUARD_RUNTIME_USER", "agentguard_runtime"))
        retention = _identifier(os.getenv("AGENTGUARD_RETENTION_USER", "agentguard_retention"))
        compactor_name = os.getenv("AGENTGUARD_LEDGER_COMPACTOR_USER", "agentguard_ledger_compactor")
        compactor = _identifier(compactor_name)
        database_name = _identifier(str(bind.engine.url.database or ""))
        bind.execute(sa.text(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{compactor_name}') THEN CREATE ROLE {compactor} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $$"))
        bind.execute(sa.text(f"REVOKE CREATE, TEMPORARY ON DATABASE {database_name} FROM PUBLIC"))
        bind.execute(sa.text(f"REVOKE CREATE, TEMPORARY ON DATABASE {database_name} FROM {compactor}"))
        bind.execute(sa.text(f"REVOKE CREATE ON SCHEMA public FROM {compactor}"))
        for table in ("ledger_segments", "ledger_segment_lifecycle", "ledger_event_archive_index", "ledger_compaction_jobs", "ledger_compaction_authorizations"):
            bind.execute(sa.text(f"REVOKE ALL ON {table} FROM {runtime}"))
            bind.execute(sa.text(f"GRANT SELECT ON {table} TO {runtime}"))
            bind.execute(sa.text(f"GRANT SELECT ON {table} TO {retention}"))
            bind.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {compactor}"))
        bind.execute(sa.text(f"REVOKE ALL ON event_log FROM {compactor}"))
        bind.execute(sa.text(f"REVOKE ALL ON integrity_records FROM {compactor}"))
        for table in ("event_log", "integrity_records", "integrity_chain_heads", "integrity_checkpoints", "integrity_checkpoint_entries", "external_anchor_receipts", "retention_holds"):
            bind.execute(sa.text(f"GRANT SELECT ON {table} TO {compactor}"))
        bind.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {compactor}"))
        bind.execute(sa.text(f"""
            CREATE OR REPLACE FUNCTION public.compact_verified_ledger_segment_v1(p_segment_id uuid)
            RETURNS integer
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                seg record;
                auth record;
                expected_count integer;
                indexed_count integer;
                deleted_count integer;
            BEGIN
                SELECT s.*, l.status AS lifecycle_status
                  INTO seg
                  FROM public.ledger_segments s
                  JOIN public.ledger_segment_lifecycle l ON l.segment_id = s.id
                 WHERE s.id = p_segment_id
                 FOR UPDATE OF s, l;
                IF NOT FOUND OR seg.lifecycle_status <> 'COMPACTION_AUTHORIZED' THEN
                    RAISE EXCEPTION 'ledger segment is not authorized';
                END IF;
                SELECT * INTO auth FROM public.ledger_compaction_authorizations
                 WHERE segment_id = seg.id ORDER BY created_at DESC LIMIT 1;
                IF NOT FOUND OR auth.expires_at <= clock_timestamp()
                   OR auth.segment_manifest_digest <> seg.segment_manifest_digest
                   OR auth.archive_ciphertext_sha256 <> seg.archive_ciphertext_sha256
                   OR auth.covering_checkpoint_digest <> seg.covering_checkpoint_digest
                   OR auth.remote_continuity_status <> 'MATCH' THEN
                    RAISE EXCEPTION 'ledger compaction authorization is invalid or expired';
                END IF;
                IF EXISTS (SELECT 1 FROM public.retention_holds h
                            WHERE h.tenant_id = seg.tenant_id AND h.released_at IS NULL
                              AND (h.subject_type = 'TENANT' OR (h.subject_type = 'TRACE' AND h.trace_id = seg.trace_id))) THEN
                    RAISE EXCEPTION 'ledger compaction is blocked by an active hold';
                END IF;
                SELECT count(*) INTO expected_count
                  FROM public.event_log e JOIN public.integrity_records r
                    ON r.tenant_id = e.tenant_id AND r.trace_id = e.trace_id
                   AND r.event_type = e.event_type AND r.event_id = e.event_id
                 WHERE e.tenant_id = seg.tenant_id AND e.trace_id = seg.trace_id
                   AND r.sequence BETWEEN seg.start_event_sequence AND seg.end_event_sequence;
                SELECT count(*) INTO indexed_count FROM public.ledger_event_archive_index
                 WHERE segment_id = seg.id;
                IF expected_count <> seg.event_count OR indexed_count <> seg.event_count THEN
                    RAISE EXCEPTION 'ledger segment source range or index is incomplete';
                END IF;
                DELETE FROM public.event_log e USING public.integrity_records r
                 WHERE r.tenant_id = e.tenant_id AND r.trace_id = e.trace_id
                   AND r.event_type = e.event_type AND r.event_id = e.event_id
                   AND e.tenant_id = seg.tenant_id AND e.trace_id = seg.trace_id
                   AND r.sequence BETWEEN seg.start_event_sequence AND seg.end_event_sequence;
                GET DIAGNOSTICS deleted_count = ROW_COUNT;
                IF deleted_count <> seg.event_count THEN
                    RAISE EXCEPTION 'ledger segment delete count changed';
                END IF;
                UPDATE public.ledger_segment_lifecycle SET status = 'COMPACTED', updated_at = clock_timestamp()
                 WHERE segment_id = seg.id;
                RETURN deleted_count;
            END;
            $fn$;
        """))
        bind.execute(sa.text(f"REVOKE ALL ON FUNCTION public.compact_verified_ledger_segment_v1(uuid) FROM PUBLIC"))
        bind.execute(sa.text(f"GRANT EXECUTE ON FUNCTION public.compact_verified_ledger_segment_v1(uuid) TO {compactor}"))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("DROP FUNCTION IF EXISTS public.compact_verified_ledger_segment_v1(uuid)"))
    op.drop_index("ix_ledger_compaction_auth_expiry", table_name="ledger_compaction_authorizations")
    op.drop_table("ledger_compaction_authorizations")
    op.drop_index("ix_ledger_compaction_jobs_claimable", table_name="ledger_compaction_jobs")
    op.drop_table("ledger_compaction_jobs")
    op.drop_index("ix_ledger_event_index_segment", table_name="ledger_event_archive_index")
    op.drop_table("ledger_event_archive_index")
    op.drop_table("ledger_segment_lifecycle")
    op.drop_index("ix_ledger_segments_tenant_trace_status", table_name="ledger_segments")
    op.drop_table("ledger_segments")
