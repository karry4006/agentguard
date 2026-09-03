import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from agentguard_server.db.base import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    traces: Mapped[list["Trace"]] = relationship(back_populates="tenant")


class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (Index("ix_api_keys_tenant_id", "tenant_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    public_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    secret_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    scopes: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant: Mapped[Tenant] = relationship(back_populates="api_keys")


class DashboardSession(Base):
    """Opaque, tenant-scoped browser session; only token hashes are persisted."""

    __tablename__ = "dashboard_sessions"
    __table_args__ = (
        UniqueConstraint("session_token_hash", name="uq_dashboard_sessions_token_hash"),
        CheckConstraint(
            "(api_key_id IS NOT NULL AND human_user_id IS NULL) OR "
            "(api_key_id IS NULL AND human_user_id IS NOT NULL)",
            name="ck_dashboard_sessions_one_principal",
        ),
        Index("ix_dashboard_sessions_tenant_active", "tenant_id", "expires_at", "revoked_at"),
        Index("ix_dashboard_sessions_api_key_active", "api_key_id", "expires_at", "revoked_at"),
        Index("ix_dashboard_sessions_human_active", "human_user_id", "expires_at", "revoked_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("api_keys.id", ondelete="CASCADE"))
    human_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("human_users.id", ondelete="CASCADE"))
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    session_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OidcLoginAttempt(Base):
    """Short-lived OIDC state, nonce, and PKCE binding for one callback."""

    __tablename__ = "oidc_login_attempts"
    __table_args__ = (
        UniqueConstraint("state_hash", name="uq_oidc_login_attempts_state_hash"),
        Index("ix_oidc_login_attempts_expiry", "expires_at", "used_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    code_verifier: Mapped[str | None] = mapped_column(String(128))
    return_to: Mapped[str] = mapped_column(String(512), nullable=False, default="/ui")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DistributedRateLimitBucket(Base):
    """Fixed-window rate-limit state shared by every server replica."""

    __tablename__ = "distributed_rate_limit_buckets"
    __table_args__ = (
        Index("ix_rate_limit_buckets_type_window", "bucket_type", "window_start"),
    )

    bucket_key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    bucket_type: Mapped[str] = mapped_column(String(64), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HumanUser(Base):
    """A provisioned human identity keyed by immutable issuer and subject."""

    __tablename__ = "human_users"
    __table_args__ = (
        UniqueConstraint("external_issuer", "external_subject", name="uq_human_users_external_identity"),
        Index("ix_human_users_external_identity", "external_issuer", "external_subject"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    external_issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    external_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_organizations_tenant_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_memberships_org_user"),
        Index("ix_organization_memberships_user_active", "user_id", "disabled_at"),
        CheckConstraint("role IN ('VIEWER','ENGINEER','ADMIN')", name="ck_organization_memberships_role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("human_users.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IdentityAuditEvent(Base):
    """Append-only, secret-free audit record for human identity actions."""

    __tablename__ = "identity_audit_events"
    __table_args__ = (Index("ix_identity_audit_org_created", "organization_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("human_users.id", ondelete="SET NULL"))
    target_membership_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organization_memberships.id", ondelete="SET NULL"))
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Trace(Base):
    __tablename__ = "traces"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", name="uq_traces_tenant_trace_id"),
        Index("ix_traces_tenant_trace", "tenant_id", "trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    workflow_name: Mapped[str | None] = mapped_column(String(255))
    group_id: Mapped[str | None] = mapped_column(String(255))
    provider: Mapped[str | None] = mapped_column(String(100))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON_TYPE, nullable=False, default=dict)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="0.1")
    tenant: Mapped[Tenant] = relationship(back_populates="traces")
    spans: Mapped[list["Span"]] = relationship(back_populates="trace", cascade="all, delete-orphan")


class Span(Base):
    __tablename__ = "spans"
    __table_args__ = (
        UniqueConstraint("tenant_id", "span_id", name="uq_spans_tenant_span_id"),
        Index("ix_spans_tenant_trace", "tenant_id", "trace_id"),
        Index("ix_spans_tenant_parent", "tenant_id", "parent_span_id"),
        ForeignKeyConstraint(
            ["tenant_id", "trace_id"],
            ["traces.tenant_id", "traces.trace_id"],
            ondelete="CASCADE",
            name="fk_spans_tenant_trace",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    span_id: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_span_id: Mapped[str | None] = mapped_column(String(255))
    span_type: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[float | None] = mapped_column()
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    error_type: Mapped[str | None] = mapped_column(String(255))
    error_message: Mapped[str | None] = mapped_column(Text)
    attributes: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="0.1")
    trace: Mapped[Trace] = relationship(back_populates="spans")


class EventLog(Base):
    __tablename__ = "event_log"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_type", "event_id", name="uq_event_log_tenant_event"),
        Index("ix_event_log_tenant_key", "tenant_id", "event_type", "event_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_key: Mapped[str] = mapped_column(String(700), nullable=False)
    trace_id: Mapped[str | None] = mapped_column(String(255))
    payload_json: Mapped[dict | None] = mapped_column(JSON_TYPE)
    event_digest: Mapped[str | None] = mapped_column(String(64))


class IntegrityRecord(Base):
    __tablename__ = "integrity_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", "sequence", name="uq_integrity_trace_sequence"),
        Index("ix_integrity_tenant_trace", "tenant_id", "trace_id"),
        Index("ix_integrity_event", "tenant_id", "event_type", "event_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_chain_mac: Mapped[str | None] = mapped_column(String(64))
    chain_mac: Mapped[str] = mapped_column(String(64), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonicalization_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IntegrityChainHead(Base):
    __tablename__ = "integrity_chain_heads"
    __table_args__ = (UniqueConstraint("tenant_id", "trace_id", name="uq_integrity_chain_head"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    next_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    head_mac: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReplaySession(Base):
    __tablename__ = "replay_sessions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_replay_tenant_idempotency"),
        Index("ix_replay_sessions_tenant_source", "tenant_id", "source_trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="dry_run")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    failure_reason: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    steps: Mapped[list["ReplayStep"]] = relationship(back_populates="session", cascade="all, delete-orphan")


class ReplayStep(Base):
    __tablename__ = "replay_steps"
    __table_args__ = (
        UniqueConstraint("replay_session_id", "sequence", name="uq_replay_step_sequence"),
        Index("ix_replay_steps_session", "replay_session_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    replay_session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("replay_sessions.id", ondelete="CASCADE"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_span_id: Mapped[str | None] = mapped_column(String(255))
    step_type: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(255))
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    recorded_input_digest: Mapped[str | None] = mapped_column(String(64))
    simulated_input_digest: Mapped[str | None] = mapped_column(String(64))
    recorded_output_digest: Mapped[str | None] = mapped_column(String(64))
    simulated_output_digest: Mapped[str | None] = mapped_column(String(64))
    comparison_status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    session: Mapped[ReplaySession] = relationship(back_populates="steps")


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_analysis_tenant_idempotency"),
        Index("ix_analysis_runs_tenant_trace", "tenant_id", "trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    analysis_version: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128))
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deterministic_status: Mapped[str] = mapped_column(String(32), nullable=False)
    ai_status: Mapped[str] = mapped_column(String(32), nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    model_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[float | None] = mapped_column()
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    findings: Mapped[list["AnalysisFinding"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class AnalysisFinding(Base):
    __tablename__ = "analysis_findings"
    __table_args__ = (Index("ix_analysis_findings_run", "analysis_run_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False)
    detector_id: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    root_cause_span_id: Mapped[str | None] = mapped_column(String(255))
    symptom_span_id: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    model_confidence: Mapped[float] = mapped_column(nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_next_step: Mapped[str | None] = mapped_column(String(255))
    evidence_span_ids: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    evidence_event_ids: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    replay_ids: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    primary_hypothesis: Mapped[bool] = mapped_column(nullable=False, default=False)
    run: Mapped[AnalysisRun] = relationship(back_populates="findings")


class EvaluationSuite(Base):
    __tablename__ = "evaluation_suites"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", "version", name="uq_evaluation_suite_tenant_name_version"),
        Index("ix_evaluation_suites_tenant", "tenant_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    configuration: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    runs: Mapped[list["EvaluationRun"]] = relationship(back_populates="suite", cascade="all, delete-orphan")


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_evaluation_run_tenant_idempotency"),
        Index("ix_evaluation_runs_tenant_suite", "tenant_id", "suite_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    suite_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evaluation_suites.id", ondelete="CASCADE"), nullable=False)
    variant: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    environment: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    suite: Mapped[EvaluationSuite] = relationship(back_populates="runs")
    cases: Mapped[list["EvaluationCaseResult"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class EvaluationCaseResult(Base):
    __tablename__ = "evaluation_case_results"
    __table_args__ = (
        UniqueConstraint("tenant_id", "run_id", "case_id", name="uq_evaluation_case_tenant_run_case"),
        Index("ix_evaluation_case_results_tenant_run", "tenant_id", "run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[str] = mapped_column(String(255), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    metrics: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    run: Mapped[EvaluationRun] = relationship(back_populates="cases")


class EvaluationComparison(Base):
    __tablename__ = "evaluation_comparisons"
    __table_args__ = (
        UniqueConstraint("tenant_id", "baseline_run_id", "candidate_run_id", name="uq_evaluation_comparison_pair"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_evaluation_comparison_tenant_idempotency"),
        Index("ix_evaluation_comparisons_tenant_suite", "tenant_id", "suite_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    suite_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evaluation_suites.id", ondelete="CASCADE"), nullable=False)
    baseline_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evaluation_runs.id", ondelete="RESTRICT"), nullable=False)
    candidate_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evaluation_runs.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    metrics: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    reasons: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    case_diffs: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    rule_results: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evaluator_version: Mapped[str] = mapped_column(String(32), nullable=False)
    taxonomy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(255))


class ReleaseGateResult(Base):
    __tablename__ = "release_gate_results"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    comparison_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evaluation_comparisons.id", ondelete="CASCADE"), nullable=False, unique=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Incident(Base):
    """Derived, tenant-scoped incident projection; source evidence is never mutated."""

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "fingerprint", "fingerprint_version", name="uq_incident_tenant_fingerprint_version"),
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_tenant_last_seen", "tenant_id", "last_seen_at"),
        Index("ix_incidents_tenant_severity", "tenant_id", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_version: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    severity_policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="severity-v1")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    affected_trace_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    primary_category: Mapped[str] = mapped_column(String(64), nullable=False)
    dimensions: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    occurrences: Mapped[list["IncidentOccurrence"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    events: Mapped[list["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentOccurrence(Base):
    __tablename__ = "incident_occurrences"
    __table_args__ = (
        UniqueConstraint("tenant_id", "trace_id", "analysis_id", "finding_key", name="uq_incident_occurrence_idempotency"),
        Index("ix_incident_occurrences_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_incident_occurrences_tenant_observed", "tenant_id", "observed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # Deliberately no FK to source analysis: this derived projection must not
    # make source evidence deletable or require runtime ownership of V5 tables.
    analysis_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    finding_key: Mapped[str] = mapped_column(String(128), nullable=False)
    failure_category: Mapped[str] = mapped_column(String(64), nullable=False)
    root_cause_span_id: Mapped[str | None] = mapped_column(String(255))
    symptom_span_id: Mapped[str | None] = mapped_column(String(255))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    agent_name: Mapped[str | None] = mapped_column(String(128))
    workflow_name: Mapped[str | None] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(128))
    provider: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    incident: Mapped[Incident] = relationship(back_populates="occurrences")


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    __table_args__ = (Index("ix_incident_events_tenant_incident", "tenant_id", "incident_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128))
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    incident: Mapped[Incident] = relationship(back_populates="events")


class NotificationDestination(Base):
    __tablename__ = "notification_destinations"
    __table_args__ = (Index("ix_notification_destinations_tenant_enabled", "tenant_id", "enabled"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    destination_type: Mapped[str] = mapped_column("type", String(32), nullable=False, default="HTTPS_WEBHOOK")
    endpoint_scheme: Mapped[str] = mapped_column(String(8), nullable=False, default="https")
    endpoint_host: Mapped[str] = mapped_column(String(255), nullable=False)
    endpoint_port: Mapped[int] = mapped_column(Integer, nullable=False)
    endpoint_path: Mapped[str] = mapped_column(String(1024), nullable=False, default="/")
    signing_secret_reference: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AlertPolicy(Base):
    __tablename__ = "alert_policies"
    __table_args__ = (Index("ix_alert_policies_tenant_enabled", "tenant_id", "enabled"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    minimum_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="HIGH")
    incident_status_filter: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=lambda: ["OPEN"])
    failure_categories: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=list)
    event_types: Mapped[list] = mapped_column(JSON_TYPE, nullable=False, default=lambda: ["INCIDENT_CREATED", "INCIDENT_REOPENED", "SEVERITY_INCREASED", "INCIDENT_RESOLVED"])
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_notification_delivery_idempotency"),
        Index("ix_notification_deliveries_tenant_status", "tenant_id", "status", "next_retry_at"),
        Index("ix_notification_deliveries_tenant_incident", "tenant_id", "incident_id", "created_at"),
        Index("ix_notification_deliveries_claimable", "status", "next_retry_at", "lease_expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    destination_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_destinations.id", ondelete="RESTRICT"), nullable=False)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alert_policies.id", ondelete="RESTRICT"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    failure_category: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    claim_token: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claim_attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class NotificationCircuitState(Base):
    """Durable circuit-breaker state, one row per tenant-owned destination."""

    __tablename__ = "notification_circuit_states"
    __table_args__ = (Index("ix_notification_circuit_states_state_probe", "state", "next_probe_at"),)

    destination_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_destinations.id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="CLOSED")
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_probe_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    half_open_probe_owner: Mapped[str | None] = mapped_column(String(64))
    half_open_lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NotificationEvent(Base):
    __tablename__ = "notification_events"
    __table_args__ = (Index("ix_notification_events_tenant_delivery", "tenant_id", "delivery_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    delivery_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_deliveries.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON_TYPE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
