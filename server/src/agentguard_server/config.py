from functools import lru_cache
import secrets
import os
import json
from pathlib import Path
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _trusted_oidc_url(value: str, environment: str, test_http_hosts: set[str]):
    parsed = urlparse(value)
    common = bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    return common and (parsed.scheme == "https" or (
        environment == "test" and parsed.scheme == "http" and parsed.hostname in test_http_hosts
    ))


class Settings(BaseSettings):
    database_url: str = Field(default="sqlite:///./agentguard.db", validation_alias=AliasChoices("DATABASE_URL", "AGENTGUARD_DATABASE_URL", "AGENTGUARD_MIGRATION_DATABASE_URL"))
    environment: str = Field(default="development", validation_alias="AGENTGUARD_ENVIRONMENT")
    capture_content: bool = Field(default=False, validation_alias="AGENTGUARD_CAPTURE_CONTENT")
    key_pepper: str | None = Field(default=None, validation_alias="AGENTGUARD_KEY_PEPPER")
    integrity_key: str | None = Field(default=None, validation_alias="AGENTGUARD_INTEGRITY_KEY")
    integrity_key_id: str = Field(default="v1", validation_alias="AGENTGUARD_INTEGRITY_KEY_ID")
    integrity_verify_keys: str | None = Field(default=None, validation_alias="AGENTGUARD_INTEGRITY_VERIFY_KEYS")
    auth_enabled: bool = Field(default=True, validation_alias="AGENTGUARD_AUTH_ENABLED")
    request_max_bytes: int = Field(default=1024 * 1024, gt=0, le=64 * 1024 * 1024, validation_alias="AGENTGUARD_REQUEST_MAX_BYTES")
    ingest_rate_limit: int = Field(default=120, gt=0, le=100000, validation_alias="AGENTGUARD_INGEST_RATE_LIMIT")
    read_rate_limit: int = Field(default=300, gt=0, le=100000, validation_alias="AGENTGUARD_READ_RATE_LIMIT")
    rate_limit_window_seconds: float = Field(default=60.0, gt=0, le=3600, validation_alias="AGENTGUARD_RATE_LIMIT_WINDOW_SECONDS")
    db_pool_size: int = Field(default=5, gt=0, le=100, validation_alias="AGENTGUARD_DB_POOL_SIZE")
    db_max_overflow: int = Field(default=10, ge=0, le=100, validation_alias="AGENTGUARD_DB_MAX_OVERFLOW")
    db_pool_timeout_seconds: float = Field(default=10.0, gt=0, le=300, validation_alias="AGENTGUARD_DB_POOL_TIMEOUT_SECONDS")
    db_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=300, validation_alias="AGENTGUARD_DB_CONNECT_TIMEOUT_SECONDS")
    db_statement_timeout_ms: int = Field(default=30000, gt=0, le=600000, validation_alias="AGENTGUARD_DB_STATEMENT_TIMEOUT_MS")
    instance_id: str = Field(default_factory=lambda: secrets.token_hex(16), min_length=1, max_length=128, validation_alias="AGENTGUARD_INSTANCE_ID")
    anchor_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_ANCHOR_ENABLED")
    anchor_endpoint: str | None = Field(default=None, validation_alias="AGENTGUARD_ANCHOR_ENDPOINT")
    anchor_namespace: str = Field(default="agentguard-development", min_length=1, max_length=128, validation_alias="AGENTGUARD_ANCHOR_NAMESPACE")
    anchor_verify_keys: str | None = Field(default=None, validation_alias="AGENTGUARD_ANCHOR_VERIFY_KEYS")
    anchor_verify_keys_file: str | None = Field(default=None, validation_alias="AGENTGUARD_ANCHOR_VERIFY_KEYS_FILE")
    anchor_interval_seconds: int = Field(default=300, gt=0, le=86400, validation_alias="AGENTGUARD_ANCHOR_INTERVAL_SECONDS")
    anchor_max_age_seconds: int = Field(default=900, gt=0, le=604800, validation_alias="AGENTGUARD_ANCHOR_MAX_AGE_SECONDS")
    anchor_request_timeout_seconds: float = Field(default=5.0, gt=0, le=120, validation_alias="AGENTGUARD_ANCHOR_REQUEST_TIMEOUT_SECONDS")
    anchor_lease_seconds: int = Field(default=30, ge=5, le=3600, validation_alias="AGENTGUARD_ANCHOR_LEASE_SECONDS")
    anchor_retry_base_seconds: int = Field(default=1, ge=1, le=3600, validation_alias="AGENTGUARD_ANCHOR_RETRY_BASE_SECONDS")
    anchor_retry_max_seconds: int = Field(default=60, ge=1, le=86400, validation_alias="AGENTGUARD_ANCHOR_RETRY_MAX_SECONDS")
    anchor_retry_max_attempts: int = Field(default=5, ge=1, le=100, validation_alias="AGENTGUARD_ANCHOR_RETRY_MAX_ATTEMPTS")
    anchor_max_entries: int = Field(default=10000, ge=1, le=1000000, validation_alias="AGENTGUARD_ANCHOR_MAX_ENTRIES")
    anchor_max_pending_jobs: int = Field(default=1, ge=1, le=100, validation_alias="AGENTGUARD_ANCHOR_MAX_PENDING_JOBS")
    quorum_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_QUORUM_ENABLED")
    quorum_witness_registry: str | None = Field(default=None, validation_alias=AliasChoices("AGENTGUARD_QUORUM_WITNESS_REGISTRY", "AGENTGUARD_WITNESS_REGISTRY"))
    quorum_threshold: int = Field(default=1, ge=1, le=32, validation_alias="AGENTGUARD_QUORUM_THRESHOLD")
    quorum_policy_epoch: int = Field(default=1, ge=1, validation_alias="AGENTGUARD_QUORUM_POLICY_EPOCH")
    quorum_policy_version: str = Field(default="witness-quorum-policy-v1", min_length=1, max_length=64, validation_alias="AGENTGUARD_QUORUM_POLICY_VERSION")
    quorum_receipt_freshness_seconds: int = Field(default=900, ge=1, le=604800, validation_alias="AGENTGUARD_QUORUM_RECEIPT_FRESHNESS_SECONDS")
    quorum_freshness_seconds: int = Field(default=300, ge=1, le=604800, validation_alias="AGENTGUARD_QUORUM_FRESHNESS_SECONDS")
    quorum_strict_conflict_blocking: bool = Field(default=True, validation_alias="AGENTGUARD_QUORUM_STRICT_CONFLICT_BLOCKING")
    archive_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_ARCHIVE_ENABLED")
    retention_purge_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_RETENTION_PURGE_ENABLED")
    archive_after_days: int = Field(default=30, ge=0, le=36500, validation_alias="AGENTGUARD_ARCHIVE_AFTER_DAYS")
    purge_after_days: int = Field(default=90, ge=0, le=36500, validation_alias="AGENTGUARD_PURGE_AFTER_DAYS")
    retention_finalization_grace_days: int = Field(default=7, ge=0, le=36500, validation_alias="AGENTGUARD_RETENTION_FINALIZATION_GRACE_DAYS")
    archive_batch_size: int = Field(default=100, ge=1, le=10000, validation_alias="AGENTGUARD_ARCHIVE_BATCH_SIZE")
    archive_max_plaintext_bytes: int = Field(default=64 * 1024 * 1024, ge=1024, le=1024 * 1024 * 1024, validation_alias="AGENTGUARD_ARCHIVE_MAX_PLAINTEXT_BYTES")
    archive_max_object_bytes: int = Field(default=96 * 1024 * 1024, ge=1024, le=1024 * 1024 * 1024, validation_alias="AGENTGUARD_ARCHIVE_MAX_OBJECT_BYTES")
    archive_max_decompressed_bytes: int = Field(default=64 * 1024 * 1024, ge=1024, le=1024 * 1024 * 1024, validation_alias="AGENTGUARD_ARCHIVE_MAX_DECOMPRESSED_BYTES")
    archive_interval_seconds: int = Field(default=300, gt=0, le=86400, validation_alias="AGENTGUARD_ARCHIVE_INTERVAL_SECONDS")
    archive_lease_seconds: int = Field(default=60, ge=5, le=3600, validation_alias="AGENTGUARD_ARCHIVE_LEASE_SECONDS")
    archive_request_timeout_seconds: float = Field(default=10.0, gt=0, le=300, validation_alias="AGENTGUARD_ARCHIVE_REQUEST_TIMEOUT_SECONDS")
    archive_store_endpoint: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_ENDPOINT")
    archive_store_bucket: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_BUCKET")
    archive_store_region: str = Field(default="us-east-1", min_length=1, max_length=64, validation_alias="AGENTGUARD_ARCHIVE_STORE_REGION")
    archive_store_access_key: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_ACCESS_KEY")
    archive_store_secret_key: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_SECRET_KEY")
    archive_store_session_token: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_SESSION_TOKEN")
    archive_store_access_key_file: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_ACCESS_KEY_FILE")
    archive_store_secret_key_file: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_SECRET_KEY_FILE")
    archive_store_session_token_file: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_SESSION_TOKEN_FILE")
    archive_encryption_keys: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS")
    archive_encryption_keys_file: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS_FILE")
    archive_encryption_key_id: str = Field(default="archive-key-v1", min_length=1, max_length=128, validation_alias="AGENTGUARD_ARCHIVE_ENCRYPTION_KEY_ID")
    allow_private_archive_tests: bool = Field(default=False, validation_alias="AGENTGUARD_ALLOW_PRIVATE_ARCHIVE_TESTS")
    allow_private_anchor_tests: bool = Field(default=False, validation_alias="AGENTGUARD_ALLOW_PRIVATE_ANCHOR_TESTS")
    ledger_archive_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_LEDGER_ARCHIVE_ENABLED")
    ledger_compaction_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_LEDGER_COMPACTION_ENABLED")
    ledger_segment_min_age_days: int = Field(default=30, ge=0, le=36500, validation_alias="AGENTGUARD_LEDGER_SEGMENT_MIN_AGE_DAYS")
    ledger_hot_tail_events: int = Field(default=10, ge=1, le=1000000, validation_alias="AGENTGUARD_LEDGER_HOT_TAIL_EVENTS")
    ledger_segment_max_events: int = Field(default=10000, ge=1, le=1000000, validation_alias="AGENTGUARD_LEDGER_SEGMENT_MAX_EVENTS")
    ledger_compaction_authorization_ttl_seconds: int = Field(default=60, ge=5, le=3600, validation_alias="AGENTGUARD_LEDGER_COMPACTION_AUTHORIZATION_TTL_SECONDS")
    ledger_compaction_retry_base_seconds: int = Field(default=5, ge=1, le=3600, validation_alias="AGENTGUARD_LEDGER_COMPACTION_RETRY_BASE_SECONDS")
    ledger_compaction_retry_max_seconds: int = Field(default=3600, ge=1, le=86400, validation_alias="AGENTGUARD_LEDGER_COMPACTION_RETRY_MAX_SECONDS")
    ledger_compaction_retry_max_attempts: int = Field(default=10, ge=1, le=100, validation_alias="AGENTGUARD_LEDGER_COMPACTION_RETRY_MAX_ATTEMPTS")
    ledger_compaction_poll_interval_seconds: float = Field(default=5.0, gt=0, le=300, validation_alias="AGENTGUARD_LEDGER_COMPACTION_POLL_INTERVAL_SECONDS")
    integrity_segment_compaction_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_INTEGRITY_SEGMENT_COMPACTION_ENABLED")
    integrity_segment_min_age_days: int = Field(default=30, ge=0, le=36500, validation_alias="AGENTGUARD_INTEGRITY_SEGMENT_MIN_AGE_DAYS")
    integrity_hot_tail_records: int = Field(default=10, ge=1, le=1000000, validation_alias="AGENTGUARD_INTEGRITY_HOT_TAIL_RECORDS")
    integrity_segment_max_records: int = Field(default=10000, ge=1, le=1000000, validation_alias="AGENTGUARD_INTEGRITY_SEGMENT_MAX_RECORDS")
    integrity_compaction_authorization_ttl_seconds: int = Field(default=60, ge=5, le=3600, validation_alias="AGENTGUARD_INTEGRITY_COMPACTION_AUTHORIZATION_TTL_SECONDS")
    integrity_compaction_retry_base_seconds: int = Field(default=5, ge=1, le=3600, validation_alias="AGENTGUARD_INTEGRITY_COMPACTION_RETRY_BASE_SECONDS")
    integrity_compaction_retry_max_seconds: int = Field(default=3600, ge=1, le=86400, validation_alias="AGENTGUARD_INTEGRITY_COMPACTION_RETRY_MAX_SECONDS")
    integrity_compaction_retry_max_attempts: int = Field(default=10, ge=1, le=100, validation_alias="AGENTGUARD_INTEGRITY_COMPACTION_RETRY_MAX_ATTEMPTS")
    integrity_compaction_poll_interval_seconds: float = Field(default=5.0, gt=0, le=300, validation_alias="AGENTGUARD_INTEGRITY_COMPACTION_POLL_INTERVAL_SECONDS")
    integrity_compactor_role: str = Field(default="agentguard_integrity_compactor", min_length=1, max_length=128, validation_alias="AGENTGUARD_INTEGRITY_COMPACTOR_ROLE")
    # V18 is deliberately opt-in.  A V17 installation therefore keeps the
    # original single-store compaction behaviour until this gate is enabled.
    archive_replication_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_ARCHIVE_REPLICATION_ENABLED")
    archive_replica_policy_version: str = Field(default="archive-replica-policy-v1", min_length=1, max_length=64, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_POLICY_VERSION")
    archive_minimum_verified_replicas: int = Field(default=1, ge=1, le=32, validation_alias="AGENTGUARD_ARCHIVE_MINIMUM_VERIFIED_REPLICAS")
    archive_replica_verification_max_age_seconds: int = Field(default=86400, ge=1, le=31536000, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_VERIFICATION_MAX_AGE_SECONDS")
    archive_replica_scrubbing_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_SCRUBBING_ENABLED")
    archive_replica_scrub_interval_seconds: int = Field(default=86400, ge=1, le=31536000, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_SCRUB_INTERVAL_SECONDS")
    archive_replica_repair_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_REPAIR_ENABLED")
    archive_replica_max_attempts: int = Field(default=10, ge=1, le=100, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_MAX_ATTEMPTS")
    archive_replica_lease_seconds: int = Field(default=60, ge=5, le=3600, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_LEASE_SECONDS")
    archive_replica_retry_base_seconds: int = Field(default=5, ge=1, le=3600, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_RETRY_BASE_SECONDS")
    archive_replica_retry_max_seconds: int = Field(default=3600, ge=1, le=86400, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_RETRY_MAX_SECONDS")
    archive_replica_poll_interval_seconds: float = Field(default=5.0, gt=0, le=300, validation_alias="AGENTGUARD_ARCHIVE_REPLICA_POLL_INTERVAL_SECONDS")
    archive_primary_store_id: str = Field(default="primary", min_length=1, max_length=128, validation_alias="AGENTGUARD_ARCHIVE_PRIMARY_STORE_ID")
    # JSON contains only non-secret registry metadata and environment-variable
    # names for credentials.  Credential values remain outside PostgreSQL,
    # source control, and the image.
    archive_store_registry: str | None = Field(default=None, validation_alias="AGENTGUARD_ARCHIVE_STORE_REGISTRY")
    ledger_compaction_replica_policy_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_LEDGER_COMPACTION_REPLICA_POLICY_ENABLED")
    shutdown_timeout_seconds: float = Field(default=10.0, gt=0, le=120, validation_alias="AGENTGUARD_SHUTDOWN_TIMEOUT_SECONDS")
    replay_max_steps: int = Field(default=1000, validation_alias="AGENTGUARD_REPLAY_MAX_STEPS")
    replay_max_input_bytes: int = Field(default=64 * 1024, validation_alias="AGENTGUARD_REPLAY_MAX_INPUT_BYTES")
    replay_max_duration_seconds: float = Field(default=5.0, validation_alias="AGENTGUARD_REPLAY_MAX_DURATION_SECONDS")
    replay_max_concurrent: int = Field(default=4, validation_alias="AGENTGUARD_REPLAY_MAX_CONCURRENT")
    replay_rate_limit: int = Field(default=30, validation_alias="AGENTGUARD_REPLAY_RATE_LIMIT")
    analysis_enabled: bool = Field(default=True, validation_alias="AGENTGUARD_ANALYSIS_ENABLED")
    analysis_model: str = Field(default="disabled-by-default-judge", validation_alias="AGENTGUARD_ANALYSIS_MODEL")
    analysis_max_spans: int = Field(default=200, validation_alias="AGENTGUARD_ANALYSIS_MAX_SPANS")
    analysis_max_events: int = Field(default=500, validation_alias="AGENTGUARD_ANALYSIS_MAX_EVENTS")
    analysis_max_input_bytes: int = Field(default=64 * 1024, validation_alias="AGENTGUARD_ANALYSIS_MAX_INPUT_BYTES")
    analysis_timeout_seconds: float = Field(default=5.0, validation_alias="AGENTGUARD_ANALYSIS_TIMEOUT_SECONDS")
    analysis_max_model_calls: int = Field(default=1, validation_alias="AGENTGUARD_ANALYSIS_MAX_MODEL_CALLS")
    analysis_max_output_bytes: int = Field(default=16 * 1024, validation_alias="AGENTGUARD_ANALYSIS_MAX_OUTPUT_BYTES")
    analysis_max_concurrent: int = Field(default=2, validation_alias="AGENTGUARD_ANALYSIS_MAX_CONCURRENT")
    analysis_rate_limit: int = Field(default=10, validation_alias="AGENTGUARD_ANALYSIS_RATE_LIMIT")
    allow_private_webhook_tests: bool = Field(default=False, validation_alias="AGENTGUARD_ALLOW_PRIVATE_WEBHOOK_TESTS")
    notification_signing_secret: str | None = Field(default=None, validation_alias="AGENTGUARD_NOTIFICATION_SIGNING_SECRET")
    notification_allowed_webhook_hosts: str | None = Field(default=None, validation_alias="AGENTGUARD_NOTIFICATION_ALLOWED_WEBHOOK_HOSTS")
    notification_tenant_rate_limit: int = Field(default=60, gt=0, le=10000, validation_alias="AGENTGUARD_NOTIFICATION_TENANT_RATE_LIMIT")
    notification_max_destinations: int = Field(default=50, gt=0, le=1000, validation_alias="AGENTGUARD_NOTIFICATION_MAX_DESTINATIONS")
    notification_max_policies: int = Field(default=100, gt=0, le=1000, validation_alias="AGENTGUARD_NOTIFICATION_MAX_POLICIES")
    notification_max_pending: int = Field(default=1000, gt=0, le=100000, validation_alias="AGENTGUARD_NOTIFICATION_MAX_PENDING")
    notification_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=30, validation_alias="AGENTGUARD_NOTIFICATION_CONNECT_TIMEOUT_SECONDS")
    notification_read_timeout_seconds: float = Field(default=5.0, gt=0, le=60, validation_alias="AGENTGUARD_NOTIFICATION_READ_TIMEOUT_SECONDS")
    notification_total_timeout_seconds: float = Field(default=10.0, gt=0, le=120, validation_alias="AGENTGUARD_NOTIFICATION_TOTAL_TIMEOUT_SECONDS")
    notification_retry_max_attempts: int = Field(default=3, ge=1, le=10, validation_alias="AGENTGUARD_NOTIFICATION_RETRY_MAX_ATTEMPTS")
    notification_retry_base_seconds: int = Field(default=5, ge=1, le=3600, validation_alias="AGENTGUARD_NOTIFICATION_RETRY_BASE_SECONDS")
    notification_retry_max_delay_seconds: int = Field(default=300, ge=1, le=86400, validation_alias="AGENTGUARD_NOTIFICATION_RETRY_MAX_DELAY_SECONDS")
    notification_circuit_failure_threshold: int = Field(default=5, ge=1, le=100, validation_alias="AGENTGUARD_NOTIFICATION_CIRCUIT_FAILURE_THRESHOLD")
    notification_circuit_open_seconds: int = Field(default=60, ge=1, le=86400, validation_alias="AGENTGUARD_NOTIFICATION_CIRCUIT_OPEN_SECONDS")
    notification_circuit_probe_lease_seconds: int = Field(default=30, ge=1, le=3600, validation_alias="AGENTGUARD_NOTIFICATION_CIRCUIT_PROBE_LEASE_SECONDS")
    notification_lease_seconds: int = Field(default=30, ge=5, le=3600, validation_alias="AGENTGUARD_NOTIFICATION_LEASE_SECONDS")
    dashboard_session_lifetime_seconds: int = Field(default=28800, ge=300, le=86400, validation_alias="AGENTGUARD_DASHBOARD_SESSION_LIFETIME_SECONDS")
    dashboard_idle_timeout_seconds: int = Field(default=3600, ge=0, le=86400, validation_alias="AGENTGUARD_DASHBOARD_IDLE_TIMEOUT_SECONDS")
    dashboard_max_sessions_per_api_key: int = Field(default=5, ge=1, le=100, validation_alias="AGENTGUARD_DASHBOARD_MAX_SESSIONS_PER_API_KEY")
    dashboard_max_sessions_per_human: int = Field(default=5, ge=1, le=100, validation_alias="AGENTGUARD_DASHBOARD_MAX_SESSIONS_PER_HUMAN")
    dashboard_login_rate_limit: int = Field(default=10, ge=1, le=1000, validation_alias="AGENTGUARD_DASHBOARD_LOGIN_RATE_LIMIT")
    dashboard_login_rate_window_seconds: float = Field(default=60.0, gt=0, le=3600, validation_alias="AGENTGUARD_DASHBOARD_LOGIN_RATE_WINDOW_SECONDS")
    dashboard_api_key_login_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_DASHBOARD_API_KEY_LOGIN_ENABLED")
    oidc_enabled: bool = Field(default=False, validation_alias="AGENTGUARD_OIDC_ENABLED")
    oidc_issuer: str | None = Field(default=None, validation_alias="AGENTGUARD_OIDC_ISSUER")
    oidc_client_id: str | None = Field(default=None, validation_alias="AGENTGUARD_OIDC_CLIENT_ID")
    oidc_client_secret: str | None = Field(default=None, validation_alias="AGENTGUARD_OIDC_CLIENT_SECRET")
    oidc_redirect_uri: str | None = Field(default=None, validation_alias="AGENTGUARD_OIDC_REDIRECT_URI")
    oidc_allowed_audiences: str | None = Field(default=None, validation_alias="AGENTGUARD_OIDC_ALLOWED_AUDIENCES")
    oidc_allowed_algorithms: str = Field(default="RS256", validation_alias="AGENTGUARD_OIDC_ALLOWED_ALGORITHMS")
    oidc_required_claims: str = Field(default="sub", validation_alias="AGENTGUARD_OIDC_REQUIRED_CLAIMS")
    oidc_login_attempt_lifetime_seconds: int = Field(default=300, ge=60, le=900, validation_alias="AGENTGUARD_OIDC_LOGIN_ATTEMPT_LIFETIME_SECONDS")
    oidc_http_timeout_seconds: float = Field(default=5.0, gt=0, le=30, validation_alias="AGENTGUARD_OIDC_HTTP_TIMEOUT_SECONDS")
    oidc_response_max_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024, validation_alias="AGENTGUARD_OIDC_RESPONSE_MAX_BYTES")
    oidc_jwks_cache_seconds: int = Field(default=300, ge=30, le=86400, validation_alias="AGENTGUARD_OIDC_JWKS_CACHE_SECONDS")
    oidc_jwks_max_keys: int = Field(default=10, ge=1, le=100, validation_alias="AGENTGUARD_OIDC_JWKS_MAX_KEYS")
    evaluation_max_cases: int = Field(default=1000, validation_alias="AGENTGUARD_EVALUATION_MAX_CASES")
    evaluation_max_rules: int = Field(default=64, validation_alias="AGENTGUARD_EVALUATION_MAX_RULES")
    evaluation_rate_limit: int = Field(default=30, validation_alias="AGENTGUARD_EVALUATION_RATE_LIMIT")
    otlp_max_compressed_bytes: int = Field(default=1024 * 1024, validation_alias="AGENTGUARD_OTLP_MAX_COMPRESSED_BYTES")
    otlp_max_decompressed_bytes: int = Field(default=4 * 1024 * 1024, validation_alias="AGENTGUARD_OTLP_MAX_DECOMPRESSED_BYTES")
    otlp_max_resource_spans: int = Field(default=100, validation_alias="AGENTGUARD_OTLP_MAX_RESOURCE_SPANS")
    otlp_max_scope_spans: int = Field(default=1000, validation_alias="AGENTGUARD_OTLP_MAX_SCOPE_SPANS")
    otlp_max_spans: int = Field(default=1000, validation_alias="AGENTGUARD_OTLP_MAX_SPANS")
    otlp_max_attributes: int = Field(default=64, validation_alias="AGENTGUARD_OTLP_MAX_ATTRIBUTES")
    otlp_max_events: int = Field(default=128, validation_alias="AGENTGUARD_OTLP_MAX_EVENTS")
    otlp_max_links: int = Field(default=128, validation_alias="AGENTGUARD_OTLP_MAX_LINKS")
    otlp_max_attribute_key_length: int = Field(default=128, validation_alias="AGENTGUARD_OTLP_MAX_ATTRIBUTE_KEY_LENGTH")
    otlp_max_attribute_value_length: int = Field(default=2048, validation_alias="AGENTGUARD_OTLP_MAX_ATTRIBUTE_VALUE_LENGTH")
    otlp_max_metadata_bytes: int = Field(default=16 * 1024, validation_alias="AGENTGUARD_OTLP_MAX_METADATA_BYTES")
    otlp_max_anyvalue_depth: int = Field(default=8, validation_alias="AGENTGUARD_OTLP_MAX_ANYVALUE_DEPTH")
    otlp_max_anyvalue_items: int = Field(default=128, validation_alias="AGENTGUARD_OTLP_MAX_ANYVALUE_ITEMS")
    model_config = SettingsConfigDict(env_prefix="AGENTGUARD_", env_file=".env", extra="ignore", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def load_secret_files(cls, values):
        data = dict(values or {})
        specifications = (
            ("key_pepper", ("AGENTGUARD_KEY_PEPPER",), ("AGENTGUARD_KEY_PEPPER_FILE",)),
            ("integrity_key", ("AGENTGUARD_INTEGRITY_KEY",), ("AGENTGUARD_INTEGRITY_KEY_FILE",)),
            ("database_url", ("DATABASE_URL", "AGENTGUARD_DATABASE_URL", "AGENTGUARD_MIGRATION_DATABASE_URL"),
             ("DATABASE_URL_FILE", "AGENTGUARD_DATABASE_URL_FILE", "AGENTGUARD_MIGRATION_DATABASE_URL_FILE")),
            ("notification_signing_secret", ("AGENTGUARD_NOTIFICATION_SIGNING_SECRET",), ("AGENTGUARD_NOTIFICATION_SIGNING_SECRET_FILE",)),
            ("oidc_client_secret", ("AGENTGUARD_OIDC_CLIENT_SECRET",), ("AGENTGUARD_OIDC_CLIENT_SECRET_FILE",)),
            ("archive_encryption_keys", ("AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS",), ("AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS_FILE",)),
            ("archive_store_access_key", ("AGENTGUARD_ARCHIVE_STORE_ACCESS_KEY",), ("AGENTGUARD_ARCHIVE_STORE_ACCESS_KEY_FILE",)),
            ("archive_store_secret_key", ("AGENTGUARD_ARCHIVE_STORE_SECRET_KEY",), ("AGENTGUARD_ARCHIVE_STORE_SECRET_KEY_FILE",)),
            ("archive_store_session_token", ("AGENTGUARD_ARCHIVE_STORE_SESSION_TOKEN",), ("AGENTGUARD_ARCHIVE_STORE_SESSION_TOKEN_FILE",)),
        )
        for field_name, direct_names, file_names in specifications:
            direct = any(os.getenv(name) not in (None, "") for name in direct_names)
            direct = direct or any(data.get(name) not in (None, "") for name in direct_names)
            direct = direct or data.get(field_name) not in (None, "")
            file_path = next((os.getenv(name) for name in file_names if os.getenv(name) is not None), None)
            if direct and file_path:
                raise ValueError("direct secret and *_FILE configuration cannot both be set")
            if not file_path:
                continue
            try:
                value = Path(file_path).read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ValueError("configured secret file is unavailable") from exc
            if not value or "\n" in value or "\r" in value or len(value) > 1024 * 1024:
                raise ValueError("configured secret file is empty, multiline, or too large")
            data[direct_names[0]] = value
        return data


@lru_cache
def get_settings() -> Settings:
    return Settings()


def validate_configuration(settings: Settings | None = None) -> Settings:
    """Validate startup-critical settings without returning secret values."""

    effective = settings or get_settings()
    environment = effective.environment.strip().lower()
    if environment not in {"development", "test", "staging", "production"}:
        raise ValueError("AGENTGUARD_ENVIRONMENT must be development, test, staging, or production")
    if effective.auth_enabled:
        pepper = (effective.key_pepper or "").strip().lower()
        if not pepper or pepper.startswith(("change-me", "replace-", "generate-", "<")) or pepper in {"insecure", "development"}:
            raise ValueError("AGENTGUARD_KEY_PEPPER is missing or a placeholder")
    integrity_key = (effective.integrity_key or "").strip()
    if len(integrity_key.encode("utf-8")) < 32 or "\n" in integrity_key or "\r" in integrity_key:
        raise ValueError("AGENTGUARD_INTEGRITY_KEY is missing or invalid")
    parsed = urlparse(effective.database_url)
    if parsed.scheme not in {"sqlite", "postgresql", "postgresql+psycopg"}:
        raise ValueError("DATABASE_URL must use sqlite or PostgreSQL")
    if parsed.scheme != "sqlite" and not parsed.hostname:
        raise ValueError("DATABASE_URL must include a database host")
    if environment == "production" and parsed.scheme == "sqlite":
        raise ValueError("production requires PostgreSQL")
    if effective.allow_private_anchor_tests and environment != "test":
        raise ValueError("private anchor test override is allowed only in test environment")
    # V20 keeps the checkpoint scheduler enabled but replaces the single V15
    # endpoint/key pair with its policy-bound witness registry.
    if effective.anchor_enabled and not effective.quorum_enabled:
        if not effective.anchor_endpoint or not effective.anchor_verify_keys_file and not effective.anchor_verify_keys:
            raise ValueError("enabled anchoring requires endpoint, namespace, and trusted public keys")
        parsed_anchor = urlparse(effective.anchor_endpoint)
        if parsed_anchor.scheme != "https" and not (environment == "test" and effective.allow_private_anchor_tests and parsed_anchor.scheme == "http"):
            raise ValueError("anchor endpoint must use HTTPS")
        if not parsed_anchor.hostname or parsed_anchor.username or parsed_anchor.password or parsed_anchor.query or parsed_anchor.fragment:
            raise ValueError("anchor endpoint is invalid")
        if effective.anchor_verify_keys:
            try:
                configured_anchor_keys = json.loads(effective.anchor_verify_keys)
            except json.JSONDecodeError as exc:
                raise ValueError("anchor verification keys are invalid") from exc
            if not isinstance(configured_anchor_keys, dict) or not configured_anchor_keys:
                raise ValueError("anchor verification keys are invalid")
        if effective.anchor_verify_keys_file:
            try:
                if not Path(effective.anchor_verify_keys_file).is_file():
                    raise ValueError("anchor verification key file is unavailable")
            except OSError as exc:
                raise ValueError("anchor verification key file is unavailable") from exc
    if effective.quorum_enabled:
        if not effective.quorum_witness_registry:
            raise ValueError("enabled quorum requires a trusted witness registry")
        try:
            registry = json.loads(effective.quorum_witness_registry)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("witness registry is invalid") from exc
        if not isinstance(registry, list) or not registry or len(registry) > 32:
            raise ValueError("witness registry is invalid")
        if effective.quorum_threshold > len(registry):
            raise ValueError("quorum threshold exceeds configured witnesses")
        seen: set[str] = set()
        for witness in registry:
            if not isinstance(witness, dict):
                raise ValueError("witness registry is invalid")
            if any(name in witness for name in ("private_key", "signing_key", "secret", "auth_token", "credential")):
                raise ValueError("witness registry must not contain private key or credential material")
            witness_id = witness.get("witness_id")
            if not isinstance(witness_id, str) or witness_id.strip().lower() in seen:
                raise ValueError("witness registry contains duplicate witness IDs")
            seen.add(witness_id.strip().lower())
            if not isinstance(witness.get("verification_key_id"), str) or not isinstance(witness.get("verification_public_key"), str):
                raise ValueError("witness registry requires pinned public verification keys")
            if not isinstance(witness.get("endpoint_config_ref"), str) or not witness["endpoint_config_ref"]:
                raise ValueError("witness registry requires trusted endpoint references")
    if effective.allow_private_webhook_tests and environment != "test":
        raise ValueError("private webhook test override is allowed only in test environment")
    if effective.notification_signing_secret and len(effective.notification_signing_secret.encode("utf-8")) < 32:
        raise ValueError("notification signing secret is too short")
    if effective.oidc_enabled:
        if not effective.oidc_issuer or not effective.oidc_client_id or not effective.oidc_redirect_uri:
            raise ValueError("OIDC issuer, client_id, and redirect URI are required")
        if not _trusted_oidc_url(effective.oidc_issuer, environment,
                                 {"localhost", "127.0.0.1", "host.docker.internal"}):
            raise ValueError("OIDC issuer must be a trusted HTTPS URL")
        if not _trusted_oidc_url(effective.oidc_redirect_uri, environment, {"localhost", "127.0.0.1"}):
            raise ValueError("OIDC redirect URI must be a trusted HTTPS URL")
        algorithms = {item.strip() for item in effective.oidc_allowed_algorithms.split(",") if item.strip()}
        if not algorithms or not algorithms <= {"RS256"}:
            raise ValueError("OIDC algorithm policy supports only RS256")
        required_claims = {item.strip() for item in effective.oidc_required_claims.split(",") if item.strip()}
        if not required_claims or not required_claims <= {"sub", "name", "email"}:
            raise ValueError("OIDC required claims may contain only sub, name, and email")
    if effective.allow_private_archive_tests and environment != "test":
        raise ValueError("private archive test override is allowed only in test environment")
    if effective.retention_purge_enabled and not effective.archive_enabled:
        raise ValueError("retention purge requires archive to be enabled")
    if effective.purge_after_days < effective.archive_after_days:
        raise ValueError("purge age must be greater than or equal to archive age")
    if effective.archive_enabled:
        if not effective.archive_store_endpoint or not effective.archive_store_bucket:
            raise ValueError("enabled archive storage requires endpoint and bucket")
        if not effective.archive_encryption_keys and not effective.archive_encryption_keys_file:
            raise ValueError("enabled archive storage requires an external encryption key registry")
        parsed_archive = urlparse(effective.archive_store_endpoint)
        private_http_ok = environment == "test" and effective.allow_private_archive_tests and parsed_archive.scheme == "http"
        if parsed_archive.scheme != "https" and not private_http_ok:
            raise ValueError("archive object-store endpoint must use HTTPS")
        if not parsed_archive.hostname or parsed_archive.username or parsed_archive.password or parsed_archive.query or parsed_archive.fragment:
            raise ValueError("archive object-store endpoint is invalid")
        if environment == "production" and (not effective.archive_store_access_key or not effective.archive_store_secret_key):
            raise ValueError("production archive storage requires explicit credentials")
    if effective.archive_replication_enabled:
        if not (effective.archive_store_endpoint and effective.archive_store_bucket) and not effective.archive_store_registry:
            raise ValueError("archive replication requires at least one trusted store")
        if effective.archive_store_registry:
            try:
                definitions = json.loads(effective.archive_store_registry)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("archive store registry is invalid") from exc
            if not isinstance(definitions, list):
                raise ValueError("archive store registry is invalid")
            for definition in definitions:
                if not isinstance(definition, dict) or not isinstance(definition.get("store_id"), str) or not isinstance(definition.get("endpoint"), str) or not isinstance(definition.get("bucket"), str):
                    raise ValueError("archive store registry is invalid")
                if any(secret in definition for secret in ("access_key", "secret_key", "session_token", "credential")):
                    raise ValueError("archive store registry must not contain credential values")
    return effective





