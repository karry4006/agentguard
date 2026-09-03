from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ArchiveResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    trace_id: str
    archive_version: str
    envelope_version: str
    object_key: str
    archive_encryption_key_id: str
    plaintext_sha256: str | None
    compressed_sha256: str | None
    ciphertext_sha256: str | None
    source_projection_digest: str | None
    covering_checkpoint_sequence: int | None
    covering_checkpoint_digest: str | None
    trace_span_count: int
    plaintext_size: int | None
    compressed_size: int | None
    ciphertext_size: int | None
    created_at: datetime
    verified_at: datetime | None
    status: str


class RetentionStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    archive_enabled: bool
    purge_enabled: bool
    pending_jobs: int
    archived: int
    purged: int
    failed_jobs: int
    active_holds: int


class RetentionRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dry_run: bool = True


class RetentionRunResponse(BaseModel):
    dry_run: bool
    queued: int
    eligible: int
    blocked: int


class RetentionHoldCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_type: Literal["TRACE", "TENANT"]
    trace_id: str | None = Field(default=None, min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=4096)


class RetentionHoldResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    subject_type: str
    trace_id: str | None
    reason: str
    created_by_principal_type: str
    created_by_principal_id: str
    created_at: datetime
    released_at: datetime | None
    released_by_principal_type: str | None
    released_by_principal_id: str | None


class ArchiveRetrievalResponse(BaseModel):
    archive: ArchiveResponse
    payload: dict[str, Any]

