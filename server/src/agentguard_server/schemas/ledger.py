from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LedgerSegmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    trace_id: str
    segment_sequence: int
    segment_version: str
    start_event_sequence: int
    end_event_sequence: int
    start_previous_hash: str | None
    end_event_hash: str
    event_count: int
    events_manifest_digest: str
    segment_manifest_digest: str
    archive_plaintext_sha256: str | None
    archive_ciphertext_sha256: str | None
    archive_object_key: str | None
    covering_checkpoint_sequence: int | None
    covering_checkpoint_digest: str | None
    created_at: datetime
    archived_verified_at: datetime | None
    status: str


class LedgerCompactRequest(BaseModel):
    segment_id: UUID


class LedgerEventLookup(BaseModel):
    tenant_id: UUID
    trace_id: str
    event_id: str
    event_sequence: int
    event_hash: str
    source: str
    evidence: dict[str, Any]


class LedgerVerificationResponse(BaseModel):
    segment_id: UUID
    verification: dict[str, Any]
