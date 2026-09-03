from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class IntegritySegmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    trace_id: str
    segment_sequence: int
    segment_version: str
    envelope_version: str
    source_start_sequence: int
    source_end_sequence: int
    record_count: int
    first_record_id: UUID
    last_record_id: UUID
    first_event_hash: str
    last_event_hash: str
    predecessor_boundary_hash: str | None
    successor_boundary_hash: str | None
    records_manifest_digest: str
    logical_segment_digest: str
    plaintext_sha256: str | None
    ciphertext_sha256: str | None
    archive_key_id: str | None
    archive_object_key: str | None
    archive_logical_id: UUID | None
    v17_ledger_segment_id: UUID
    v17_ledger_segment_digest: str
    v15_checkpoint_id: UUID
    v15_checkpoint_digest: str
    v15_continuity_status: str
    state: str
    verified_at: datetime | None
    compacted_at: datetime | None
    created_at: datetime
    updated_at: datetime


class IntegritySegmentRequest(BaseModel):
    segment_id: UUID


class IntegritySegmentPlanRequest(BaseModel):
    trace_id: str


class IntegritySegmentActionResponse(BaseModel):
    segment_id: UUID
    status: str
    records: int | None = None
    detail: dict[str, Any] | None = None
