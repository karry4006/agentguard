from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ArchiveReplicaResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    tenant_id: UUID
    logical_archive_type: str
    logical_archive_id: UUID
    store_id: str
    object_key: str
    expected_ciphertext_sha256: str
    expected_plaintext_sha256: str | None
    expected_logical_digest: str
    encryption_key_id: str
    state: str
    verified_at: datetime | None
    last_scrubbed_at: datetime | None
    last_error_category: str | None
    created_at: datetime
    updated_at: datetime


class ArchiveReplicaHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    logical_archive_type: str
    logical_archive_id: str
    health: str
    verified_replica_count: int
    required_verified_replicas: int
    states: dict[str, int]


class ArchiveRepairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_store_id: str
    dry_run: bool = True
