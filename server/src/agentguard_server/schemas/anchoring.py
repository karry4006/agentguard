from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class CheckpointCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    force: bool = False


class CheckpointResponse(BaseModel):
    id: UUID
    namespace: str
    checkpoint_sequence: int
    checkpoint_version: str
    manifest_digest: str
    previous_checkpoint_digest: str | None
    checkpoint_digest: str
    entry_count: int
    created_at: datetime
    verification: dict[str, Any] | None = None


class AnchorStatusResponse(BaseModel):
    namespace: str
    latest_checkpoint_sequence: int | None
    latest_checkpoint_at: datetime | None
    last_successful_anchor_at: datetime | None
    verification_status: str
    freshness: str
    remote_continuity: str | None = None
    signer_key_id: str | None = None


class ContinuityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    local_sequence: int | None = None
    remote_sequence: int | None = None
    local_digest: str | None = None
    remote_digest: str | None = None
