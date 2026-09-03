from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class NotificationDestinationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=2048)
    signing_secret_reference: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    enabled: bool = True
    model_config = ConfigDict(extra="forbid")


class NotificationDestinationResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    type: str = Field(validation_alias=AliasChoices("type", "destination_type"))
    endpoint_scheme: str
    endpoint_host: str
    endpoint_port: int
    endpoint_path: str
    signing_secret_reference: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class NotificationDestinationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    signing_secret_reference: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    enabled: bool | None = None
    model_config = ConfigDict(extra="forbid")


class AlertPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    minimum_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    incident_status_filter: list[Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]] = Field(default_factory=lambda: ["OPEN"], max_length=3)
    failure_categories: list[str] = Field(default_factory=list, max_length=32)
    event_types: list[Literal["INCIDENT_CREATED", "INCIDENT_REOPENED", "SEVERITY_INCREASED", "INCIDENT_RESOLVED"]] = Field(default_factory=lambda: ["INCIDENT_CREATED", "INCIDENT_REOPENED", "SEVERITY_INCREASED", "INCIDENT_RESOLVED"], max_length=4)
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    enabled: bool = True
    model_config = ConfigDict(extra="forbid")


class AlertPolicyResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    minimum_severity: str
    incident_status_filter: list[str]
    failure_categories: list[str]
    event_types: list[str]
    cooldown_seconds: int
    enabled: bool
    policy_version: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class AlertPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    minimum_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    incident_status_filter: list[Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]] | None = Field(default=None, max_length=3)
    failure_categories: list[str] | None = Field(default=None, max_length=32)
    event_types: list[Literal["INCIDENT_CREATED", "INCIDENT_REOPENED", "SEVERITY_INCREASED", "INCIDENT_RESOLVED"]] | None = Field(default=None, max_length=4)
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    enabled: bool | None = None
    model_config = ConfigDict(extra="forbid")


class NotificationDeliveryResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    incident_id: UUID
    destination_id: UUID
    policy_id: UUID
    event_type: str
    status: str
    attempt_count: int
    failure_category: str | None
    payload_digest: str
    created_at: datetime
    last_attempt_at: datetime | None
    delivered_at: datetime | None
    next_retry_at: datetime | None
    model_config = ConfigDict(from_attributes=True, extra="forbid")
