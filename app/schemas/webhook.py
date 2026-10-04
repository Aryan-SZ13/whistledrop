import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class WebhookCreateRequest(BaseModel):
    url: HttpUrl = Field(..., description="Destination HTTPS URL (port 443)")
    description: Optional[str] = Field(default=None, max_length=255)
    subscribed_events: List[str] = Field(
        ...,
        min_length=1,
        description="List of events: report.created, report.status_changed, message.created, evidence.scanned, report.withdrawn, quorum.requested, quorum.approved",
    )

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WebhookCreateResponse(BaseModel):
    id: uuid.UUID
    url: str
    description: Optional[str] = None
    subscribed_events: List[str]
    webhook_secret: str = Field(..., description="Shared secret for HMAC-SHA256 signature verification (shown once)")
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class WebhookResponse(BaseModel):
    id: uuid.UUID
    url: str
    description: Optional[str] = None
    subscribed_events: List[str]
    is_active: bool
    failure_count: int
    created_at: datetime
    updated_at: datetime
    disabled_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class WebhookUpdateRequest(BaseModel):
    is_active: Optional[bool] = None
    subscribed_events: Optional[List[str]] = None
    description: Optional[str] = Field(default=None, max_length=255)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class WebhookDeliveryResponse(BaseModel):
    id: uuid.UUID
    outbox_event_id: uuid.UUID
    endpoint_id: uuid.UUID
    opaque_delivery_id: str
    attempt_number: int
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None
    delivered_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="forbid")


class WebhookTestResponse(BaseModel):
    status: str = Field(default="test_event_queued")
    opaque_event_id: str

    model_config = ConfigDict(extra="forbid")
