from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import MessageSenderType


class CaseMessageCreateRequest(BaseModel):
    """Payload for submitting a message to an anonymous case channel."""
    content: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The plaintext message content (1 to 5,000 characters).",
    )


class ModeratorMessageCreateRequest(BaseModel):
    """Payload for a moderator posting a public reply to a case."""
    content: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The public response message to the whistleblower (1 to 5,000 characters).",
    )


class CaseMessageResponse(BaseModel):
    """Public message representation. Never exposes internal DB UUIDs or moderator identity."""
    id: str = Field(..., description="Opaque public message identifier (e.g. msg_...).")
    sender: str = Field(..., description="Sender type: 'REPORTER' or 'MODERATOR'.")
    content: str = Field(..., description="Message text content.")
    created_at: datetime = Field(..., description="Timestamp when message was created.")

    model_config = ConfigDict(from_attributes=True)


class CaseMessageListResponse(BaseModel):
    """Cursor-paginated conversation list."""
    items: List[CaseMessageResponse] = Field(default_factory=list, description="List of messages in chronological order.")
    next_cursor: Optional[str] = Field(None, description="Opaque signed cursor token for fetching next page.")
    has_more: bool = Field(False, description="True if subsequent messages exist beyond this page.")
    total_unread: int = Field(0, description="Total unread messages for the requesting caller.")


class MessageReadAckRequest(BaseModel):
    """Request to advance message read high-water mark."""
    last_read_message_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Public message ID (msg_...) of the highest read message.",
    )


class MessageReadAckResponse(BaseModel):
    """Result of message read acknowledgment."""
    acknowledged: bool = Field(..., description="True if acknowledgment was processed.")
    last_read_message_id: Optional[str] = Field(None, description="Public message ID of current high-water mark.")
    last_read_at: Optional[datetime] = Field(None, description="Timestamp of current high-water mark.")
    unread_count: int = Field(..., description="Remaining unread messages after this advancement.")


class CaseNotificationResponse(BaseModel):
    """Pull-based anonymous notification check response."""
    status: str = Field(..., description="Current case lifecycle status.")
    status_version: int = Field(..., description="Current lifecycle status version.")
    has_status_update: bool = Field(..., description="True if status has changed since reporter's last ack.")
    unread_messages: int = Field(..., description="Number of unread messages from moderators.")
    last_activity_at: Optional[datetime] = Field(None, description="Timestamp of most recent activity on this case.")


class NotificationStatusAckRequest(BaseModel):
    """Request to acknowledge observed case status version."""
    status_version: int = Field(
        ...,
        ge=1,
        le=1000000,
        description="The status version being acknowledged by the whistleblower.",
    )


class NotificationStatusAckResponse(BaseModel):
    """Result of status version acknowledgment."""
    acknowledged: bool = Field(..., description="True if acknowledgment was recorded.")
    acknowledged_version: int = Field(..., description="The high-water status version recorded.")
