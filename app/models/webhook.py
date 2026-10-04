import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.moderator import Moderator
    from app.models.report import Report


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    url: Mapped[str] = mapped_column(
        sa.String(2048),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        sa.String(255),
        nullable=True,
    )
    secret_encrypted: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    secret_iv: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    secret_tag: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean,
        default=True,
        server_default=sa.true(),
        nullable=False,
        index=True,
    )
    subscribed_events: Mapped[List[str]] = mapped_column(
        sa.JSON,
        nullable=False,
    )
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
        nullable=False,
    )
    failure_count: Mapped[int] = mapped_column(
        sa.Integer,
        default=0,
        server_default=sa.text("0"),
        nullable=False,
    )
    disabled_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    created_by: Mapped["Moderator"] = relationship(
        "Moderator",
        foreign_keys=[created_by_id],
    )


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    opaque_event_id: Mapped[str] = mapped_column(
        sa.String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    report_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("reports.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    payload: Mapped[Dict[str, Any]] = mapped_column(
        sa.JSON,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        sa.String(32),
        default="PENDING",
        server_default="PENDING",
        nullable=False,
        index=True,
    )
    retry_count: Mapped[int] = mapped_column(
        sa.Integer,
        default=0,
        server_default=sa.text("0"),
        nullable=False,
    )
    next_retry_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )
    lease_worker_id: Mapped[Optional[str]] = mapped_column(
        sa.String(64),
        nullable=True,
    )
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    dispatched_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    error_summary: Mapped[Optional[str]] = mapped_column(
        sa.String(500),
        nullable=True,
    )


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    outbox_event_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("outbox_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    opaque_delivery_id: Mapped[str] = mapped_column(
        sa.String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    attempt_number: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
    )
    status_code: Mapped[Optional[int]] = mapped_column(
        sa.Integer,
        nullable=True,
    )
    latency_ms: Mapped[Optional[float]] = mapped_column(
        sa.Float,
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        sa.String(500),
        nullable=True,
    )
    delivered_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )
