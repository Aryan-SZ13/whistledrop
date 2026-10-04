from datetime import datetime
from typing import TYPE_CHECKING, Optional
import uuid
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import MessageSenderType

if TYPE_CHECKING:
    from app.models.moderator import Moderator
    from app.models.report import Report


class CaseMessage(Base):
    """Represents a message in the bidirectional case communication channel."""
    __tablename__ = "case_messages"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    public_id: Mapped[str] = mapped_column(
        sa.String(36),
        unique=True,
        index=True,
        nullable=False,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sender_type: Mapped[MessageSenderType] = mapped_column(
        sa.Enum(
            MessageSenderType,
            name="message_sender_type_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )
    moderator_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    idempotency_key: Mapped[Optional[str]] = mapped_column(
        sa.String(64),
        nullable=True,
    )
    content: Mapped[str] = mapped_column(
        sa.Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.clock_timestamp(),
        nullable=False,
        index=True,
    )

    # Relationships
    report: Mapped["Report"] = relationship("Report", back_populates="messages", foreign_keys=[report_id])
    moderator: Mapped[Optional["Moderator"]] = relationship("Moderator")

    __table_args__ = (
        sa.CheckConstraint(
            "char_length(content) >= 1 AND char_length(content) <= 5000",
            name="chk_message_content_length",
        ),
        sa.CheckConstraint(
            "(sender_type = 'REPORTER' AND moderator_id IS NULL) OR (sender_type = 'MODERATOR' AND moderator_id IS NOT NULL)",
            name="chk_message_authorship",
        ),
        # Partial unique indexes for idempotency scopes
        sa.Index(
            "uq_case_messages_reporter_idempotency",
            "report_id",
            "idempotency_key",
            unique=True,
            postgresql_where=sa.text("sender_type = 'REPORTER' AND idempotency_key IS NOT NULL"),
        ),
        sa.Index(
            "uq_case_messages_moderator_idempotency",
            "report_id",
            "moderator_id",
            "idempotency_key",
            unique=True,
            postgresql_where=sa.text("sender_type = 'MODERATOR' AND idempotency_key IS NOT NULL"),
        ),
        # Deterministic keyset pagination & read state queries
        sa.Index(
            "ix_case_messages_report_created",
            "report_id",
            "created_at",
            "id",
        ),
        sa.Index(
            "ix_case_messages_report_sender",
            "report_id",
            "sender_type",
            "created_at",
            "id",
        ),
    )


class CaseMessageModeratorReadState(Base):
    """Tracks per-moderator monotonic read high-water mark for a given report."""
    __tablename__ = "case_message_moderator_read_state"

    report_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("reports.id", ondelete="CASCADE"),
        primary_key=True,
    )
    moderator_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    last_read_message_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("case_messages.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_read_created_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.clock_timestamp(),
        onupdate=sa.func.clock_timestamp(),
        nullable=False,
    )

    # Relationships
    report: Mapped["Report"] = relationship("Report", back_populates="moderator_read_states")
    moderator: Mapped["Moderator"] = relationship("Moderator")
    last_read_message: Mapped[Optional["CaseMessage"]] = relationship("CaseMessage", foreign_keys=[last_read_message_id])
