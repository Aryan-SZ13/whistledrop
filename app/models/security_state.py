import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.moderator import Moderator
    from app.models.quorum import QuorumRequest


class WarrantCanary(Base):
    """Stores cryptographically signed periodic warrant canary statements."""
    __tablename__ = "warrant_canaries"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    canary_sequence: Mapped[int] = mapped_column(
        sa.Integer,
        unique=True,
        nullable=False,
    )
    statement_hash: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
    )
    statement_text: Mapped[str] = mapped_column(
        sa.Text,
        nullable=False,
    )
    valid_from: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
    )
    valid_until: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    published_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
    signature: Mapped[str] = mapped_column(
        sa.String(128),
        nullable=False,
    )
    signing_key_id: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
    )
    first_approved_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="RESTRICT"),
        nullable=True,
    )
    second_approved_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="RESTRICT"),
        nullable=True,
    )
    quorum_request_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("quorum_requests.id", ondelete="RESTRICT"),
        nullable=True,
    )

    __table_args__ = (
        sa.CheckConstraint(
            "first_approved_by_id IS NULL OR second_approved_by_id IS NULL OR first_approved_by_id != second_approved_by_id",
            name="chk_canary_distinct_approvers",
        ),
        sa.CheckConstraint("valid_until > valid_from", name="chk_canary_validity_period"),
    )


class SystemSecurityState(Base):
    """Singleton tracking emergency sealing state and operational dead-man's switch."""
    __tablename__ = "system_security_state"

    id: Mapped[int] = mapped_column(
        sa.Integer,
        primary_key=True,
    )
    is_sealed: Mapped[bool] = mapped_column(
        sa.Boolean,
        nullable=False,
        default=False,
        server_default=sa.text("false"),
    )
    sealed_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    sealed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="SET NULL"),
        nullable=True,
    )
    seal_reason: Mapped[Optional[str]] = mapped_column(
        sa.String(500),
        nullable=True,
    )
    dead_man_due_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
    )
    last_check_in_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
    last_check_in_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
        nullable=False,
    )
