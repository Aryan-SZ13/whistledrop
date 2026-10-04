import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.moderator import Moderator


class QuorumRequest(Base):
    __tablename__ = "quorum_requests"
    __table_args__ = (
        sa.CheckConstraint("proposed_by_id != approved_by_id", name="chk_quorum_distinct_operators"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    action_type: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    target_id: Mapped[Optional[str]] = mapped_column(
        sa.String(64),
        nullable=True,
        index=True,
    )
    proposal_hash: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
    )
    proposed_by_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="RESTRICT"),
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
    parameters: Mapped[Dict[str, Any]] = mapped_column(
        sa.JSON,
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(
        sa.String(1000),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
    executed_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    approved_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    approval_reason: Mapped[Optional[str]] = mapped_column(
        sa.String(1000),
        nullable=True,
    )
    approval_signature: Mapped[Optional[str]] = mapped_column(
        sa.String(128),
        nullable=True,
    )

    # Relationships
    proposed_by: Mapped["Moderator"] = relationship(
        "Moderator",
        foreign_keys=[proposed_by_id],
    )
    approved_by: Mapped[Optional["Moderator"]] = relationship(
        "Moderator",
        foreign_keys=[approved_by_id],
    )
