import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.moderator import Moderator


class ModeratorSession(Base):
    __tablename__ = "moderator_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    moderator_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_family: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        default=uuid.uuid4,
        nullable=False,
        index=True,
    )
    refresh_token_hash: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    user_agent_hash: Mapped[Optional[str]] = mapped_column(
        sa.String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    is_revoked: Mapped[bool] = mapped_column(
        sa.Boolean,
        default=False,
        server_default=sa.false(),
        nullable=False,
        index=True,
    )
    replaced_by_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderator_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    moderator: Mapped["Moderator"] = relationship(
        "Moderator",
        foreign_keys=[moderator_id],
    )
