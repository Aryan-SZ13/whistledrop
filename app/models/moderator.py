import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import ModeratorRole

if TYPE_CHECKING:
    from app.models.report_update import ReportUpdate
    from app.models.audit_log import AuditLog


class Moderator(Base):
    __tablename__ = "moderators"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(
        sa.String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        sa.String(255),
        nullable=False,
    )
    role: Mapped[ModeratorRole] = mapped_column(
        sa.Enum(
            ModeratorRole,
            name="moderator_role_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=ModeratorRole.MODERATOR,
    )
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean,
        default=True,
        server_default=sa.true(),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )

    # Relationships
    report_updates: Mapped[List["ReportUpdate"]] = relationship(
        "ReportUpdate",
        back_populates="creator",
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="moderator",
    )
