import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, List, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import ModeratorRole

if TYPE_CHECKING:
    from app.models.report import Report
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
    token_version: Mapped[int] = mapped_column(
        sa.Integer,
        default=1,
        server_default=sa.text("1"),
        nullable=False,
    )
    totp_secret_encrypted: Mapped[Optional[bytes]] = mapped_column(
        sa.LargeBinary,
        nullable=True,
    )
    totp_secret_iv: Mapped[Optional[bytes]] = mapped_column(
        sa.LargeBinary,
        nullable=True,
    )
    totp_secret_tag: Mapped[Optional[bytes]] = mapped_column(
        sa.LargeBinary,
        nullable=True,
    )
    is_totp_enabled: Mapped[bool] = mapped_column(
        sa.Boolean,
        default=False,
        server_default=sa.false(),
        nullable=False,
        index=True,
    )
    totp_enrolled_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    backup_codes: Mapped[Optional[Any]] = mapped_column(
        sa.JSON,
        nullable=True,
    )
    failed_totp_attempts: Mapped[int] = mapped_column(
        sa.Integer,
        default=0,
        server_default=sa.text("0"),
        nullable=False,
    )
    totp_locked_until: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
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
    assigned_reports: Mapped[List["Report"]] = relationship(
        "Report",
        back_populates="assignee",
        foreign_keys="Report.assigned_to",
    )
