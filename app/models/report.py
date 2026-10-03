import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import ReportCategory, ReportStatus

if TYPE_CHECKING:
    from app.models.report_update import ReportUpdate
    from app.models.audit_log import AuditLog


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    case_code_digest: Mapped[str] = mapped_column(
        sa.String(128),
        unique=True,
        index=True,
        nullable=False,
    )
    category: Mapped[ReportCategory] = mapped_column(
        sa.Enum(
            ReportCategory,
            name="report_category_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(
        sa.Text,
        nullable=False,
    )
    evidence_url: Mapped[Optional[str]] = mapped_column(
        sa.Text,
        nullable=True,
    )
    status: Mapped[ReportStatus] = mapped_column(
        sa.Enum(
            ReportStatus,
            name="report_status_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=ReportStatus.SUBMITTED,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
        nullable=False,
    )

    # Note: Intentionally excludes reporter identity, IP address, and User-Agent.

    # Relationships
    updates: Mapped[List["ReportUpdate"]] = relationship(
        "ReportUpdate",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="report",
    )
