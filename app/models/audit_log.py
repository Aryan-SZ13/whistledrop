import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.report import Report
    from app.models.moderator import Moderator


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    report_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("reports.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    moderator_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    # Structured action metadata (e.g. status transition, timestamp diffs).
    # Critical: Do NOT store full report descriptions or reporter-identifying data in metadata.
    metadata_: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata",
        sa.JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )

    # Relationships
    report: Mapped[Optional["Report"]] = relationship(
        "Report",
        back_populates="audit_logs",
    )
    moderator: Mapped[Optional["Moderator"]] = relationship(
        "Moderator",
        back_populates="audit_logs",
    )
