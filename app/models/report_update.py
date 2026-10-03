import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import ReportUpdateType

if TYPE_CHECKING:
    from app.models.report import Report
    from app.models.moderator import Moderator


class ReportUpdate(Base):
    __tablename__ = "report_updates"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    report_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    type: Mapped[ReportUpdateType] = mapped_column(
        sa.Enum(
            ReportUpdateType,
            name="report_update_type_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=ReportUpdateType.PUBLIC_UPDATE,
        index=True,
    )
    message: Mapped[str] = mapped_column(
        sa.Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("moderators.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    report: Mapped["Report"] = relationship(
        "Report",
        back_populates="updates",
    )
    creator: Mapped[Optional["Moderator"]] = relationship(
        "Moderator",
        back_populates="report_updates",
    )
