import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.enums import EvidenceScanStatus

if TYPE_CHECKING:
    from app.models.report import Report


class EvidenceAttachment(Base):
    __tablename__ = "evidence_attachments"

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
    storage_key: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        unique=True,
        nullable=False,
        index=True,
        default=uuid.uuid4,
    )
    detected_mime: Mapped[str] = mapped_column(
        sa.String(127),
        nullable=False,
    )
    file_size: Mapped[int] = mapped_column(
        sa.BigInteger,
        nullable=False,
    )
    sha256_hash: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
    )
    scan_status: Mapped[EvidenceScanStatus] = mapped_column(
        sa.Enum(
            EvidenceScanStatus,
            name="evidence_scan_status_enum",
            native_enum=True,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=EvidenceScanStatus.PENDING_SCAN,
        index=True,
    )
    scanned_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
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

    # Note: Intentionally excludes reporter identity, IP address, and client filename.

    # Relationships
    report: Mapped["Report"] = relationship(
        "Report",
        back_populates="evidence_attachments",
    )
