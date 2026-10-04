import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.report import Report


class CaseEncryptionKey(Base):
    """Stores the wrapped per-case Data Encryption Key (DEK) for payload envelope encryption."""
    __tablename__ = "case_encryption_keys"

    report_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("reports.id", ondelete="CASCADE"),
        primary_key=True,
    )
    dek_encrypted: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    dek_iv: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    dek_tag: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    key_version: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    is_destroyed: Mapped[bool] = mapped_column(
        sa.Boolean,
        nullable=False,
        default=False,
        server_default=sa.text("false"),
        index=True,
    )
    destroyed_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )

    # Relationships
    report: Mapped["Report"] = relationship(
        "Report",
        back_populates="encryption_key",
    )
