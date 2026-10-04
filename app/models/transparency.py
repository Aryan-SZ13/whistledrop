from datetime import datetime
from typing import Optional
import uuid
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class MerkleTreeState(Base):
    """Singleton tracking contiguous leaf index allocation and tree size."""
    __tablename__ = "merkle_tree_state"

    id: Mapped[int] = mapped_column(
        sa.Integer,
        primary_key=True,
    )
    tree_size: Mapped[int] = mapped_column(
        sa.BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    next_leaf_index: Mapped[int] = mapped_column(
        sa.BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
        nullable=False,
    )


class MerkleLeaf(Base):
    """Immutable leaf commitment in the RFC 6962 transparency log."""
    __tablename__ = "merkle_leaves"

    leaf_index: Mapped[int] = mapped_column(
        sa.BigInteger,
        primary_key=True,
    )
    leaf_hash: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    opaque_reference: Mapped[str] = mapped_column(
        sa.String(64),
        nullable=False,
        index=True,
    )
    canonical_leaf_bytes: Mapped[bytes] = mapped_column(
        sa.LargeBinary,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )


class SignedTreeHead(Base):
    """Periodically published Signed Tree Head (STH) binding tree size, root, and Ed25519 signature."""
    __tablename__ = "signed_tree_heads"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    tree_size: Mapped[int] = mapped_column(
        sa.BigInteger,
        unique=True,
        nullable=False,
    )
    root_hash: Mapped[str] = mapped_column(
        sa.String(64),
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
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
        index=True,
    )
