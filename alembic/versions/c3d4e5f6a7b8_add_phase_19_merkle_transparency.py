"""add Phase 19: RFC 6962 append-only Merkle transparency log

Revision ID: c3d4e5f6a7b8
Revises: b8c9d0e1f2a3
Create Date: 2026-10-04 20:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    # 1. Create merkle_tree_state table (singleton sequence allocator)
    op.create_table(
        'merkle_tree_state',
        sa.Column('id', sa.Integer(), primary_key=True, server_default=sa.text('1')),
        sa.Column('tree_size', sa.BigInteger(), nullable=False, server_default=sa.text('0')),
        sa.Column('next_leaf_index', sa.BigInteger(), nullable=False, server_default=sa.text('0')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    # Initialize singleton state
    op.execute(sa.text("INSERT INTO merkle_tree_state (id, tree_size, next_leaf_index) VALUES (1, 0, 0) ON CONFLICT (id) DO NOTHING"))

    # 2. Create merkle_leaves table
    op.create_table(
        'merkle_leaves',
        sa.Column('leaf_index', sa.BigInteger(), primary_key=True),
        sa.Column('leaf_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('opaque_reference', sa.String(128), nullable=False),
        sa.Column('canonical_leaf_bytes', sa.LargeBinary(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_merkle_leaves_leaf_hash', 'merkle_leaves', ['leaf_hash'])
    op.create_index('ix_merkle_leaves_event_type', 'merkle_leaves', ['event_type'])
    op.create_index('ix_merkle_leaves_opaque_ref', 'merkle_leaves', ['opaque_reference'])
    op.create_index('ix_merkle_leaves_created_at', 'merkle_leaves', ['created_at'])

    # 3. Create signed_tree_heads table
    op.create_table(
        'signed_tree_heads',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('tree_size', sa.BigInteger(), nullable=False, unique=True),
        sa.Column('root_hash', sa.String(64), nullable=False),
        sa.Column('signature', sa.String(128), nullable=False),
        sa.Column('signing_key_id', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_signed_tree_heads_tree_size', 'signed_tree_heads', ['tree_size'])
    op.create_index('ix_signed_tree_heads_created_at', 'signed_tree_heads', ['created_at'])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    op.drop_table('signed_tree_heads')
    op.drop_table('merkle_leaves')
    op.drop_table('merkle_tree_state')
