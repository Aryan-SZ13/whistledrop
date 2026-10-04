"""add Phase 20: warrant canaries, dead-man switch, and emergency access sealing

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-04 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    # 1. Create system_security_state table (singleton)
    op.create_table(
        'system_security_state',
        sa.Column('id', sa.Integer(), primary_key=True, server_default=sa.text('1')),
        sa.Column('is_sealed', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('sealed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sealed_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='SET NULL'), nullable=True),
        sa.Column('seal_reason', sa.String(500), nullable=True),
        sa.Column('dead_man_due_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_check_in_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_check_in_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='SET NULL'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    # Initialize singleton state: 14 days in future
    op.execute(sa.text("INSERT INTO system_security_state (id, is_sealed, dead_man_due_at, last_check_in_at) VALUES (1, false, NOW() + INTERVAL '14 days', NOW()) ON CONFLICT (id) DO NOTHING"))

    # 2. Create warrant_canaries table
    op.create_table(
        'warrant_canaries',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('canary_sequence', sa.Integer(), nullable=False, unique=True),
        sa.Column('statement_text', sa.Text(), nullable=False),
        sa.Column('statement_hash', sa.String(64), nullable=False),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
        sa.Column('published_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('signature', sa.String(128), nullable=False),
        sa.Column('signing_key_id', sa.String(64), nullable=False),
        sa.Column('first_approved_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='RESTRICT'), nullable=True),
        sa.Column('second_approved_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='RESTRICT'), nullable=True),
        sa.Column('quorum_request_id', sa.Uuid(as_uuid=True), sa.ForeignKey('quorum_requests.id', ondelete='RESTRICT'), nullable=True),
    )
    op.create_index('ix_warrant_canaries_sequence', 'warrant_canaries', ['canary_sequence'])
    op.create_index('ix_warrant_canaries_valid_until', 'warrant_canaries', ['valid_until'])
    op.create_index('ix_warrant_canaries_published_at', 'warrant_canaries', ['published_at'])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    op.drop_table('warrant_canaries')
    op.drop_table('system_security_state')
