"""add Phase 18: payload envelope encryption and case DEK storage

Revision ID: b8c9d0e1f2a3
Revises: a7b9c1d2e3f4
Create Date: 2026-10-04 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8c9d0e1f2a3'
down_revision: Union[str, None] = 'a7b9c1d2e3f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    # 1. Create case_encryption_keys table
    op.create_table(
        'case_encryption_keys',
        sa.Column('report_id', sa.Uuid(as_uuid=True), sa.ForeignKey('reports.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('dek_encrypted', sa.LargeBinary(), nullable=False),
        sa.Column('dek_iv', sa.LargeBinary(), nullable=False),
        sa.Column('dek_tag', sa.LargeBinary(), nullable=False),
        sa.Column('key_version', sa.Integer(), nullable=False, server_default=sa.text('1')),
        sa.Column('is_destroyed', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('destroyed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_case_encryption_keys_is_destroyed', 'case_encryption_keys', ['is_destroyed'])

    # 2. Add ALEE columns to reports table and alter description to nullable
    op.alter_column('reports', 'description', existing_type=sa.Text(), nullable=True)
    op.add_column('reports', sa.Column('description_encrypted', sa.LargeBinary(), nullable=True))
    op.add_column('reports', sa.Column('description_iv', sa.LargeBinary(), nullable=True))
    op.add_column('reports', sa.Column('description_tag', sa.LargeBinary(), nullable=True))
    op.add_column('reports', sa.Column('description_aad_version', sa.Integer(), nullable=True))

    # 3. Add ALEE columns to report_updates table and alter message to nullable
    op.alter_column('report_updates', 'message', existing_type=sa.Text(), nullable=True)
    op.add_column('report_updates', sa.Column('message_encrypted', sa.LargeBinary(), nullable=True))
    op.add_column('report_updates', sa.Column('message_iv', sa.LargeBinary(), nullable=True))
    op.add_column('report_updates', sa.Column('message_tag', sa.LargeBinary(), nullable=True))
    op.add_column('report_updates', sa.Column('message_aad_version', sa.Integer(), nullable=True))

    # 4. Add ALEE columns to case_messages table and alter content to nullable
    op.alter_column('case_messages', 'content', existing_type=sa.Text(), nullable=True)
    op.add_column('case_messages', sa.Column('content_encrypted', sa.LargeBinary(), nullable=True))
    op.add_column('case_messages', sa.Column('content_iv', sa.LargeBinary(), nullable=True))
    op.add_column('case_messages', sa.Column('content_tag', sa.LargeBinary(), nullable=True))
    op.add_column('case_messages', sa.Column('content_aad_version', sa.Integer(), nullable=True))

    # Update check constraint on case_messages content length
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("ALTER TABLE case_messages DROP CONSTRAINT IF EXISTS chk_message_content_length"))
        op.execute(sa.text("ALTER TABLE case_messages ADD CONSTRAINT chk_message_content_length CHECK (content IS NULL OR (char_length(content) >= 1 AND char_length(content) <= 5000))"))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    op.drop_column('case_messages', 'content_aad_version')
    op.drop_column('case_messages', 'content_tag')
    op.drop_column('case_messages', 'content_iv')
    op.drop_column('case_messages', 'content_encrypted')
    op.alter_column('case_messages', 'content', existing_type=sa.Text(), nullable=False)

    op.drop_column('report_updates', 'message_aad_version')
    op.drop_column('report_updates', 'message_tag')
    op.drop_column('report_updates', 'message_iv')
    op.drop_column('report_updates', 'message_encrypted')
    op.alter_column('report_updates', 'message', existing_type=sa.Text(), nullable=False)

    op.drop_column('reports', 'description_aad_version')
    op.drop_column('reports', 'description_tag')
    op.drop_column('reports', 'description_iv')
    op.drop_column('reports', 'description_encrypted')
    op.alter_column('reports', 'description', existing_type=sa.Text(), nullable=False)

    op.drop_index('ix_case_encryption_keys_is_destroyed', table_name='case_encryption_keys')
    op.drop_table('case_encryption_keys')
