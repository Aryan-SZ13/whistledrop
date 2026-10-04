"""add case_messages, case_message_moderator_read_state, and report notification fields

Revision ID: e3f8a1c92d54
Revises: c1a9f0293d8b
Create Date: 2026-10-04 15:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e3f8a1c92d54'
down_revision: Union[str, None] = 'c1a9f0293d8b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create message_sender_type_enum
    sender_type_enum = postgresql.ENUM('REPORTER', 'MODERATOR', name='message_sender_type_enum')
    sender_type_enum.create(op.get_bind(), checkfirst=True)

    # 2. Create case_messages table
    op.create_table(
        'case_messages',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('public_id', sa.String(36), nullable=False),
        sa.Column('report_id', sa.Uuid(as_uuid=True), sa.ForeignKey('reports.id', ondelete='CASCADE'), nullable=False),
        sa.Column(
            'sender_type',
            sa.Enum('REPORTER', 'MODERATOR', name='message_sender_type_enum', create_type=False),
            nullable=False,
        ),
        sa.Column('moderator_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='RESTRICT'), nullable=True),
        sa.Column('idempotency_key', sa.String(64), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
        sa.CheckConstraint(
            'char_length(content) >= 1 AND char_length(content) <= 5000',
            name='chk_message_content_length',
        ),
        sa.CheckConstraint(
            "(sender_type = 'REPORTER' AND moderator_id IS NULL) OR (sender_type = 'MODERATOR' AND moderator_id IS NOT NULL)",
            name='chk_message_authorship',
        ),
    )

    # 3. Indexes for case_messages
    op.create_index('uq_case_messages_public_id', 'case_messages', ['public_id'], unique=True)
    op.create_index(
        'uq_case_messages_reporter_idempotency',
        'case_messages',
        ['report_id', 'idempotency_key'],
        unique=True,
        postgresql_where=sa.text("sender_type = 'REPORTER' AND idempotency_key IS NOT NULL"),
    )
    op.create_index(
        'uq_case_messages_moderator_idempotency',
        'case_messages',
        ['report_id', 'moderator_id', 'idempotency_key'],
        unique=True,
        postgresql_where=sa.text("sender_type = 'MODERATOR' AND idempotency_key IS NOT NULL"),
    )
    op.create_index(
        'ix_case_messages_report_created',
        'case_messages',
        ['report_id', 'created_at', 'id'],
    )
    op.create_index(
        'ix_case_messages_report_sender',
        'case_messages',
        ['report_id', 'sender_type', 'created_at', 'id'],
    )

    # 4. Create case_message_moderator_read_state table
    op.create_table(
        'case_message_moderator_read_state',
        sa.Column('report_id', sa.Uuid(as_uuid=True), sa.ForeignKey('reports.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('moderator_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('last_read_message_id', sa.Uuid(as_uuid=True), sa.ForeignKey('case_messages.id', ondelete='SET NULL'), nullable=True),
        sa.Column('last_read_created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    )
    op.create_index(
        'ix_mod_read_state_moderator',
        'case_message_moderator_read_state',
        ['moderator_id'],
    )

    # 5. Add columns to reports
    op.add_column('reports', sa.Column('status_version', sa.Integer(), server_default='1', nullable=False))
    op.add_column('reports', sa.Column('reporter_acknowledged_status_version', sa.Integer(), server_default='1', nullable=False))
    op.add_column('reports', sa.Column('reporter_last_read_created_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'reports',
        sa.Column(
            'reporter_last_read_message_id',
            sa.Uuid(as_uuid=True),
            sa.ForeignKey('case_messages.id', ondelete='SET NULL'),
            nullable=True,
        ),
    )


def downgrade() -> None:
    # 1. Drop columns from reports
    op.drop_constraint('reports_reporter_last_read_message_id_fkey', 'reports', type_='foreignkey')
    op.drop_column('reports', 'reporter_last_read_message_id')
    op.drop_column('reports', 'reporter_last_read_created_at')
    op.drop_column('reports', 'reporter_acknowledged_status_version')
    op.drop_column('reports', 'status_version')

    # 2. Drop case_message_moderator_read_state
    op.drop_index('ix_mod_read_state_moderator', table_name='case_message_moderator_read_state')
    op.drop_table('case_message_moderator_read_state')

    # 3. Drop case_messages
    op.drop_index('ix_case_messages_report_sender', table_name='case_messages')
    op.drop_index('ix_case_messages_report_created', table_name='case_messages')
    op.drop_index('uq_case_messages_moderator_idempotency', table_name='case_messages')
    op.drop_index('uq_case_messages_reporter_idempotency', table_name='case_messages')
    op.drop_index('uq_case_messages_public_id', table_name='case_messages')
    op.drop_table('case_messages')

    # 4. Drop message_sender_type_enum
    sender_type_enum = postgresql.ENUM('REPORTER', 'MODERATOR', name='message_sender_type_enum')
    sender_type_enum.drop(op.get_bind(), checkfirst=True)
