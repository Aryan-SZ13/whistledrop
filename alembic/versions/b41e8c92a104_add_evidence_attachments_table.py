"""add evidence attachments table and scan status enum

Revision ID: b41e8c92a104
Revises: 087f9290f638
Create Date: 2026-10-04 03:26:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b41e8c92a104'
down_revision: Union[str, None] = '087f9290f638'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create evidence_attachments table (sa.Enum will automatically create evidence_scan_status_enum)
    op.create_table(
        'evidence_attachments',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('report_id', sa.Uuid(), nullable=False),
        sa.Column('storage_key', sa.Uuid(), nullable=False),
        sa.Column('detected_mime', sa.String(length=127), nullable=False),
        sa.Column('file_size', sa.BigInteger(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column(
            'scan_status',
            sa.Enum(
                'PENDING_SCAN',
                'SCAN_CLEAN',
                'PROMOTING',
                'CLEAN',
                'INFECTED',
                'SCAN_FAILED',
                'DELETED',
                name='evidence_scan_status_enum',
            ),
            server_default='PENDING_SCAN',
            nullable=False,
        ),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['report_id'], ['reports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_evidence_attachments_report_id'), 'evidence_attachments', ['report_id'], unique=False)
    op.create_index(op.f('ix_evidence_attachments_storage_key'), 'evidence_attachments', ['storage_key'], unique=True)
    op.create_index(op.f('ix_evidence_attachments_scan_status'), 'evidence_attachments', ['scan_status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_evidence_attachments_scan_status'), table_name='evidence_attachments')
    op.drop_index(op.f('ix_evidence_attachments_storage_key'), table_name='evidence_attachments')
    op.drop_index(op.f('ix_evidence_attachments_report_id'), table_name='evidence_attachments')
    op.drop_table('evidence_attachments')

    scan_status_enum = postgresql.ENUM(
        'PENDING_SCAN',
        'SCAN_CLEAN',
        'PROMOTING',
        'CLEAN',
        'INFECTED',
        'SCAN_FAILED',
        'DELETED',
        name='evidence_scan_status_enum',
    )
    scan_status_enum.drop(op.get_bind(), checkfirst=True)
