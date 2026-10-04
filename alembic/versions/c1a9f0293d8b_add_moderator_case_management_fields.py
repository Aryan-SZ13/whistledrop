"""add moderator case management fields priority assigned_to version_id

Revision ID: c1a9f0293d8b
Revises: b41e8c92a104
Create Date: 2026-10-04 14:52:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c1a9f0293d8b'
down_revision: Union[str, None] = 'b41e8c92a104'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create report_priority_enum
    priority_enum = postgresql.ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='report_priority_enum')
    priority_enum.create(op.get_bind(), checkfirst=True)

    # 2. Add columns to reports
    op.add_column(
        'reports',
        sa.Column(
            'priority',
            sa.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='report_priority_enum'),
            server_default='MEDIUM',
            nullable=False,
        ),
    )
    op.add_column(
        'reports',
        sa.Column(
            'assigned_to',
            sa.Uuid(),
            sa.ForeignKey('moderators.id', ondelete='SET NULL'),
            nullable=True,
        ),
    )
    op.add_column(
        'reports',
        sa.Column(
            'version_id',
            sa.Integer(),
            server_default='1',
            nullable=False,
        ),
    )

    # 3. Create indexes
    op.create_index('ix_reports_priority', 'reports', ['priority'], unique=False)
    op.create_index('ix_reports_assigned_to', 'reports', ['assigned_to'], unique=False)
    op.create_index('ix_reports_status_priority', 'reports', ['status', 'priority'], unique=False)
    op.create_index('ix_reports_assigned_status', 'reports', ['assigned_to', 'status'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_reports_assigned_status', table_name='reports')
    op.drop_index('ix_reports_status_priority', table_name='reports')
    op.drop_index('ix_reports_assigned_to', table_name='reports')
    op.drop_index('ix_reports_priority', table_name='reports')

    op.drop_column('reports', 'version_id')
    op.drop_column('reports', 'assigned_to')
    op.drop_column('reports', 'priority')

    priority_enum = postgresql.ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='report_priority_enum')
    priority_enum.drop(op.get_bind(), checkfirst=True)
