"""add report update type enum and column

Revision ID: 087f9290f638
Revises: de70dfb259c0
Create Date: 2026-10-03 19:39:33.482476

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '087f9290f638'
down_revision: Union[str, None] = 'de70dfb259c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create enum type explicitly if not present
    update_type_enum = postgresql.ENUM(
        'PUBLIC_UPDATE',
        'INTERNAL_NOTE',
        name='report_update_type_enum',
        create_type=False,
    )
    update_type_enum.create(op.get_bind(), checkfirst=True)

    # 2. Add column with server_default='PUBLIC_UPDATE' for zero-downtime / backfill safety
    op.add_column(
        'report_updates',
        sa.Column(
            'type',
            sa.Enum('PUBLIC_UPDATE', 'INTERNAL_NOTE', name='report_update_type_enum'),
            nullable=False,
            server_default='PUBLIC_UPDATE',
        ),
    )
    op.create_index(op.f('ix_report_updates_type'), 'report_updates', ['type'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_report_updates_type'), table_name='report_updates')
    op.drop_column('report_updates', 'type')
    update_type_enum = postgresql.ENUM(
        'PUBLIC_UPDATE',
        'INTERNAL_NOTE',
        name='report_update_type_enum',
    )
    update_type_enum.drop(op.get_bind(), checkfirst=True)

