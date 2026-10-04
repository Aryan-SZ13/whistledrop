"""add Phase 15, 16, 17: MFA, sessions, webhooks, outbox, and quorum

Revision ID: a7b9c1d2e3f4
Revises: f4a8b2c1d3e5
Create Date: 2026-10-04 19:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7b9c1d2e3f4'
down_revision: Union[str, None] = 'f4a8b2c1d3e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("SET lock_timeout = '5s'"))

    # 1. Alter moderators table (Phase 15 MFA & token_version)
    op.add_column('moderators', sa.Column('token_version', sa.Integer(), nullable=False, server_default=sa.text('1')))
    op.add_column('moderators', sa.Column('totp_secret_encrypted', sa.LargeBinary(), nullable=True))
    op.add_column('moderators', sa.Column('totp_secret_iv', sa.LargeBinary(), nullable=True))
    op.add_column('moderators', sa.Column('totp_secret_tag', sa.LargeBinary(), nullable=True))
    op.add_column('moderators', sa.Column('is_totp_enabled', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('moderators', sa.Column('totp_enrolled_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('moderators', sa.Column('backup_codes', sa.JSON(), nullable=True))
    op.add_column('moderators', sa.Column('failed_totp_attempts', sa.Integer(), nullable=False, server_default=sa.text('0')))
    op.add_column('moderators', sa.Column('totp_locked_until', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_moderators_totp_enabled', 'moderators', ['is_totp_enabled'])

    # 2. Create moderator_sessions table (Phase 15 persistent sessions)
    op.create_table(
        'moderator_sessions',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('moderator_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='CASCADE'), nullable=False),
        sa.Column('session_family', sa.Uuid(as_uuid=True), nullable=False),
        sa.Column('refresh_token_hash', sa.String(64), nullable=False),
        sa.Column('user_agent_hash', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('replaced_by_session_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderator_sessions.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_moderator_sessions_moderator_id', 'moderator_sessions', ['moderator_id'])
    op.create_index('ix_moderator_sessions_session_family', 'moderator_sessions', ['session_family'])
    op.create_index('ix_moderator_sessions_refresh_token_hash', 'moderator_sessions', ['refresh_token_hash'])
    op.create_index('ix_moderator_sessions_expires_at', 'moderator_sessions', ['expires_at'])
    op.create_index('ix_moderator_sessions_is_revoked', 'moderator_sessions', ['is_revoked'])

    # 3. Create webhook_endpoints table (Phase 16)
    op.create_table(
        'webhook_endpoints',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('description', sa.String(255), nullable=True),
        sa.Column('secret_encrypted', sa.LargeBinary(), nullable=False),
        sa.Column('secret_iv', sa.LargeBinary(), nullable=False),
        sa.Column('secret_tag', sa.LargeBinary(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('subscribed_events', sa.JSON(), nullable=False),
        sa.Column('created_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('failure_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('disabled_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_webhook_endpoints_is_active', 'webhook_endpoints', ['is_active'])

    # 4. Create outbox_events table (Phase 16)
    op.create_table(
        'outbox_events',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('opaque_event_id', sa.String(64), unique=True, nullable=False),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('report_id', sa.Uuid(as_uuid=True), sa.ForeignKey('reports.id', ondelete='SET NULL'), nullable=True),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default='PENDING'),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('next_retry_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('lease_worker_id', sa.String(64), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('dispatched_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_summary', sa.String(500), nullable=True),
    )
    op.create_index('ix_outbox_events_opaque_event_id', 'outbox_events', ['opaque_event_id'])
    op.create_index('ix_outbox_events_event_type', 'outbox_events', ['event_type'])
    op.create_index('ix_outbox_events_report_id', 'outbox_events', ['report_id'])
    op.create_index('ix_outbox_events_created_at', 'outbox_events', ['created_at'])
    op.create_index('ix_outbox_events_status', 'outbox_events', ['status'])
    op.create_index('ix_outbox_events_next_retry_at', 'outbox_events', ['next_retry_at'])
    op.create_index('ix_outbox_events_lease_expires_at', 'outbox_events', ['lease_expires_at'])

    # 5. Create webhook_deliveries table (Phase 16)
    op.create_table(
        'webhook_deliveries',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('outbox_event_id', sa.Uuid(as_uuid=True), sa.ForeignKey('outbox_events.id', ondelete='CASCADE'), nullable=False),
        sa.Column('endpoint_id', sa.Uuid(as_uuid=True), sa.ForeignKey('webhook_endpoints.id', ondelete='CASCADE'), nullable=False),
        sa.Column('opaque_delivery_id', sa.String(64), unique=True, nullable=False),
        sa.Column('attempt_number', sa.Integer(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.Column('error_message', sa.String(500), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_webhook_deliveries_outbox_event_id', 'webhook_deliveries', ['outbox_event_id'])
    op.create_index('ix_webhook_deliveries_endpoint_id', 'webhook_deliveries', ['endpoint_id'])
    op.create_index('ix_webhook_deliveries_opaque_delivery_id', 'webhook_deliveries', ['opaque_delivery_id'])
    op.create_index('ix_webhook_deliveries_delivered_at', 'webhook_deliveries', ['delivered_at'])

    # 6. Create quorum_requests table (Phase 17)
    op.create_table(
        'quorum_requests',
        sa.Column('id', sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column('action_type', sa.String(64), nullable=False),
        sa.Column('target_id', sa.String(64), nullable=True),
        sa.Column('proposal_hash', sa.String(64), nullable=False),
        sa.Column('proposed_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default='PENDING'),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('reason', sa.String(1000), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approved_by_id', sa.Uuid(as_uuid=True), sa.ForeignKey('moderators.id', ondelete='RESTRICT'), nullable=True),
        sa.Column('approval_reason', sa.String(1000), nullable=True),
        sa.Column('approval_signature', sa.String(128), nullable=True),
        sa.CheckConstraint('proposed_by_id != approved_by_id', name='chk_quorum_distinct_operators'),
    )
    op.create_index('ix_quorum_requests_action_type', 'quorum_requests', ['action_type'])
    op.create_index('ix_quorum_requests_target_id', 'quorum_requests', ['target_id'])
    op.create_index('ix_quorum_requests_proposed_by_id', 'quorum_requests', ['proposed_by_id'])
    op.create_index('ix_quorum_requests_status', 'quorum_requests', ['status'])
    op.create_index('ix_quorum_requests_expires_at', 'quorum_requests', ['expires_at'])
    op.create_index('ix_quorum_requests_approved_by_id', 'quorum_requests', ['approved_by_id'])


def downgrade() -> None:
    op.drop_table('quorum_requests')
    op.drop_table('webhook_deliveries')
    op.drop_table('outbox_events')
    op.drop_table('webhook_endpoints')
    op.drop_table('moderator_sessions')

    op.drop_index('ix_moderators_totp_enabled', table_name='moderators')
    op.drop_column('moderators', 'totp_locked_until')
    op.drop_column('moderators', 'failed_totp_attempts')
    op.drop_column('moderators', 'backup_codes')
    op.drop_column('moderators', 'totp_enrolled_at')
    op.drop_column('moderators', 'is_totp_enabled')
    op.drop_column('moderators', 'totp_secret_tag')
    op.drop_column('moderators', 'totp_secret_iv')
    op.drop_column('moderators', 'totp_secret_encrypted')
    op.drop_column('moderators', 'token_version')
