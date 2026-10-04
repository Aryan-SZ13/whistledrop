"""add audit hash chain, evidence envelope encryption, and retention fields

Revision ID: f4a8b2c1d3e5
Revises: e3f8a1c92d54
Create Date: 2026-10-04 16:30:00.000000

"""
from typing import Sequence, Union
import hashlib
import hmac
import json
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'f4a8b2c1d3e5'
down_revision: Union[str, None] = 'e3f8a1c92d54'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add WITHDRAWN to report_status_enum if using PostgreSQL
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    if dialect_name == "postgresql":
        op.execute(sa.text("ALTER TYPE report_status_enum ADD VALUE IF NOT EXISTS 'WITHDRAWN'"))

    # 2. Add retention columns to reports
    op.add_column('reports', sa.Column('terminal_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('reports', sa.Column('is_shredded', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('reports', sa.Column('shredded_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('reports', sa.Column('withdrawn_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_reports_terminal_at', 'reports', ['terminal_at'])

    # 3. Add envelope encryption and shredding columns to evidence_attachments
    op.add_column('evidence_attachments', sa.Column('shred_status', sa.String(32), nullable=False, server_default='ACTIVE'))
    op.add_column('evidence_attachments', sa.Column('wrapped_dek', sa.LargeBinary(), nullable=True))
    op.add_column('evidence_attachments', sa.Column('dek_nonce', sa.LargeBinary(), nullable=True))
    op.add_column('evidence_attachments', sa.Column('dek_tag', sa.LargeBinary(), nullable=True))
    op.add_column('evidence_attachments', sa.Column('file_nonce', sa.LargeBinary(), nullable=True))
    op.add_column('evidence_attachments', sa.Column('file_tag', sa.LargeBinary(), nullable=True))
    op.add_column('evidence_attachments', sa.Column('kek_key_id', sa.String(64), nullable=True))
    op.add_column('evidence_attachments', sa.Column('encryption_version', sa.Integer(), nullable=False, server_default='1'))
    op.create_index('ix_evidence_attachments_shred_status', 'evidence_attachments', ['shred_status'])

    # 4. Add hash chain columns to audit_logs
    op.add_column('audit_logs', sa.Column('sequence_number', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('audit_logs', sa.Column('previous_hash', sa.String(64), nullable=True))
    op.add_column('audit_logs', sa.Column('entry_hash', sa.String(64), nullable=True))
    op.add_column('audit_logs', sa.Column('hash_version', sa.Integer(), nullable=False, server_default='1'))

    # 5. Backfill existing audit_logs sequence_number and entry_hash if any exist
    try:
        from app.core.config import settings
        chain_secret = settings.AUDIT_CHAIN_SECRET.encode("utf-8")
    except Exception:
        chain_secret = b"dev-insecure-audit-chain-secret-key-change-in-production-min32"

    domain_sep = b"whistledrop-audit-v1\x00"

    # Query existing audit logs grouped by report_id
    conn = bind
    reports_res = conn.execute(sa.text("SELECT DISTINCT report_id FROM audit_logs WHERE report_id IS NOT NULL"))
    report_ids = [r[0] for r in reports_res.fetchall()]

    for rep_id in report_ids:
        rows_res = conn.execute(
            sa.text(
                "SELECT id, action, metadata, created_at, moderator_id "
                "FROM audit_logs WHERE report_id = :rep_id "
                "ORDER BY created_at ASC, id ASC"
            ),
            {"rep_id": rep_id},
        )
        rows = rows_res.fetchall()
        prev_hash = "GENESIS_HASH_V1_00000000000000000000000000000000000000000000000000000000"
        seq = 1
        for row in rows:
            row_id, action, meta_val, created_at, mod_id = row
            if isinstance(created_at, str):
                created_dt = datetime.fromisoformat(created_at)
            else:
                created_dt = created_at
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            else:
                created_dt = created_dt.astimezone(timezone.utc)
            formatted_dt = created_dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            if meta_val is None:
                canonical_meta = "null"
            elif isinstance(meta_val, str):
                try:
                    parsed = json.loads(meta_val)
                    canonical_meta = json.dumps(parsed, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
                except Exception:
                    canonical_meta = meta_val
            else:
                canonical_meta = json.dumps(meta_val, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

            actor_type = "MODERATOR" if mod_id else "SYSTEM"
            actor_id_str = str(mod_id).lower() if mod_id else "NONE"

            canonical_string = (
                f"hash_version=1\n"
                f"report_id={str(rep_id).lower()}\n"
                f"sequence_number={seq}\n"
                f"created_at={formatted_dt}\n"
                f"action={action.strip()}\n"
                f"actor_type={actor_type}\n"
                f"actor_id={actor_id_str}\n"
                f"previous_hash={prev_hash}\n"
                f"metadata={canonical_meta}\n"
            )
            entry_hash = hmac.new(
                chain_secret,
                domain_sep + canonical_string.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            conn.execute(
                sa.text(
                    "UPDATE audit_logs SET sequence_number = :seq, previous_hash = :prev, entry_hash = :hash "
                    "WHERE id = :id"
                ),
                {"seq": seq, "prev": prev_hash if seq > 1 else None, "hash": entry_hash, "id": row_id},
            )
            prev_hash = entry_hash
            seq += 1

    # Backfill non-report-scoped audit_logs if any
    conn.execute(
        sa.text(
            "UPDATE audit_logs SET entry_hash = '0000000000000000000000000000000000000000000000000000000000000000' "
            "WHERE entry_hash IS NULL"
        )
    )

    # 6. Make entry_hash NOT NULL and create unique constraint
    op.alter_column('audit_logs', 'entry_hash', nullable=False)
    op.create_unique_constraint('uq_audit_logs_report_seq', 'audit_logs', ['report_id', 'sequence_number'])


def downgrade() -> None:
    op.drop_constraint('uq_audit_logs_report_seq', 'audit_logs', type_='unique')
    op.drop_column('audit_logs', 'hash_version')
    op.drop_column('audit_logs', 'entry_hash')
    op.drop_column('audit_logs', 'previous_hash')
    op.drop_column('audit_logs', 'sequence_number')

    op.drop_index('ix_evidence_attachments_shred_status', table_name='evidence_attachments')
    op.drop_column('evidence_attachments', 'encryption_version')
    op.drop_column('evidence_attachments', 'kek_key_id')
    op.drop_column('evidence_attachments', 'file_tag')
    op.drop_column('evidence_attachments', 'file_nonce')
    op.drop_column('evidence_attachments', 'dek_tag')
    op.drop_column('evidence_attachments', 'dek_nonce')
    op.drop_column('evidence_attachments', 'wrapped_dek')
    op.drop_column('evidence_attachments', 'shred_status')

    op.drop_index('ix_reports_terminal_at', table_name='reports')
    op.drop_column('reports', 'withdrawn_at')
    op.drop_column('reports', 'shredded_at')
    op.drop_column('reports', 'is_shredded')
    op.drop_column('reports', 'terminal_at')
