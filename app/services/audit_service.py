"""Tamper-Evident Chain-of-Custody Audit Ledger Service (Phase 13).

Provides sequential HMAC-SHA256 chained audit logging with canonical JSON
serialization, strict row-level concurrency locking, and mathematical chain verification.
"""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, List, Optional, Union
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit_log import AuditLog
from app.models.report import Report

logger = logging.getLogger(__name__)

AUDIT_DOMAIN_SEPARATOR = b"whistledrop-audit-v1\x00"
GENESIS_HASH_V1 = "0" * 64


def format_utc_iso(dt: datetime) -> str:
    """Format datetime as canonical UTC ISO 8601 string with microsecond precision."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def canonicalize_metadata(metadata: Optional[Dict[str, Any]]) -> str:
    """Serialize dictionary metadata to strictly deterministic, sorted canonical JSON."""
    if metadata is None:
        return "null"
    return json.dumps(metadata, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def serialize_canonical_audit_entry(
    hash_version: int,
    report_id: uuid.UUID,
    sequence_number: int,
    created_at: datetime,
    action: str,
    actor_type: str,
    actor_id: Optional[Union[uuid.UUID, str]],
    previous_hash: Optional[str],
    metadata: Optional[Dict[str, Any]],
) -> bytes:
    """Construct deterministic newline-delimited canonical UTF-8 representation of an audit entry."""
    prev_str = previous_hash if previous_hash else GENESIS_HASH_V1
    actor_id_str = str(actor_id).lower() if actor_id else "NONE"
    canonical_meta = canonicalize_metadata(metadata)
    formatted_dt = format_utc_iso(created_at)

    canonical_string = (
        f"hash_version={hash_version}\n"
        f"report_id={str(report_id).lower()}\n"
        f"sequence_number={sequence_number}\n"
        f"created_at={formatted_dt}\n"
        f"action={action.strip()}\n"
        f"actor_type={actor_type.strip()}\n"
        f"actor_id={actor_id_str}\n"
        f"previous_hash={prev_str}\n"
        f"metadata={canonical_meta}\n"
    )
    return canonical_string.encode("utf-8")


def compute_entry_hash(canonical_bytes: bytes, secret: Optional[bytes] = None) -> str:
    """Compute HMAC-SHA256 digest over domain-separated canonical bytes."""
    key = secret or settings.AUDIT_CHAIN_SECRET.encode("utf-8")
    return hmac.new(key, AUDIT_DOMAIN_SEPARATOR + canonical_bytes, hashlib.sha256).hexdigest()


class AuditService:
    """Centralized tamper-evident audit chain service."""

    async def append_entry(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        action: str,
        actor_type: str = "SYSTEM",
        actor_id: Optional[Union[uuid.UUID, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
    ) -> AuditLog:
        """Append a cryptographically chained audit log entry under report row-level locking."""
        # 1. Acquire row lock on the report to serialize concurrent appends for this report
        stmt_lock = sa.select(Report.id).where(Report.id == report_id).with_for_update()
        await db.execute(stmt_lock)

        # 2. Fetch the latest sequence number and entry hash for this report
        stmt_last = (
            sa.select(AuditLog.sequence_number, AuditLog.entry_hash)
            .where(AuditLog.report_id == report_id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(1)
        )
        res_last = await db.execute(stmt_last)
        last_row = res_last.one_or_none()

        if last_row is None:
            seq = 1
            prev_hash = GENESIS_HASH_V1
        else:
            seq = last_row[0] + 1
            prev_hash = last_row[1]

        now = created_at or datetime.now(timezone.utc)

        # Determine moderator_id column value
        mod_id = None
        if actor_type == "MODERATOR" and actor_id:
            if isinstance(actor_id, uuid.UUID):
                mod_id = actor_id
            else:
                try:
                    mod_id = uuid.UUID(str(actor_id))
                except Exception:
                    pass

        actor_type_str = "MODERATOR" if mod_id else "SYSTEM"

        # 3. Canonicalize and hash
        canonical_bytes = serialize_canonical_audit_entry(
            hash_version=1,
            report_id=report_id,
            sequence_number=seq,
            created_at=now,
            action=action,
            actor_type=actor_type_str,
            actor_id=mod_id,
            previous_hash=prev_hash,
            metadata=metadata,
        )
        entry_hash = compute_entry_hash(canonical_bytes)

        log_entry = AuditLog(
            report_id=report_id,
            sequence_number=seq,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            hash_version=1,
            moderator_id=mod_id,
            action=action.strip(),
            metadata_=metadata,
            created_at=now,
        )
        db.add(log_entry)
        await db.flush()
        return log_entry

    async def verify_report_audit_chain(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Dict[str, Any]:
        """Verify the mathematical continuity and HMAC integrity of the audit chain for a report."""
        stmt = (
            sa.select(AuditLog)
            .where(AuditLog.report_id == report_id)
            .order_by(AuditLog.sequence_number.asc())
        )
        res = await db.execute(stmt)
        entries = res.scalars().all()

        if not entries:
            return {
                "report_id": str(report_id),
                "is_valid": True,
                "chain_intact": True,
                "total_entries": 0,
                "verified_up_to_sequence": 0,
                "tamper_detected": False,
                "broken_sequence_number": None,
                "error_detail": None,
                "discrepancy_details": None,
                "latest_entry_hash": None,
                "latest_audit_hash": None,
            }

        expected_seq = 1
        prev_hash: Optional[str] = None

        for entry in entries:
            # 1. Monotonic sequence check
            if entry.sequence_number != expected_seq:
                msg = f"Sequence gap or collision at {entry.sequence_number}; expected {expected_seq}"
                return {
                    "report_id": str(report_id),
                    "is_valid": False,
                    "chain_intact": False,
                    "total_entries": len(entries),
                    "verified_up_to_sequence": expected_seq - 1,
                    "tamper_detected": True,
                    "broken_sequence_number": entry.sequence_number,
                    "failing_sequence_number": entry.sequence_number,
                    "error_detail": msg,
                    "discrepancy_details": msg,
                    "latest_entry_hash": prev_hash,
                    "latest_audit_hash": prev_hash,
                }

            # 2. Hash version check
            if entry.hash_version != 1:
                msg = f"Unsupported hash_version {entry.hash_version} at sequence {entry.sequence_number}"
                return {
                    "report_id": str(report_id),
                    "is_valid": False,
                    "chain_intact": False,
                    "total_entries": len(entries),
                    "verified_up_to_sequence": expected_seq - 1,
                    "tamper_detected": True,
                    "broken_sequence_number": entry.sequence_number,
                    "failing_sequence_number": entry.sequence_number,
                    "error_detail": msg,
                    "discrepancy_details": msg,
                    "latest_entry_hash": prev_hash,
                    "latest_audit_hash": prev_hash,
                }

            # 3. Previous hash continuity check
            if expected_seq == 1:
                if entry.previous_hash != GENESIS_HASH_V1 and entry.previous_hash is not None:
                    msg = f"Invalid genesis previous_hash at sequence 1: {entry.previous_hash}"
                    return {
                        "report_id": str(report_id),
                        "is_valid": False,
                        "chain_intact": False,
                        "total_entries": len(entries),
                        "verified_up_to_sequence": 0,
                        "tamper_detected": True,
                        "broken_sequence_number": 1,
                        "failing_sequence_number": 1,
                        "error_detail": msg,
                        "discrepancy_details": msg,
                        "latest_entry_hash": None,
                        "latest_audit_hash": None,
                    }
            else:
                if entry.previous_hash != prev_hash:
                    msg = f"Broken previous_hash chain at sequence {entry.sequence_number}. Expected {prev_hash}, found {entry.previous_hash}"
                    return {
                        "report_id": str(report_id),
                        "is_valid": False,
                        "chain_intact": False,
                        "total_entries": len(entries),
                        "verified_up_to_sequence": expected_seq - 1,
                        "tamper_detected": True,
                        "broken_sequence_number": entry.sequence_number,
                        "failing_sequence_number": entry.sequence_number,
                        "error_detail": msg,
                        "discrepancy_details": msg,
                        "latest_entry_hash": prev_hash,
                        "latest_audit_hash": prev_hash,
                    }

            # 4. HMAC integrity check
            actor_type_str = "MODERATOR" if entry.moderator_id else "SYSTEM"
            canonical_bytes = serialize_canonical_audit_entry(
                hash_version=entry.hash_version,
                report_id=report_id,
                sequence_number=entry.sequence_number,
                created_at=entry.created_at,
                action=entry.action,
                actor_type=actor_type_str,
                actor_id=entry.moderator_id,
                previous_hash=entry.previous_hash,
                metadata=entry.metadata_,
            )
            expected_hash = compute_entry_hash(canonical_bytes)

            if not hmac.compare_digest(entry.entry_hash, expected_hash):
                msg = f"HMAC mismatch at sequence {entry.sequence_number}. Stored: {entry.entry_hash}, computed: {expected_hash}"
                return {
                    "report_id": str(report_id),
                    "is_valid": False,
                    "chain_intact": False,
                    "total_entries": len(entries),
                    "verified_up_to_sequence": expected_seq - 1,
                    "tamper_detected": True,
                    "broken_sequence_number": entry.sequence_number,
                    "failing_sequence_number": entry.sequence_number,
                    "error_detail": msg,
                    "discrepancy_details": msg,
                    "latest_entry_hash": prev_hash,
                    "latest_audit_hash": prev_hash,
                }

            prev_hash = entry.entry_hash
            expected_seq += 1

        return {
            "report_id": str(report_id),
            "is_valid": True,
            "chain_intact": True,
            "total_entries": len(entries),
            "verified_up_to_sequence": len(entries),
            "tamper_detected": False,
            "broken_sequence_number": None,
            "error_detail": None,
            "discrepancy_details": None,
            "latest_entry_hash": prev_hash,
            "latest_audit_hash": prev_hash,
        }

    verify_chain = verify_report_audit_chain

    def compute_entry_hash(
        self,
        hash_version: int,
        report_id: Any,
        sequence_number: int,
        created_at_iso: str,
        action: str,
        actor_id: Optional[Union[uuid.UUID, str]] = None,
        actor_role: str = "SYSTEM",
        details: Optional[Dict[str, Any]] = None,
        previous_hash: Optional[str] = None,
    ) -> str:
        dt = datetime.fromisoformat(created_at_iso)
        canonical = serialize_canonical_audit_entry(
            hash_version=hash_version,
            report_id=report_id if isinstance(report_id, uuid.UUID) else uuid.UUID(str(report_id)),
            sequence_number=sequence_number,
            created_at=dt,
            action=action,
            actor_type=actor_role,
            actor_id=actor_id,
            previous_hash=previous_hash,
            metadata=details,
        )
        return compute_entry_hash(canonical)


audit_service = AuditService()
