import inspect
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.redis import get_redis
from app.models.case_message import CaseMessage
from app.models.enums import EvidenceScanStatus, EvidenceShredStatus, ReportStatus
from app.models.evidence import EvidenceAttachment
from app.models.report import Report
from app.schemas.export_retention import (
    RetentionExecuteResponse,
    RetentionPreviewItem,
    RetentionPreviewResponse,
    ReportWithdrawResponse,
)
from app.services.audit_service import audit_service
from app.services.shredder_service import shredder_service

logger = logging.getLogger(__name__)

LUA_COMPARE_AND_DELETE = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


class RetentionService:
    def __init__(self) -> None:
        self.lock_key = "lock:retention_execution"

    async def withdraw_report(
        self,
        report_id: uuid.UUID,
        reason: Optional[str],
        db: AsyncSession,
    ) -> ReportWithdrawResponse:
        """
        Processes a whistleblower withdrawal request:
          1. Locks the report row FOR UPDATE.
          2. Idempotently sets report status to WITHDRAWN and sets terminal_at retention clock.
          3. Cryptographically shreds all evidence DEKs immediately in the database.
          4. Appends REPORT_WITHDRAWN and REPORT_CRYPTOGRAPHICALLY_SHREDDED audit log entries.
          5. Commits the database transaction (ATOMIC key destruction + audit record).
          6. Executes best-effort physical evidence file shredding post-commit.
        """
        now = datetime.now(timezone.utc)
        stmt = (
            sa.select(Report)
            .where(Report.id == report_id)
            .with_for_update()
        )
        res = await db.execute(stmt)
        report = res.scalar_one_or_none()
        if not report:
            raise ValueError("Report not found.")

        is_already_withdrawn = report.status == ReportStatus.WITHDRAWN

        if not is_already_withdrawn:
            report.status = ReportStatus.WITHDRAWN
            report.withdrawn_at = now
            report.terminal_at = now + timedelta(days=settings.RETENTION_WITHDRAWN_DAYS)
            report.version_id += 1
            report.status_version += 1
            report.updated_at = now

        # Cryptographically destroy evidence keys in DB
        stmt_ev = (
            sa.select(EvidenceAttachment)
            .where(
                EvidenceAttachment.report_id == report_id,
                EvidenceAttachment.shred_status == EvidenceShredStatus.ACTIVE.value,
            )
            .with_for_update()
        )
        res_ev = await db.execute(stmt_ev)
        attachments_to_shred = res_ev.scalars().all()

        for att in attachments_to_shred:
            att.shred_status = EvidenceShredStatus.KEY_DESTROYED.value
            att.wrapped_dek = None
            att.dek_nonce = None
            att.dek_tag = None
            att.kek_key_id = None
            att.updated_at = now

        # Phase 18: Unified Cryptographic Erasure - destroy case payload encryption DEK
        from app.services.payload_encryption_service import payload_encryption_service
        await payload_encryption_service.destroy_case_dek(db, report_id)

        audit_entry_1 = None
        audit_entry_2 = None

        if not is_already_withdrawn:
            audit_entry_1 = await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action="REPORT_WITHDRAWN",
                actor_type="REPORTER",
                actor_id=None,
                metadata={
                    "reason": reason or "Withdrawn by whistleblower",
                    "withdrawn_at": now.isoformat(),
                    "retention_terminal_at": report.terminal_at.isoformat(),
                },
                created_at=now,
            )

        if attachments_to_shred:
            audit_entry_2 = await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action="REPORT_CRYPTOGRAPHICALLY_SHREDDED",
                actor_type="SYSTEM",
                actor_id=None,
                metadata={
                    "event": "whistleblower_withdrawal",
                    "keys_destroyed": len(attachments_to_shred),
                },
                created_at=now,
            )

        # Publish transactional outbox event
        from app.services.outbox_service import outbox_service
        await outbox_service.publish_event(
            db=db,
            event_type="report.withdrawn",
            report_id=report.id,
            case_code_digest=report.case_code_digest,
            raw_data={"status": report.status.value, "category": report.category.value},
        )

        # Commit DB transaction atomically
        await db.commit()

        # Post-commit best-effort disk removal
        for att in attachments_to_shred:
            self._shred_attachment_files(att)

        latest_hash = (
            audit_entry_2.entry_hash
            if audit_entry_2
            else (audit_entry_1.entry_hash if audit_entry_1 else "0" * 64)
        )

        return ReportWithdrawResponse(
            message="Case has been successfully withdrawn. Evidence encryption keys destroyed.",
            withdrawn_at=report.withdrawn_at or now,
            status=report.status.value,
            terminal_at=report.terminal_at,
            evidence_shred_status=EvidenceShredStatus.KEY_DESTROYED.value,
            latest_audit_hash=latest_hash,
        )

    def _shred_attachment_files(self, att: EvidenceAttachment) -> None:
        """Best-effort file overwrite and unlinking for quarantined and approved storage."""
        quar_path = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{att.storage_key}.bin"
        app_path = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{att.storage_key}.bin"

        shredder_service.best_effort_shred_file(quar_path)
        shredder_service.best_effort_shred_file(app_path)

    async def preview_retention_sweep(
        self, db: AsyncSession, limit: int = 100
    ) -> RetentionPreviewResponse:
        """Evaluates retention status across terminal cases without modifying state."""
        now = datetime.now(timezone.utc)
        stmt = (
            sa.select(Report)
            .where(
                Report.is_shredded.is_(False),
                Report.terminal_at.is_not(None),
                Report.terminal_at <= now,
            )
            .order_by(Report.terminal_at.asc())
            .limit(limit)
        )
        res = await db.execute(stmt)
        reports = res.scalars().all()

        items: List[RetentionPreviewItem] = []
        for r in reports:
            ev_count_stmt = sa.select(sa.func.count(EvidenceAttachment.id)).where(
                EvidenceAttachment.report_id == r.id,
                EvidenceAttachment.shred_status == EvidenceShredStatus.ACTIVE.value,
            )
            ev_count = (await db.execute(ev_count_stmt)).scalar() or 0
            days_past = (now - r.terminal_at).total_seconds() / 86400.0

            items.append(
                RetentionPreviewItem(
                    report_id=str(r.id),
                    status=r.status.value,
                    terminal_at=r.terminal_at,
                    days_past_terminal=round(days_past, 2),
                    evidence_count=ev_count,
                )
            )

        return RetentionPreviewResponse(
            eligible_count=len(items),
            reports=items,
        )

    async def execute_retention_sweep(
        self,
        db_factory,
        limit: Optional[int] = None,
        quorum_context: Optional[Any] = None,
    ) -> RetentionExecuteResponse:
        """
        Executes distributed-locked retention shredding:
          - Requires dual-control Quorum approval when settings.QUORUM_ENFORCE_RETENTION is enabled.
          - Acquires Redis advisory lock with CSPRNG owner token.
          - Sweeps expired terminal reports.
          - Per case: redacts case content, destroys notes, shreds evidence keys, appends audit tombstone.
          - Releases Redis lock via Lua compare-and-delete.
        """
        if settings.QUORUM_ENFORCE_RETENTION and quorum_context is None:
            from app.services.quorum_service import QuorumRequiredException
            raise QuorumRequiredException(
                action_type="MANUAL_RETENTION_SWEEP",
                details={"limit": limit or settings.RETENTION_BATCH_SIZE},
            )
        return await self._run_retention_sweep(db_factory, limit=limit, quorum_context=quorum_context)

    async def execute_retention_sweep_internal(
        self,
        db: AsyncSession,
        limit: Optional[int] = None,
        quorum_context: Optional[Any] = None,
    ) -> RetentionExecuteResponse:
        from app.db.session import async_session_factory
        return await self._run_retention_sweep(async_session_factory, limit=limit, quorum_context=quorum_context)

    async def _run_retention_sweep(
        self,
        db_factory,
        limit: Optional[int] = None,
        quorum_context: Optional[Any] = None,
    ) -> RetentionExecuteResponse:
        batch_limit = limit or settings.RETENTION_BATCH_SIZE
        redis = get_redis()
        if inspect.isawaitable(redis):
            redis = await redis
        owner_token = secrets.token_urlsafe(32)

        # Acquire distributed lock
        acquired = await redis.set(
            self.lock_key,
            owner_token,
            nx=True,
            ex=settings.RETENTION_LOCK_TTL_SECONDS,
        )
        if not acquired:
            logger.info("Retention sweep lock is held by another worker; skipping execution.")
            return RetentionExecuteResponse(
                processed_count=0,
                shredded_evidence_count=0,
                failed_count=0,
                lock_acquired=False,
                details=[],
            )

        processed_count = 0
        shredded_evidence_count = 0
        failed_count = 0
        details: List[Dict[str, Any]] = []

        try:
            # Query candidate report IDs
            now = datetime.now(timezone.utc)
            async with db_factory() as db:
                stmt = (
                    sa.select(Report.id)
                    .where(
                        Report.is_shredded.is_(False),
                        Report.terminal_at.is_not(None),
                        Report.terminal_at <= now,
                    )
                    .order_by(Report.terminal_at.asc())
                    .limit(batch_limit)
                )
                res = await db.execute(stmt)
                candidate_ids = res.scalars().all()

            for report_id in candidate_ids:
                try:
                    async with db_factory() as case_db:
                        # Row-lock report
                        stmt_rep = (
                            sa.select(Report)
                            .where(Report.id == report_id)
                            .with_for_update()
                        )
                        res_rep = await case_db.execute(stmt_rep)
                        report = res_rep.scalar_one_or_none()

                        if not report or report.is_shredded or not report.terminal_at or report.terminal_at > datetime.now(timezone.utc):
                            continue

                        shred_time = datetime.now(timezone.utc)

                        # Redact report description and clear encrypted fields
                        report.description = "[REDACTED PURSUANT TO DATA RETENTION/WITHDRAWAL POLICY]"
                        report.description_encrypted = None
                        report.description_iv = None
                        report.description_tag = None
                        report.description_aad_version = None
                        report.is_shredded = True
                        report.shredded_at = shred_time
                        report.version_id += 1
                        report.updated_at = shred_time

                        # Redact channel messages and clear encrypted fields
                        stmt_msgs = (
                            sa.update(CaseMessage)
                            .where(CaseMessage.report_id == report_id)
                            .values(
                                content="[REDACTED PURSUANT TO DATA RETENTION/WITHDRAWAL POLICY]",
                                content_encrypted=None,
                                content_iv=None,
                                content_tag=None,
                                content_aad_version=None,
                            )
                        )
                        await case_db.execute(stmt_msgs)

                        # Cryptographically destroy evidence keys
                        stmt_evs = (
                            sa.select(EvidenceAttachment)
                            .where(EvidenceAttachment.report_id == report_id)
                            .with_for_update()
                        )
                        res_evs = await case_db.execute(stmt_evs)
                        ev_list = res_evs.scalars().all()

                        for ev in ev_list:
                            ev.shred_status = EvidenceShredStatus.KEY_DESTROYED.value
                            ev.wrapped_dek = None
                            ev.dek_nonce = None
                            ev.dek_tag = None
                            ev.kek_key_id = None
                            ev.updated_at = shred_time

                        # Phase 18: Unified Cryptographic Erasure - destroy case payload encryption DEK
                        from app.services.payload_encryption_service import payload_encryption_service
                        await payload_encryption_service.destroy_case_dek(case_db, report_id)

                        # Append tamper-evident chained audit tombstone
                        await audit_service.append_entry(
                            db=case_db,
                            report_id=report.id,
                            action="REPORT_RETENTION_SHREDDED",
                            actor_type="SYSTEM",
                            actor_id=None,
                            metadata={
                                "terminal_at": report.terminal_at.isoformat(),
                                "shredded_at": shred_time.isoformat(),
                                "evidence_keys_destroyed": len(ev_list),
                            },
                            created_at=shred_time,
                        )

                        # Atomic DB commit
                        await case_db.commit()

                        # Post-commit physical best-effort shredding
                        for ev in ev_list:
                            self._shred_attachment_files(ev)

                        processed_count += 1
                        shredded_evidence_count += len(ev_list)
                        details.append({
                            "report_id": str(report_id),
                            "status": "SHREDDED",
                            "evidence_count": len(ev_list),
                        })

                except Exception as e:
                    logger.error("Failed to shred report %s in retention sweep: %s", report_id, str(e))
                    failed_count += 1
                    details.append({
                        "report_id": str(report_id),
                        "status": "ERROR",
                        "error": str(e),
                    })

        finally:
            # Release Redis lock using Lua compare-and-delete
            try:
                await redis.eval(
                    LUA_COMPARE_AND_DELETE,
                    1,
                    self.lock_key,
                    owner_token,
                )
            except Exception as e:
                logger.error("Failed to release retention execution lock: %s", str(e))

        return RetentionExecuteResponse(
            processed_count=processed_count,
            shredded_evidence_count=shredded_evidence_count,
            failed_count=failed_count,
            lock_acquired=True,
            details=details,
        )


retention_service = RetentionService()
