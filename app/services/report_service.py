import logging
from typing import Optional, Tuple
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import derive_case_code_digest, generate_case_code
from app.models.audit_log import AuditLog
from app.models.enums import ReportStatus, ReportUpdateType
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.schemas.report import (
    ReportCreate,
    ReportTrackingResponse,
    ReportUpdatePublic,
)

logger = logging.getLogger(__name__)


class ReportService:
    """Business logic for anonymous report submission and management."""

    async def create_report(
        self,
        db: AsyncSession,
        report_in: ReportCreate,
    ) -> Tuple[Report, str]:
        """Create a new anonymous report atomically within a database transaction.

        Flow:
        1. Generate a high-entropy case code using CSPRNG.
        2. Derive HMAC-SHA256 digest using CASE_CODE_SECRET.
        3. Persist the Report model record with status SUBMITTED (storing only digest).
        4. Persist an AuditLog record (excluding case code, description, and client metadata).
        5. Atomically commit the transaction.
        6. Return the persisted Report model and the reusable plaintext case code.

        Returns:
            Tuple[Report, str]: The persisted report model and the plaintext case code.
        """
        # 1. Generate case code using cryptographically secure RNG
        case_code = generate_case_code()

        # 2. Derive HMAC digest using CASE_CODE_SECRET
        case_code_digest = derive_case_code_digest(case_code)

        try:
            # 3. Create Report model instance (only storing digest, never plaintext case code)
            evidence_url_str = str(report_in.evidence_url) if report_in.evidence_url else None
            report = Report(
                case_code_digest=case_code_digest,
                category=report_in.category,
                description=report_in.description,
                evidence_url=evidence_url_str,
                status=ReportStatus.SUBMITTED,
            )
            db.add(report)
            await db.flush()  # Populates report.id for internal audit log linkage

            # 4. Create safe audit log entry (no case codes, digests, descriptions, or PII)
            audit_log = AuditLog(
                report_id=report.id,
                moderator_id=None,
                action="REPORT_SUBMITTED",
                metadata_={
                    "category": report.category.value,
                    "has_evidence": bool(report.evidence_url),
                },
            )
            db.add(audit_log)

            # 5. Commit both records atomically
            await db.commit()
            await db.refresh(report)

            # 6. Minimal operational logging: log ONLY high-level category count/status.
            # NEVER log case codes, digests, descriptions, evidence URLs, or auth tokens.
            logger.info("Report submitted successfully: category=%s", report.category.value)

            return report, case_code

        except Exception as e:
            await db.rollback()
            logger.error("Failed to submit anonymous report, transaction rolled back: %s", str(e))
            raise

    async def get_report_tracking(
        self,
        db: AsyncSession,
        case_code: str,
    ) -> Optional[ReportTrackingResponse]:
        """Retrieve the public tracking state of a report by its case code.

        Flow:
        1. Normalize case code by stripping whitespace.
        2. Derive HMAC-SHA256 digest using CASE_CODE_SECRET.
        3. Perform indexed lookup on reports.case_code_digest.
        4. If found, retrieve chronological public updates without moderator/audit details.
        5. Map to public ReportTrackingResponse schema with strict field minimization.

        Returns:
            Optional[ReportTrackingResponse]: Public tracking schema if found, None otherwise.
        """
        if not case_code:
            return None

        # 1. Normalize case code where intended
        normalized_code = case_code.strip()
        if not normalized_code:
            return None

        # 2. Derive HMAC digest using centralized security function
        case_code_digest = derive_case_code_digest(normalized_code)

        # 3. Query report by indexed digest
        stmt = sa.select(Report).where(Report.case_code_digest == case_code_digest)
        result = await db.execute(stmt)
        report = result.scalar_one_or_none()

        if report is None:
            return None

        # 4. Query chronological public updates with least-privilege column selection
        # Strictly selects only message and created_at, filtering by PUBLIC_UPDATE.
        stmt_updates = (
            sa.select(
                ReportUpdate.message,
                ReportUpdate.created_at,
            )
            .where(
                ReportUpdate.report_id == report.id,
                ReportUpdate.type == ReportUpdateType.PUBLIC_UPDATE,
            )
            .order_by(ReportUpdate.created_at.asc(), ReportUpdate.id.asc())
        )
        res_updates = await db.execute(stmt_updates)
        update_rows = res_updates.all()

        # 5. Construct public tracking response with strict field minimization
        public_updates = [
            ReportUpdatePublic(
                message=u.message,
                created_at=u.created_at,
            )
            for u in update_rows
        ]

        return ReportTrackingResponse(
            status=report.status,
            updates=public_updates,
        )


report_service = ReportService()
