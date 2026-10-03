import logging
from typing import Tuple
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import derive_case_code_digest, generate_case_code
from app.models.audit_log import AuditLog
from app.models.enums import ReportStatus
from app.models.report import Report
from app.schemas.report import ReportCreate

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
        6. Return the persisted Report model and the single-use plaintext case code.

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


report_service = ReportService()
