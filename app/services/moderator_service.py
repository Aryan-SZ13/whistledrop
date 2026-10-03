from datetime import datetime, timezone
import logging
from typing import List, Optional, Tuple
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.enums import ReportCategory, ReportStatus, ReportUpdateType
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.schemas.moderator import (
    ModeratorReportDetailResponse,
    ModeratorReportResponse,
    ModeratorUpdateResponse,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# Domain Exceptions
# ==============================================================================

class ReportNotFoundError(Exception):
    """Raised when a report is not found by ID."""
    pass


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle transition is attempted."""

    def __init__(self, from_status: ReportStatus, to_status: ReportStatus):
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Invalid report lifecycle transition from {from_status.value} to {to_status.value}."
        )


# Explicit lifecycle transition graph
VALID_TRANSITIONS = {
    ReportStatus.SUBMITTED: {ReportStatus.UNDER_REVIEW},
    ReportStatus.UNDER_REVIEW: {ReportStatus.RESOLVED, ReportStatus.DISMISSED},
    ReportStatus.RESOLVED: set(),
    ReportStatus.DISMISSED: set(),
}


def validate_transition(current_status: ReportStatus, target_status: ReportStatus) -> None:
    """Validate report state transition according to the strict lifecycle state machine.

    Allowed transitions:
        SUBMITTED -> UNDER_REVIEW
        UNDER_REVIEW -> RESOLVED
        UNDER_REVIEW -> DISMISSED

    Terminal states:
        RESOLVED (no further transitions)
        DISMISSED (no further transitions)
    """
    allowed = VALID_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise InvalidStateTransitionError(current_status, target_status)


class ModeratorService:
    """Service layer for internal moderator report management and inspection."""

    async def list_reports(
        self,
        db: AsyncSession,
        *,
        status: Optional[ReportStatus] = None,
        category: Optional[ReportCategory] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[ModeratorReportResponse], int]:
        """List reports with filtering, safe bounded pagination, and deterministic ordering.

        Deterministic ordering: newest reports first by created_at.desc(), with
        report.id.desc() as a stable secondary tie-breaker.

        Returns:
            Tuple[List[ModeratorReportResponse], int]: (items, total_count)
        """
        # Enforce bounded pagination defensively
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        filters = []
        if status is not None:
            filters.append(Report.status == status)
        if category is not None:
            filters.append(Report.category == category)

        # 1. Total count query
        count_stmt = sa.select(sa.func.count(Report.id))
        if filters:
            count_stmt = count_stmt.where(*filters)
        total_res = await db.execute(count_stmt)
        total = total_res.scalar() or 0

        # 2. Paginated items query - least-privilege column selection
        # Strictly selects only fields required by ModeratorReportResponse.
        # Sensitive fields such as case_code_digest and unneeded relations are excluded.
        stmt = sa.select(
            Report.id,
            Report.category,
            Report.description,
            Report.evidence_url,
            Report.status,
            Report.created_at,
            Report.updated_at,
        )
        if filters:
            stmt = stmt.where(*filters)
        stmt = (
            stmt.order_by(Report.created_at.desc(), Report.id.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await db.execute(stmt)
        rows = result.all()

        # 3. Explicit mapping from selected columns to moderator response schemas
        items = [
            ModeratorReportResponse(
                id=row.id,
                category=row.category,
                description=row.description,
                evidence_url=row.evidence_url,
                status=row.status,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        ]

        return items, total

    async def get_report_by_id(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Optional[ModeratorReportResponse]:
        """Retrieve a single report by internal UUID with least-privilege column selection.

        Strictly selects only fields required by ModeratorReportResponse.
        """
        stmt = sa.select(
            Report.id,
            Report.category,
            Report.description,
            Report.evidence_url,
            Report.status,
            Report.created_at,
            Report.updated_at,
        ).where(Report.id == report_id)
        result = await db.execute(stmt)
        row = result.one_or_none()

        if row is None:
            return None

        return ModeratorReportResponse(
            id=row.id,
            category=row.category,
            description=row.description,
            evidence_url=row.evidence_url,
            status=row.status,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    async def get_report_detail_by_id(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Optional[ModeratorReportDetailResponse]:
        """Retrieve a report with its chronological public updates and internal notes.

        Audit log internals and case_code_digest are strictly excluded.
        """
        # 1. Fetch report with least privilege
        report_summary = await self.get_report_by_id(db, report_id)
        if report_summary is None:
            return None

        # 2. Fetch chronological updates (both PUBLIC_UPDATE and INTERNAL_NOTE) with least-privilege column selection
        # Strictly selects only fields required by ModeratorUpdateResponse.
        stmt_updates = (
            sa.select(
                ReportUpdate.id,
                ReportUpdate.message,
                ReportUpdate.type,
                ReportUpdate.created_at,
                ReportUpdate.created_by,
            )
            .where(ReportUpdate.report_id == report_id)
            .order_by(ReportUpdate.created_at.asc(), ReportUpdate.id.asc())
        )
        res_updates = await db.execute(stmt_updates)
        update_rows = res_updates.all()

        update_responses = [
            ModeratorUpdateResponse(
                id=u.id,
                message=u.message,
                type=u.type,
                created_at=u.created_at,
                created_by=u.created_by,
            )
            for u in update_rows
        ]

        return ModeratorReportDetailResponse(
            id=report_summary.id,
            category=report_summary.category,
            description=report_summary.description,
            evidence_url=report_summary.evidence_url,
            status=report_summary.status,
            created_at=report_summary.created_at,
            updated_at=report_summary.updated_at,
            updates=update_responses,
        )

    async def update_report_status(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        new_status: ReportStatus,
        moderator_id: uuid.UUID,
    ) -> ModeratorReportResponse:
        """Atomically transition report status and record audit log entry with row locking.

        Enforces:
        - Row-level locking (SELECT ... FOR UPDATE) against concurrent transitions
        - State machine validation via validate_transition
        - Atomic mutation: Report.status + Report.updated_at + AuditLog in single transaction
        - Safe structured metadata in AuditLog (no credentials, descriptions, or secrets)
        """
        try:
            # 1. Row-level lock to prevent concurrent conflicting state transitions
            stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
            result = await db.execute(stmt)
            report = result.scalar_one_or_none()

            if report is None:
                raise ReportNotFoundError(f"Report {report_id} not found.")

            # 2. State machine validation
            validate_transition(report.status, new_status)

            from_status = report.status
            now = datetime.now(timezone.utc)

            # 3. Apply state mutation
            report.status = new_status
            report.updated_at = now

            # 4. Create structured audit log
            audit = AuditLog(
                report_id=report.id,
                moderator_id=moderator_id,
                action="REPORT_STATUS_CHANGED",
                metadata_={
                    "from_status": from_status.value,
                    "to_status": new_status.value,
                },
            )
            db.add(audit)

            # 5. Commit atomically
            await db.commit()
            await db.refresh(report)

            logger.info(
                "Report status transitioned: report_id=%s, from=%s, to=%s, moderator_id=%s",
                report.id,
                from_status.value,
                new_status.value,
                moderator_id,
            )

            return ModeratorReportResponse(
                id=report.id,
                category=report.category,
                description=report.description,
                evidence_url=report.evidence_url,
                status=report.status,
                created_at=report.created_at,
                updated_at=report.updated_at,
            )
        except Exception:
            await db.rollback()
            raise

    async def add_report_update(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        message: str,
        update_type: ReportUpdateType,
        moderator_id: uuid.UUID,
    ) -> ModeratorUpdateResponse:
        """Atomically create a report update/internal note and record an audit log entry.

        Enforces:
        - Report existence verification
        - Atomic persistence: ReportUpdate + AuditLog + Report.updated_at timestamp bump
        - Safe structured metadata in AuditLog (message text remains in ReportUpdate only)
        """
        try:
            # 1. Verify report exists with lock
            stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
            result = await db.execute(stmt)
            report = result.scalar_one_or_none()

            if report is None:
                raise ReportNotFoundError(f"Report {report_id} not found.")

            now = datetime.now(timezone.utc)
            report.updated_at = now

            # 2. Create ReportUpdate
            update = ReportUpdate(
                report_id=report.id,
                message=message,
                type=update_type,
                created_by=moderator_id,
            )
            db.add(update)
            await db.flush()  # Populates update.id

            # 3. Create structured AuditLog entry (does NOT duplicate message text or secrets)
            audit = AuditLog(
                report_id=report.id,
                moderator_id=moderator_id,
                action="REPORT_UPDATE_CREATED",
                metadata_={
                    "update_id": str(update.id),
                    "update_type": update_type.value,
                },
            )
            db.add(audit)

            # 4. Commit atomically
            await db.commit()
            await db.refresh(update)

            logger.info(
                "Report update created: report_id=%s, type=%s, moderator_id=%s",
                report.id,
                update_type.value,
                moderator_id,
            )

            return ModeratorUpdateResponse(
                id=update.id,
                message=update.message,
                type=update.type,
                created_at=update.created_at,
                created_by=update.created_by,
            )
        except Exception:
            await db.rollback()
            raise


moderator_service = ModeratorService()

