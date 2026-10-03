import logging
from typing import List, Optional, Tuple
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import ReportCategory, ReportStatus
from app.models.report import Report
from app.schemas.moderator import ModeratorReportResponse

logger = logging.getLogger(__name__)


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
        # Enforce bounded pagination
        safe_limit = max(1, min(limit, 100))
        safe_offset = max(0, offset)

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

        # 2. Paginated items query
        stmt = sa.select(Report)
        if filters:
            stmt = stmt.where(*filters)
        stmt = (
            stmt.order_by(Report.created_at.desc(), Report.id.desc())
            .limit(safe_limit)
            .offset(safe_offset)
        )
        result = await db.execute(stmt)
        reports = result.scalars().all()

        # 3. Explicit mapping to moderator response schemas (omitting case_code_digest and internals)
        items = [
            ModeratorReportResponse(
                id=r.id,
                category=r.category,
                description=r.description,
                evidence_url=r.evidence_url,
                status=r.status,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            for r in reports
        ]

        return items, total

    async def get_report_by_id(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Optional[ModeratorReportResponse]:
        """Retrieve a single report by internal UUID with moderator response minimization."""
        stmt = sa.select(Report).where(Report.id == report_id)
        result = await db.execute(stmt)
        r = result.scalar_one_or_none()

        if r is None:
            return None

        return ModeratorReportResponse(
            id=r.id,
            category=r.category,
            description=r.description,
            evidence_url=r.evidence_url,
            status=r.status,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )


moderator_service = ModeratorService()
