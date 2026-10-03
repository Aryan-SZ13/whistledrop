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


moderator_service = ModeratorService()
