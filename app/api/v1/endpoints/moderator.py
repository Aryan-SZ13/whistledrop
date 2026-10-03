import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_moderator
from app.db.session import get_db
from app.models.enums import ReportCategory, ReportStatus
from app.models.moderator import Moderator
from app.schemas.moderator import (
    ModeratorReportListResponse,
    ModeratorReportResponse,
)
from app.services.moderator_service import moderator_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/reports",
    response_model=ModeratorReportListResponse,
    status_code=status.HTTP_200_OK,
    summary="List and filter reports",
    description=(
        "Retrieve paginated reports for internal moderation. "
        "Supports filtering by status and category with deterministic ordering."
    ),
)
async def list_reports(
    status_filter: Optional[ReportStatus] = Query(None, alias="status", description="Filter by report status"),
    category_filter: Optional[ReportCategory] = Query(None, alias="category", description="Filter by report category"),
    limit: int = Query(20, ge=1, le=100, description="Page limit (max 100)"),
    offset: int = Query(0, ge=0, description="Page offset index"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportListResponse:
    """List reports for authorized moderators with safe bounded pagination."""
    items, total = await moderator_service.list_reports(
        db,
        status=status_filter,
        category=category_filter,
        limit=limit,
        offset=offset,
    )
    return ModeratorReportListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/reports/{report_id}",
    response_model=ModeratorReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect single report",
    description="Retrieve detailed moderation view for a specific report by internal UUID.",
)
async def get_report(
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportResponse:
    """Inspect an individual report by UUID for authorized moderators."""
    report = await moderator_service.get_report_by_id(db, report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return report
