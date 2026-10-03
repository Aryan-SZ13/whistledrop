import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_moderator
from app.db.session import get_db
from app.models.enums import ReportCategory, ReportStatus
from app.models.moderator import Moderator
from app.schemas.evidence import (
    EvidenceModeratorListResponse,
    EvidenceModeratorResponse,
)
from app.schemas.moderator import (
    ModeratorReportDetailResponse,
    ModeratorReportListResponse,
    ModeratorReportResponse,
    ModeratorUpdateCreate,
    ModeratorUpdateResponse,
    ReportStatusUpdateRequest,
)
from app.services.evidence_service import (
    EvidenceNotAvailableError,
    EvidenceNotFoundError,
    evidence_service,
)
from app.services.moderator_service import (
    InvalidStateTransitionError,
    ReportNotFoundError,
    moderator_service,
)

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
    response_model=ModeratorReportDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect single report with updates",
    description="Retrieve detailed moderation view for a specific report including chronological public updates and internal notes.",
)
async def get_report(
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportDetailResponse:
    """Inspect an individual report with its updates by UUID for authorized moderators."""
    report = await moderator_service.get_report_detail_by_id(db, report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return report


@router.patch(
    "/reports/{report_id}/status",
    response_model=ModeratorReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Update report lifecycle status",
    description="Transition a report to a new lifecycle status according to strict state machine rules.",
)
async def update_report_status(
    status_update: ReportStatusUpdateRequest,
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportResponse:
    """Update report lifecycle status atomically with audit logging."""
    try:
        updated = await moderator_service.update_report_status(
            db=db,
            report_id=report_id,
            new_status=status_update.status,
            moderator_id=current_moderator.id,
        )
        return updated
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except InvalidStateTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.post(
    "/reports/{report_id}/updates",
    response_model=ModeratorUpdateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Post update or internal note",
    description="Post a public timeline update or an internal review note to a report.",
)
async def add_report_update(
    update_in: ModeratorUpdateCreate,
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorUpdateResponse:
    """Post an update or note to a report atomically with audit logging."""
    try:
        result = await moderator_service.add_report_update(
            db=db,
            report_id=report_id,
            message=update_in.message,
            update_type=update_in.type,
            moderator_id=current_moderator.id,
        )
        return result
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )


@router.get(
    "/reports/{report_id}/evidence",
    response_model=EvidenceModeratorListResponse,
    status_code=status.HTTP_200_OK,
    summary="List evidence attachments for a report",
    description="Retrieve all evidence attachments associated with a report for authorized moderators.",
)
async def list_report_evidence(
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> EvidenceModeratorListResponse:
    """Retrieve metadata for all attachments linked to the report, with synthetic display names."""
    report = await moderator_service.get_report_by_id(db=db, report_id=report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    evidence_items = await evidence_service.list_evidence_for_report(db=db, report_id=report_id)
    responses = [
        EvidenceModeratorResponse(
            id=item.id,
            detected_mime=item.detected_mime,
            file_size=item.file_size,
            scan_status=item.scan_status,
            created_at=item.created_at,
            display_name=display_name,
        )
        for item, display_name in evidence_items
    ]
    return EvidenceModeratorListResponse(items=responses, total=len(responses))


@router.get(
    "/reports/{report_id}/evidence/{evidence_id}",
    status_code=status.HTTP_200_OK,
    summary="Download clean evidence attachment",
    description="Stream a verified, clean evidence file attachment for an authorized moderator.",
)
async def download_report_evidence(
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    evidence_id: uuid.UUID = Path(..., description="Internal evidence attachment UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
):
    """Stream clean evidence file to authorized moderator with download disposition and nosniff."""
    try:
        file_path, detected_mime, display_name = await evidence_service.get_clean_evidence_for_download(
            db=db,
            report_id=report_id,
            evidence_id=evidence_id,
        )
        return FileResponse(
            path=str(file_path),
            media_type=detected_mime,
            filename=display_name,
            headers={
                "Content-Disposition": f'attachment; filename="{display_name}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-cache, no-store, must-revalidate",
            },
        )
    except EvidenceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence attachment not found",
        )
    except EvidenceNotAvailableError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Evidence attachment not available",
        )

