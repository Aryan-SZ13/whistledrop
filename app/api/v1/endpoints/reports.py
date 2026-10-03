import logging
from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.report import (
    ReportCreate,
    ReportCreateResponse,
    ReportTrackingResponse,
)
from app.services.report_service import report_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/reports",
    response_model=ReportCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit anonymous report",
    description=(
        "Submit an anonymous whistleblower incident report. "
        "Returns a unique case code (bearer credential) shown only once for status tracking. "
        "Internal database identifiers are not exposed."
    ),
)
async def submit_report(
    report_in: ReportCreate,
    db: AsyncSession = Depends(get_db),
) -> ReportCreateResponse:
    """Endpoint for anonymous report ingestion."""
    report, case_code = await report_service.create_report(db=db, report_in=report_in)
    return ReportCreateResponse(
        case_code=case_code,
        status=report.status,
        created_at=report.created_at,
    )


@router.get(
    "/reports/{case_code}",
    response_model=ReportTrackingResponse,
    status_code=status.HTTP_200_OK,
    summary="Track anonymous report status",
    description=(
        "Retrieve the current lifecycle status and public timeline updates for a submitted report "
        "using its case code as a reusable bearer credential. "
        "Internal database identifiers, descriptions, evidence URLs, and moderator identities are not exposed."
    ),
)
async def track_report(
    case_code: str = Path(
        ...,
        min_length=10,
        max_length=128,
        description="The reusable case code provided upon report submission",
    ),
    db: AsyncSession = Depends(get_db),
) -> ReportTrackingResponse:
    """Endpoint for anonymous report tracking."""
    try:
        tracking = await report_service.get_report_tracking(db=db, case_code=case_code)
    except Exception as e:
        logger.error("Internal error during report tracking: %s", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while tracking the report.",
        )

    if tracking is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return tracking
