from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.report import ReportCreate, ReportCreateResponse
from app.services.report_service import report_service

router = APIRouter()


@router.post(
    "/reports",
    response_model=ReportCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit anonymous report",
    description=(
        "Submit an anonymous whistleblower incident report. "
        "Returns a unique case code (bearer credential) shown only once for status tracking."
    ),
)
async def submit_report(
    report_in: ReportCreate,
    db: AsyncSession = Depends(get_db),
) -> ReportCreateResponse:
    """Endpoint for anonymous report ingestion."""
    report, case_code = await report_service.create_report(db=db, report_in=report_in)
    return ReportCreateResponse(
        id=report.id,
        case_code=case_code,
        status=report.status,
        created_at=report.created_at,
    )
