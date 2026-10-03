import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import resolve_client_ip
from app.core.config import settings
from app.db.session import get_db
from app.schemas.report import (
    ReportCreate,
    ReportCreateResponse,
    ReportTrackingResponse,
)
from app.services.rate_limiter import (
    RateLimitPolicy,
    RateLimitUnavailableError,
    rate_limiter,
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
    request: Request,
    report_in: ReportCreate,
    db: AsyncSession = Depends(get_db),
) -> ReportCreateResponse:
    """Endpoint for anonymous report ingestion protected by sliding window rate limiting."""
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="submit",
            max_requests=settings.SUBMISSION_RATE_LIMIT,
            window_seconds=settings.SUBMISSION_RATE_WINDOW_SECONDS,
        )
        limit_result = await rate_limiter.check_rate_limit(policy, client_ip)
    except RateLimitUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
        )

    if not limit_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(limit_result.retry_after)},
        )

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
    request: Request,
    case_code: str = Path(
        ...,
        min_length=10,
        max_length=128,
        description="The reusable case code provided upon report submission",
    ),
    db: AsyncSession = Depends(get_db),
) -> ReportTrackingResponse:
    """Endpoint for anonymous report tracking protected by atomic dual-policy rate limiting."""
    client_ip = resolve_client_ip(request)
    try:
        client_policy = RateLimitPolicy(
            key_prefix="lookup",
            max_requests=settings.LOOKUP_RATE_LIMIT,
            window_seconds=settings.LOOKUP_RATE_WINDOW_SECONDS,
        )
        global_policy = RateLimitPolicy(
            key_prefix="lookup_global",
            max_requests=settings.LOOKUP_GLOBAL_RATE_LIMIT,
            window_seconds=settings.LOOKUP_GLOBAL_RATE_WINDOW_SECONDS,
        )
        limit_result = await rate_limiter.check_multi_rate_limit(
            client_policy=client_policy,
            global_policy=global_policy,
            client_ip=client_ip,
        )
    except RateLimitUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
        )

    if not limit_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(limit_result.retry_after)},
        )

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
