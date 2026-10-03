import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Header, HTTPException, Path, Request, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import resolve_client_ip
from app.core.config import settings
from app.db.session import get_db
from app.schemas.evidence import EvidenceUploadResponse
from app.schemas.report import (
    ReportCreate,
    ReportCreateResponse,
    ReportTrackingResponse,
)
from app.services.evidence_service import (
    AttachmentQuotaExceededError,
    EvidenceError,
    EvidenceNotFoundError,
    FileValidationError,
    InsufficientStorageError,
    evidence_service,
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


@router.post(
    "/reports/evidence",
    response_model=EvidenceUploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Attach evidence to an existing report",
    description=(
        "Upload one or more evidence file attachments to an existing report using its case code. "
        "Authenticated via the X-Case-Code header. "
        "Case codes and file identifiers are never exposed in URLs or application logs."
    ),
)
async def upload_evidence(
    request: Request,
    files: List[UploadFile] = File(...),
    x_case_code: Optional[str] = Header(
        None,
        alias="X-Case-Code",
        min_length=10,
        max_length=128,
        description="The bearer case code for the report",
    ),
    db: AsyncSession = Depends(get_db),
) -> EvidenceUploadResponse:
    """Anonymous evidence upload endpoint protected by dedicated rate limiting and X-Case-Code auth."""
    # 1. Dedicated rate limit check for evidence uploads
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="upload",
            max_requests=settings.ATTACHMENT_UPLOAD_RATE_LIMIT,
            window_seconds=settings.ATTACHMENT_UPLOAD_RATE_WINDOW_SECONDS,
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

    # 2. Case code header authentication
    # CRITICAL: Never log the raw x_case_code value!
    if not x_case_code or not x_case_code.strip():
        logger.warning("Evidence upload attempted without X-Case-Code header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Case code credential required",
        )

    # 3. Process attachments via EvidenceService
    try:
        accepted_count, total_bytes = await evidence_service.attach_evidence_to_report(
            db=db,
            case_code=x_case_code.strip(),
            files=files,
        )
        return EvidenceUploadResponse(
            status="ACCEPTED",
            attachments_accepted=accepted_count,
            total_bytes=total_bytes,
        )
    except InsufficientStorageError as e:
        logger.error("Insufficient storage for evidence upload: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail="Storage temporarily unavailable",
        )
    except FileValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except AttachmentQuotaExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except EvidenceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except EvidenceError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
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
