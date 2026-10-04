import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Header, HTTPException, Path, Query, Request, Response, UploadFile, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.client_ip import resolve_client_ip
from app.core.config import settings
from app.core.security import derive_case_code_digest
from app.db.session import get_db
from app.models.enums import MessageSenderType
from app.models.report import Report
from app.schemas.case_message import (
    CaseMessageListResponse,
    CaseMessageResponse,
    CaseNotificationResponse,
    MessageReadAckRequest,
    MessageReadAckResponse,
    NotificationStatusAckRequest,
    NotificationStatusAckResponse,
)
from app.schemas.evidence import EvidenceUploadResponse
from app.schemas.export_retention import (
    ReportVerificationReceiptResponse,
    ReportWithdrawRequest,
    ReportWithdrawResponse,
)
from app.schemas.report import (
    ReportCreate,
    ReportCreateResponse,
    ReportTrackingResponse,
)
from app.services.case_export_service import case_export_service
from app.services.retention_service import retention_service
from app.services.case_channel_service import (
    CaseClosedError,
    InvalidCursorError,
    MessageNotFoundError,
    add_no_store_cache_headers,
    case_channel_service,
    read_and_validate_message_payload,
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


async def get_authenticated_report_by_header(
    x_case_code: Optional[str],
    db: AsyncSession,
) -> Report:
    """Validate X-Case-Code header and return matching report. Never logs plaintext case code."""
    if not x_case_code or not x_case_code.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Case code credential required",
        )
    case_code_digest = derive_case_code_digest(x_case_code.strip())
    stmt = sa.select(Report).where(Report.case_code_digest == case_code_digest)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return report


async def check_channel_rate_limit(
    request: Request,
    report: Report,
    key_prefix: str,
    limit: int,
    window: int,
) -> None:
    """Atomic dual-policy rate limiting across client IP and case credential."""
    client_ip = resolve_client_ip(request)
    try:
        client_policy = RateLimitPolicy(
            key_prefix=f"{key_prefix}_client",
            max_requests=limit,
            window_seconds=window,
        )
        case_policy = RateLimitPolicy(
            key_prefix=f"{key_prefix}_case:{report.case_code_digest}",
            max_requests=limit,
            window_seconds=window,
        )
        limit_result = await rate_limiter.check_multi_rate_limit(
            client_policy=client_policy,
            global_policy=case_policy,
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


@router.post(
    "/reports/messages",
    response_model=CaseMessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit message to anonymous case channel",
    description="Submit a follow-up message to the case conversation channel.",
)
async def post_case_message(
    request: Request,
    response: Response,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> CaseMessageResponse:
    add_no_store_cache_headers(response)
    report = await get_authenticated_report_by_header(x_case_code, db)
    await check_channel_rate_limit(
        request, report, "msg", settings.MESSAGE_RATE_LIMIT, settings.MESSAGE_RATE_WINDOW_SECONDS
    )
    content = await read_and_validate_message_payload(request)
    try:
        msg, is_recovered = await case_channel_service.create_message(
            db=db,
            report_id=report.id,
            sender_type=MessageSenderType.REPORTER,
            content=content,
            idempotency_key=idempotency_key,
        )
    except CaseClosedError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    if is_recovered:
        response.headers["X-Cache-Lookup"] = "HIT"

    return CaseMessageResponse(
        id=msg.public_id,
        sender=msg.sender_type.value,
        content=msg.content,
        created_at=msg.created_at,
    )


@router.get(
    "/reports/messages",
    response_model=CaseMessageListResponse,
    status_code=status.HTTP_200_OK,
    summary="List anonymous case messages",
    description="Retrieve cursor-paginated messages for the case conversation.",
)
async def list_case_messages(
    request: Request,
    response: Response,
    cursor: Optional[str] = Query(None, max_length=512),
    limit: int = Query(20, ge=1, le=100),
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> CaseMessageListResponse:
    add_no_store_cache_headers(response)
    report = await get_authenticated_report_by_header(x_case_code, db)
    await check_channel_rate_limit(
        request, report, "msg_list", settings.MESSAGE_RATE_LIMIT, settings.MESSAGE_RATE_WINDOW_SECONDS
    )
    try:
        return await case_channel_service.list_messages(
            db=db,
            report_id=report.id,
            cursor=cursor,
            limit=limit,
            caller_sender_type=MessageSenderType.REPORTER,
        )
    except InvalidCursorError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post(
    "/reports/messages/read",
    response_model=MessageReadAckResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge message read state",
    description="Monotonically advance the whistleblower message read high-water mark.",
)
async def acknowledge_reporter_messages_read(
    request: Request,
    response: Response,
    read_req: MessageReadAckRequest,
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> MessageReadAckResponse:
    add_no_store_cache_headers(response)
    report = await get_authenticated_report_by_header(x_case_code, db)
    await check_channel_rate_limit(
        request, report, "msg_read", settings.MESSAGE_RATE_LIMIT, settings.MESSAGE_RATE_WINDOW_SECONDS
    )
    try:
        return await case_channel_service.advance_reporter_read_state(
            db=db,
            report_id=report.id,
            public_message_id=read_req.last_read_message_id,
        )
    except MessageNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/reports/notifications",
    response_model=CaseNotificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Poll case notification status",
    description="Pull-based check for unread messages and lifecycle status updates.",
)
async def get_case_notifications(
    request: Request,
    response: Response,
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> CaseNotificationResponse:
    add_no_store_cache_headers(response)
    report = await get_authenticated_report_by_header(x_case_code, db)
    await check_channel_rate_limit(
        request, report, "notif", settings.NOTIFICATION_RATE_LIMIT, settings.NOTIFICATION_RATE_WINDOW_SECONDS
    )
    return await case_channel_service.get_case_notifications(db=db, report=report)


@router.post(
    "/reports/notifications/read",
    response_model=NotificationStatusAckResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge case status notification",
    description="Monotonically acknowledge observed case status version.",
)
async def acknowledge_notification_status(
    request: Request,
    response: Response,
    ack_req: NotificationStatusAckRequest,
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> NotificationStatusAckResponse:
    add_no_store_cache_headers(response)
    report = await get_authenticated_report_by_header(x_case_code, db)
    await check_channel_rate_limit(
        request, report, "notif_read", settings.NOTIFICATION_RATE_LIMIT, settings.NOTIFICATION_RATE_WINDOW_SECONDS
    )
    return await case_channel_service.acknowledge_notification_status(
        db=db,
        report_id=report.id,
        status_version=ack_req.status_version,
    )


@router.get(
    "/reports/verification",
    response_model=ReportVerificationReceiptResponse,
    summary="Get Asymmetrically Verifiable Case Verification Receipt",
    description="Retrieve an Ed25519-signed cryptographic receipt verifying the case's current state and audit sequence.",
)
async def get_case_verification_receipt(
    request: Request,
    response: Response,
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> ReportVerificationReceiptResponse:
    add_no_store_cache_headers(response)
    report = await get_authenticated_report_by_header(x_case_code=x_case_code, db=db)
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="verification",
            max_requests=settings.VERIFICATION_RECEIPT_RATE_LIMIT,
            window_seconds=settings.VERIFICATION_RECEIPT_RATE_WINDOW_SECONDS,
        )
        limit_result = await rate_limiter.check_rate_limit(
            policy=policy,
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

    return await case_export_service.generate_verification_receipt(report=report, db=db)


@router.post(
    "/reports/withdraw",
    response_model=ReportWithdrawResponse,
    summary="Withdraw Whistleblower Case and Cryptographically Destroy Evidence",
    description="Idempotently withdraw case, destroy all evidence encryption keys, and enter retention lifecycle.",
)
async def withdraw_case(
    payload: ReportWithdrawRequest,
    request: Request,
    response: Response,
    x_case_code: Optional[str] = Header(None, alias="X-Case-Code"),
    db: AsyncSession = Depends(get_db),
) -> ReportWithdrawResponse:
    add_no_store_cache_headers(response)
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Withdrawal must be explicitly confirmed with confirm=true.",
        )
    report = await get_authenticated_report_by_header(x_case_code=x_case_code, db=db)
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="withdraw",
            max_requests=settings.WITHDRAWAL_RATE_LIMIT,
            window_seconds=settings.WITHDRAWAL_RATE_WINDOW_SECONDS,
        )
        limit_result = await rate_limiter.check_rate_limit(
            policy=policy,
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

    return await retention_service.withdraw_report(
        report_id=report.id,
        reason=payload.reason,
        db=db,
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
    response: Response,
    case_code: str = Path(
        ...,
        min_length=10,
        max_length=128,
        description="The reusable case code provided upon report submission",
    ),
    db: AsyncSession = Depends(get_db),
) -> ReportTrackingResponse:
    """Endpoint for anonymous report tracking protected by atomic dual-policy rate limiting."""
    add_no_store_cache_headers(response)
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
