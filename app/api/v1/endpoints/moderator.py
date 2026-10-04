from datetime import datetime, timezone
import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.api.deps import require_admin, require_moderator
from app.core.client_ip import resolve_client_ip
from app.core.config import settings
from app.db.session import async_session_maker, get_db
from app.models.enums import MessageSenderType, ReportCategory, ReportPriority, ReportStatus
from app.models.moderator import Moderator
from app.models.report import Report
from app.schemas.case_message import (
    CaseMessageListResponse,
    CaseMessageResponse,
    MessageReadAckRequest,
    MessageReadAckResponse,
)
from app.schemas.evidence import (
    EvidenceModeratorListResponse,
    EvidenceModeratorResponse,
)
from app.schemas.export_retention import (
    AuditChainVerifyResponse,
    RetentionExecuteRequest,
    RetentionExecuteResponse,
    RetentionPreviewResponse,
)
from app.schemas.moderator import (
    DashboardStatsResponse,
    ModeratorReportDetailResponse,
    ModeratorReportListResponse,
    ModeratorReportResponse,
    ModeratorUpdateCreate,
    ModeratorUpdateResponse,
    ReportAssignmentUpdateRequest,
    ReportPriorityUpdateRequest,
    ReportStatusUpdateRequest,
    TimelineListResponse,
)
from app.services.audit_service import audit_service
from app.services.case_channel_service import (
    CaseClosedError,
    InvalidCursorError as ChannelInvalidCursorError,
    MessageNotFoundError as ChannelMessageNotFoundError,
    case_channel_service,
    read_and_validate_message_payload,
)
from app.services.case_export_service import (
    CaseExportError,
    CaseShreddedError,
    case_export_service,
)
from app.services.evidence_service import (
    EvidenceNotAvailableError,
    EvidenceNotFoundError,
    evidence_service,
)
from app.services.moderator_service import (
    InvalidAssignmentError,
    InvalidCursorError,
    InvalidStateTransitionError,
    ReportNotFoundError,
    UnauthorizedActionError,
    VersionConflictError,
    moderator_service,
)
from app.services.rate_limiter import (
    RateLimitPolicy,
    RateLimitUnavailableError,
    rate_limiter,
)
from app.schemas.canary import AdminCheckInRequest, EmergencySealRequest, SecurityStateResponse
from app.services.canary_service import canary_service
from app.services.mfa_service import mfa_service
from app.services.payload_encryption_service import payload_encryption_service
from app.services.retention_service import retention_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/dashboard/stats",
    response_model=DashboardStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get case management dashboard stats",
    description="Retrieve consolidated dashboard aggregate metrics.",
)
async def get_dashboard_stats(
    since: Optional[datetime] = Query(None, description="Optional lower bound datetime filter (max 90 days)"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> DashboardStatsResponse:
    """Retrieve aggregate dashboard metrics for active moderators."""
    if since is not None:
        now = datetime.now(timezone.utc)
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        if (now - since).days > 90:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="The 'since' parameter cannot be older than 90 days.",
            )

    return await moderator_service.get_dashboard_stats(
        db,
        current_moderator_id=current_moderator.id,
        since=since,
    )


@router.get(
    "/reports",
    response_model=ModeratorReportListResponse,
    status_code=status.HTTP_200_OK,
    summary="List and filter reports",
    description=(
        "Retrieve paginated reports for internal moderation. "
        "Supports multi-field filtering, search, and sorting."
    ),
)
async def list_reports(
    status_filter: Optional[ReportStatus] = Query(None, alias="status", description="Filter by report status"),
    category_filter: Optional[ReportCategory] = Query(None, alias="category", description="Filter by report category"),
    priority_filter: Optional[ReportPriority] = Query(None, alias="priority", description="Filter by report priority"),
    assigned_to: Optional[uuid.UUID] = Query(None, description="Filter by assigned moderator UUID"),
    unassigned: Optional[bool] = Query(None, description="Filter by unassigned status"),
    search: Optional[str] = Query(None, min_length=1, max_length=200, description="Safe text search on description"),
    has_evidence: Optional[bool] = Query(None, description="Filter by presence of approved evidence attachments"),
    date_from: Optional[datetime] = Query(None, description="Filter reports created after or on this timestamp"),
    date_to: Optional[datetime] = Query(None, description="Filter reports created before or on this timestamp"),
    sort_by: str = Query("created_at", pattern="^(created_at|updated_at|priority|status)$", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort direction"),
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
        priority=priority_filter,
        assigned_to=assigned_to,
        unassigned=unassigned,
        search=search,
        has_evidence=has_evidence,
        date_from=date_from,
        date_to=date_to,
        sort_by=sort_by,
        sort_order=sort_order,
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
    description="Transition a report to a new lifecycle status with mandatory OCC and role enforcement.",
)
async def update_report_status(
    status_update: ReportStatusUpdateRequest,
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportResponse:
    """Update report lifecycle status atomically with audit logging and OCC."""
    try:
        updated = await moderator_service.update_report_status(
            db=db,
            report_id=report_id,
            new_status=status_update.status,
            expected_version=status_update.expected_version,
            moderator=current_moderator,
            reopen_reason=status_update.reopen_reason,
        )
        return updated
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except VersionConflictError as e:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": str(e), "current_version": e.current_version},
        )
    except UnauthorizedActionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except InvalidStateTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@router.patch(
    "/reports/{report_id}/priority",
    response_model=ModeratorReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Update report priority",
    description="Update a report's priority level with mandatory OCC.",
)
async def update_report_priority(
    priority_update: ReportPriorityUpdateRequest,
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportResponse:
    """Update report priority atomically with audit logging and OCC."""
    try:
        updated = await moderator_service.update_report_priority(
            db=db,
            report_id=report_id,
            new_priority=priority_update.priority,
            expected_version=priority_update.expected_version,
            moderator=current_moderator,
        )
        return updated
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except VersionConflictError as e:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": str(e), "current_version": e.current_version},
        )
    except InvalidStateTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@router.patch(
    "/reports/{report_id}/assignment",
    response_model=ModeratorReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Update report assignment",
    description="Assign or unassign a report with mandatory OCC and role authorization.",
)
async def update_report_assignment(
    assignment_update: ReportAssignmentUpdateRequest,
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorReportResponse:
    """Assign or unassign report atomically with audit logging and OCC."""
    try:
        updated = await moderator_service.update_report_assignment(
            db=db,
            report_id=report_id,
            target_moderator_id=assignment_update.moderator_id,
            expected_version=assignment_update.expected_version,
            moderator=current_moderator,
        )
        return updated
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except VersionConflictError as e:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": str(e), "current_version": e.current_version},
        )
    except UnauthorizedActionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except InvalidAssignmentError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@router.post(
    "/reports/{report_id}/updates",
    response_model=ModeratorUpdateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Post update or internal note",
    description="Post a public timeline update or an internal review note to a report with mandatory OCC.",
)
async def add_report_update(
    update_in: ModeratorUpdateCreate,
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> ModeratorUpdateResponse:
    """Post an update or note to a report atomically with audit logging and OCC."""
    try:
        result = await moderator_service.add_report_update(
            db=db,
            report_id=report_id,
            message=update_in.message,
            update_type=update_in.type,
            expected_version=update_in.expected_version,
            moderator_id=current_moderator.id,
        )
        return result
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except VersionConflictError as e:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": str(e), "current_version": e.current_version},
        )
    except InvalidStateTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@router.get(
    "/reports/{report_id}/timeline",
    response_model=TimelineListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get case timeline with cursor pagination",
    description="Retrieve unified chronological case activity timeline using cursor pagination.",
)
async def get_case_timeline(
    report_id: uuid.UUID = Path(..., description="Internal report UUID"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    cursor: Optional[str] = Query(None, max_length=512, description="Opaque cursor string for pagination"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> TimelineListResponse:
    """Retrieve cursor-paginated timeline for authorized moderators."""
    try:
        return await moderator_service.get_case_timeline(
            db=db,
            report_id=report_id,
            limit=limit,
            cursor=cursor,
        )
    except ReportNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    except InvalidCursorError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
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
        content_bytes, detected_mime, display_name = await evidence_service.get_clean_evidence_for_download(
            db=db,
            report_id=report_id,
            evidence_id=evidence_id,
        )
        return Response(
            content=content_bytes,
            media_type=detected_mime,
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


@router.get(
    "/reports/{report_id}/messages",
    response_model=CaseMessageListResponse,
    status_code=status.HTTP_200_OK,
    summary="List messages for a report",
    description="Retrieve cursor-paginated messages for a case conversation as an authorized moderator.",
)
async def list_report_messages_for_moderator(
    report_id: uuid.UUID = Path(..., description="Report UUID"),
    cursor: Optional[str] = Query(None, max_length=512),
    limit: int = Query(20, ge=1, le=100),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> CaseMessageListResponse:
    stmt = sa.select(Report).where(Report.id == report_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    try:
        return await case_channel_service.list_messages(
            db=db,
            report_id=report_id,
            cursor=cursor,
            limit=limit,
            caller_sender_type=MessageSenderType.MODERATOR,
            moderator_id=current_moderator.id,
        )
    except ChannelInvalidCursorError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post(
    "/reports/{report_id}/messages",
    response_model=CaseMessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Post public reply to whistleblower",
    description="Post a public moderator reply to the anonymous case channel.",
)
async def post_moderator_message(
    request: Request,
    response: Response,
    report_id: uuid.UUID = Path(..., description="Report UUID"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> CaseMessageResponse:
    content = await read_and_validate_message_payload(request)
    try:
        msg, is_recovered = await case_channel_service.create_message(
            db=db,
            report_id=report_id,
            sender_type=MessageSenderType.MODERATOR,
            content=content,
            moderator=current_moderator,
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


@router.post(
    "/reports/{report_id}/messages/read",
    response_model=MessageReadAckResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge moderator message read state",
    description="Monotonically advance the moderator's read high-water mark for this report.",
)
async def acknowledge_moderator_messages_read(
    read_req: MessageReadAckRequest,
    report_id: uuid.UUID = Path(..., description="Report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> MessageReadAckResponse:
    try:
        return await case_channel_service.advance_moderator_read_state(
            db=db,
            report_id=report_id,
            moderator_id=current_moderator.id,
            public_message_id=read_req.last_read_message_id,
        )
    except ChannelMessageNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/reports/{report_id}/audit/verify",
    response_model=AuditChainVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify report audit log chain",
    description="Validates the sequential HMAC-SHA256 audit log integrity for the given report.",
)
async def verify_report_audit_chain(
    request: Request,
    report_id: uuid.UUID = Path(..., description="Report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> AuditChainVerifyResponse:
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="audit_verify",
            max_requests=settings.AUDIT_VERIFY_RATE_LIMIT,
            window_seconds=settings.AUDIT_VERIFY_RATE_WINDOW_SECONDS,
        )
        limit_res = await rate_limiter.check_rate_limit(
            policy=policy,
            client_ip=client_ip,
        )
    except RateLimitUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
        )
    if not limit_res.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(limit_res.retry_after)},
        )

    res = await audit_service.verify_chain(db=db, report_id=report_id)
    return AuditChainVerifyResponse(**res)


@router.get(
    "/reports/{report_id}/export",
    status_code=status.HTTP_200_OK,
    summary="Export Asymmetrically Signed Tamper-Evident Case Archive",
    description="Creates a point-in-time signed snapshot ZIP of the entire case, including decrypted evidence and audit log.",
)
async def export_report_case_archive(
    request: Request,
    report_id: uuid.UUID = Path(..., description="Report UUID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="export",
            max_requests=settings.EXPORT_RATE_LIMIT,
            window_seconds=settings.EXPORT_RATE_WINDOW_SECONDS,
        )
        limit_res = await rate_limiter.check_rate_limit(
            policy=policy,
            client_ip=client_ip,
        )
    except RateLimitUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
        )
    if not limit_res.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(limit_res.retry_after)},
        )

    try:
        zip_path = await case_export_service.export_case_archive(report_id=report_id, db=db)
    except CaseShreddedError as e:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(e))
    except CaseExportError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return FileResponse(
        path=str(zip_path),
        media_type="application/zip",
        filename=zip_path.name,
        background=BackgroundTask(case_export_service.cleanup_export_file, zip_path),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@router.get(
    "/retention/preview",
    response_model=RetentionPreviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Preview Expired Terminal Reports for Retention Shredding",
    description="Inspect cases that have passed their terminal retention thresholds without executing shredding.",
)
async def preview_retention_sweep(
    limit: int = Query(100, ge=1, le=1000),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> RetentionPreviewResponse:
    return await retention_service.preview_retention_sweep(db=db, limit=limit)


@router.post(
    "/retention/execute",
    response_model=RetentionExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Distributed-Locked Retention Shredding Sweep",
    description="Acquires distributed lock and shreds expired cases, destroying evidence keys and recording audit tombstones.",
)
async def execute_retention_sweep(
    payload: RetentionExecuteRequest,
    current_moderator: Moderator = Depends(require_moderator),
) -> RetentionExecuteResponse:
    try:
        return await retention_service.execute_retention_sweep(
            db_factory=async_session_maker,
            limit=payload.limit,
        )
    except Exception as e:
        if "redis" in type(e).__module__.lower() or isinstance(e, (ConnectionError, OSError)):
            logger.error("Retention execution failed due to lock service failure: %s", type(e).__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Retention lock service unavailable.",
            )
        raise


@router.post(
    "/reports/{report_id}/rewrap-keys",
    status_code=status.HTTP_200_OK,
    summary="Rewrap Case Data Encryption Key under Active KEK",
)
async def rewrap_case_key(
    report_id: uuid.UUID = Path(..., description="Target Report ID"),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
):
    new_version = await payload_encryption_service.rewrap_case_dek(db, report_id)
    await db.commit()
    return {
        "report_id": str(report_id),
        "status": "rewrapped",
        "active_version": new_version,
        "new_key_version": new_version,
    }


@router.post(
    "/security/check-in",
    status_code=status.HTTP_200_OK,
    summary="Dead-Man's Switch Administrator Check-In",
)
async def admin_check_in(
    payload: AdminCheckInRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if not current_admin.is_totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin must have MFA enabled to perform check-in",
        )
    is_valid = await mfa_service.verify_totp_or_recovery_code(db, current_admin, payload.totp_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )
    next_due = await canary_service.admin_check_in(db, current_admin.id)
    return {"status": "ok", "next_due_at": next_due.isoformat()}


@router.post(
    "/security/emergency-seal",
    status_code=status.HTTP_200_OK,
    summary="Engage Emergency Access Sealing",
)
async def emergency_seal(
    payload: EmergencySealRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    state = await canary_service.execute_emergency_seal(
        db=db,
        initiator_id=current_admin.id,
        reason=payload.reason,
    )
    await db.commit()
    return {
        "status": "sealed",
        "sealed_at": state.sealed_at.isoformat() if state.sealed_at else None,
        "reason": state.seal_reason,
    }


@router.post(
    "/security/emergency-unseal",
    status_code=status.HTTP_200_OK,
    summary="Disengage Emergency Access Sealing",
)
async def emergency_unseal(
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    await canary_service.execute_emergency_unseal(
        db=db,
        approver_id=current_admin.id,
    )
    await db.commit()
    return {"status": "unsealed"}


@router.get(
    "/security/state",
    response_model=SecurityStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Get System Security State",
)
async def get_security_state(
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
):
    state = await canary_service.get_or_create_security_state(db)
    return state
