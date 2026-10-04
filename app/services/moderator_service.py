import base64
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.metrics import moderator_actions_total
from app.models.audit_log import AuditLog
from app.services.audit_service import audit_service
from app.models.enums import (
    EvidenceScanStatus,
    ModeratorRole,
    ReportCategory,
    ReportPriority,
    ReportStatus,
    ReportUpdateType,
)
from app.models.evidence import EvidenceAttachment
from app.models.moderator import Moderator
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.schemas.moderator import (
    DashboardStatsResponse,
    ModeratorReportDetailResponse,
    ModeratorReportResponse,
    ModeratorUpdateResponse,
    TimelineEventResponse,
    TimelineListResponse,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# Domain Exceptions
# ==============================================================================

class ReportNotFoundError(Exception):
    """Raised when a report is not found by ID."""
    pass


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle transition is attempted."""

    def __init__(self, from_status: ReportStatus, to_status: ReportStatus, detail: Optional[str] = None):
        self.from_status = from_status
        self.to_status = to_status
        msg = detail or f"Invalid report lifecycle transition from {from_status.value} to {to_status.value}."
        super().__init__(msg)


class VersionConflictError(Exception):
    """Raised when an optimistic concurrency control version check fails."""

    def __init__(self, expected_version: int, current_version: int):
        self.expected_version = expected_version
        self.current_version = current_version
        super().__init__(
            f"Conflict: Report was modified concurrently by another moderator. "
            f"Current version is {current_version}, expected {expected_version}. Please refresh."
        )


class UnauthorizedActionError(Exception):
    """Raised when a moderator lacks sufficient permissions for an action."""
    pass


class InvalidAssignmentError(Exception):
    """Raised when an assignment target is invalid (e.g. inactive moderator)."""
    pass


class InvalidCursorError(Exception):
    """Raised when a pagination cursor is malformed or invalid."""
    pass


# Explicit standard lifecycle transition graph
VALID_TRANSITIONS = {
    ReportStatus.SUBMITTED: {ReportStatus.UNDER_REVIEW},
    ReportStatus.UNDER_REVIEW: {ReportStatus.RESOLVED, ReportStatus.DISMISSED},
    ReportStatus.RESOLVED: set(),
    ReportStatus.DISMISSED: set(),
    ReportStatus.WITHDRAWN: set(),
}


def validate_transition(current_status: ReportStatus, target_status: ReportStatus) -> None:
    """Validate report state transition according to the standard lifecycle state machine."""
    allowed = VALID_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise InvalidStateTransitionError(current_status, target_status)


def encode_timeline_cursor(dt: datetime, event_id: uuid.UUID) -> str:
    """Encode timeline pagination tuple into a Base64URL string."""
    payload = json.dumps({"t": dt.isoformat(), "id": str(event_id)})
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8")


def decode_timeline_cursor(cursor_str: str) -> Tuple[datetime, uuid.UUID]:
    """Decode and validate Base64URL timeline pagination cursor."""
    try:
        raw = base64.urlsafe_b64decode(cursor_str.encode("utf-8")).decode("utf-8")
        data = json.loads(raw)
        dt = datetime.fromisoformat(data["t"])
        eid = uuid.UUID(data["id"])
        return dt, eid
    except Exception as e:
        raise InvalidCursorError("Invalid pagination cursor.") from e


def escape_like_string(value: str) -> str:
    """Safely escape SQL LIKE / ILIKE wildcard characters."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ModeratorService:
    """Service layer for internal moderator report management and inspection."""

    async def list_reports(
        self,
        db: AsyncSession,
        *,
        status: Optional[ReportStatus] = None,
        category: Optional[ReportCategory] = None,
        priority: Optional[ReportPriority] = None,
        assigned_to: Optional[uuid.UUID] = None,
        unassigned: Optional[bool] = None,
        search: Optional[str] = None,
        has_evidence: Optional[bool] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[ModeratorReportResponse], int]:
        """List reports with rich multi-field filtering, search, sorting, and bounded pagination."""
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        filters = []
        if status is not None:
            filters.append(Report.status == status)
        if category is not None:
            filters.append(Report.category == category)
        if priority is not None:
            filters.append(Report.priority == priority)
        if unassigned is True:
            filters.append(Report.assigned_to.is_(None))
        elif assigned_to is not None:
            filters.append(Report.assigned_to == assigned_to)

        if date_from is not None:
            filters.append(Report.created_at >= date_from)
        if date_to is not None:
            filters.append(Report.created_at <= date_to)

        if search and search.strip():
            safe_search = f"%{escape_like_string(search.strip())}%"
            filters.append(Report.description.ilike(safe_search, escape="\\"))

        if has_evidence is not None:
            if has_evidence:
                filters.append(
                    sa.or_(
                        Report.evidence_url.isnot(None),
                        Report.evidence_attachments.any(
                            EvidenceAttachment.scan_status == EvidenceScanStatus.CLEAN
                        ),
                    )
                )
            else:
                filters.append(
                    sa.and_(
                        Report.evidence_url.is_(None),
                        ~Report.evidence_attachments.any(
                            EvidenceAttachment.scan_status == EvidenceScanStatus.CLEAN
                        ),
                    )
                )

        # 1. Total count query
        count_stmt = sa.select(sa.func.count(Report.id))
        if filters:
            count_stmt = count_stmt.where(*filters)
        total_res = await db.execute(count_stmt)
        total = total_res.scalar() or 0

        # 2. Paginated items query
        sort_column_map = {
            "created_at": Report.created_at,
            "updated_at": Report.updated_at,
            "priority": Report.priority,
            "status": Report.status,
        }
        col = sort_column_map.get(sort_by, Report.created_at)
        order_clause = col.asc() if sort_order.lower() == "asc" else col.desc()

        stmt = (
            sa.select(
                Report.id,
                Report.category,
                Report.description,
                Report.evidence_url,
                Report.status,
                Report.priority,
                Report.assigned_to,
                Report.version_id,
                Report.created_at,
                Report.updated_at,
            )
            .where(*filters)
            .order_by(order_clause, Report.id.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await db.execute(stmt)
        rows = result.all()

        items = [
            ModeratorReportResponse(
                id=row.id,
                category=row.category,
                description=row.description,
                evidence_url=row.evidence_url,
                status=row.status,
                priority=row.priority,
                assigned_to=row.assigned_to,
                version_id=row.version_id,
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
        """Retrieve a single report by internal UUID with least-privilege column selection."""
        stmt = sa.select(
            Report.id,
            Report.category,
            Report.description,
            Report.evidence_url,
            Report.status,
            Report.priority,
            Report.assigned_to,
            Report.version_id,
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
            priority=row.priority,
            assigned_to=row.assigned_to,
            version_id=row.version_id,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    async def get_report_detail_by_id(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Optional[ModeratorReportDetailResponse]:
        """Retrieve a report with its chronological public updates and internal notes."""
        report_summary = await self.get_report_by_id(db, report_id)
        if report_summary is None:
            return None

        stmt_updates = (
            sa.select(
                ReportUpdate.id,
                ReportUpdate.message,
                ReportUpdate.type,
                ReportUpdate.created_at,
                ReportUpdate.created_by,
            )
            .where(ReportUpdate.report_id == report_id)
            .order_by(ReportUpdate.created_at.asc(), ReportUpdate.id.asc())
        )
        res_updates = await db.execute(stmt_updates)
        update_rows = res_updates.all()

        update_responses = [
            ModeratorUpdateResponse(
                id=u.id,
                message=u.message,
                type=u.type,
                created_at=u.created_at,
                created_by=u.created_by,
            )
            for u in update_rows
        ]

        return ModeratorReportDetailResponse(
            id=report_summary.id,
            category=report_summary.category,
            description=report_summary.description,
            evidence_url=report_summary.evidence_url,
            status=report_summary.status,
            priority=report_summary.priority,
            assigned_to=report_summary.assigned_to,
            version_id=report_summary.version_id,
            created_at=report_summary.created_at,
            updated_at=report_summary.updated_at,
            updates=update_responses,
        )

    async def update_report_status(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        new_status: ReportStatus,
        expected_version: int,
        moderator: Moderator,
        reopen_reason: Optional[str] = None,
        quorum_context: Optional[Any] = None,
    ) -> ModeratorReportResponse:
        """Atomically transition report status with mandatory OCC and role authorization."""
        try:
            stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
            result = await db.execute(stmt)
            report = result.scalar_one_or_none()

            if report is None:
                raise ReportNotFoundError(f"Report {report_id} not found.")

            # Concurrency check
            if report.version_id != expected_version:
                raise VersionConflictError(expected_version, report.version_id)

            from_status = report.status
            if from_status == ReportStatus.WITHDRAWN:
                raise InvalidStateTransitionError(
                    from_status, new_status, "Withdrawn reports are permanently terminal and cannot be modified."
                )

            now = datetime.now(timezone.utc)
            is_reopening = from_status in (ReportStatus.RESOLVED, ReportStatus.DISMISSED)

            if is_reopening:
                # Reopen Authorization Rule: ADMIN only
                if moderator.role != ModeratorRole.ADMIN:
                    raise UnauthorizedActionError("Admin privileges required to reopen closed reports.")
                if new_status != ReportStatus.UNDER_REVIEW:
                    raise InvalidStateTransitionError(
                        from_status, new_status, "Reopened reports can only transition to UNDER_REVIEW."
                    )
                if not reopen_reason or len(reopen_reason.strip()) < 10:
                    raise ValueError("A valid reopen_reason (minimum 10 characters) is required to reopen closed reports.")

                # Quorum enforcement check
                if settings.QUORUM_ENFORCE_CASE_REOPEN and quorum_context is None:
                    from app.services.quorum_service import QuorumRequiredException
                    raise QuorumRequiredException(
                        action_type="ADMIN_CASE_REOPEN",
                        target_id=str(report.id),
                        details={
                            "expected_version": expected_version,
                            "reopen_reason": reopen_reason.strip(),
                        },
                    )

                action = "REPORT_REOPENED"
                audit_meta = {
                    "from_status": from_status.value,
                    "to_status": new_status.value,
                    "reopen_reason": reopen_reason.strip(),
                }
            else:
                validate_transition(from_status, new_status)
                action = "REPORT_STATUS_CHANGED"
                audit_meta = {
                    "from_status": from_status.value,
                    "to_status": new_status.value,
                }

            report.status = new_status
            report.version_id += 1
            report.status_version += 1
            report.updated_at = now

            # Update retention clock according to terminal status
            if new_status == ReportStatus.RESOLVED:
                report.terminal_at = now + timedelta(days=settings.RETENTION_RESOLVED_DAYS)
            elif new_status == ReportStatus.DISMISSED:
                report.terminal_at = now + timedelta(days=settings.RETENTION_DISMISSED_DAYS)
            elif is_reopening:
                report.terminal_at = None

            # Append tamper-evident chained audit entry
            await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action=action,
                actor_type="MODERATOR",
                actor_id=moderator.id,
                metadata=audit_meta,
                created_at=now,
            )

            # Publish transactional outbox event
            from app.services.outbox_service import outbox_service
            await outbox_service.publish_event(
                db=db,
                event_type="report.status_changed",
                report_id=report.id,
                case_code_digest=report.case_code_digest,
                raw_data={
                    "status": new_status.value,
                    "category": report.category.value,
                    "priority": report.priority.value,
                },
            )

            await db.commit()
            await db.refresh(report)

            moderator_actions_total.labels(action="reopen" if is_reopening else "status_change").inc()
            logger.info(
                "Report status updated: report_id=%s, from=%s, to=%s, moderator_id=%s, version=%s",
                report.id,
                from_status.value,
                new_status.value,
                moderator.id,
                report.version_id,
            )

            return ModeratorReportResponse(
                id=report.id,
                category=report.category,
                description=report.description,
                evidence_url=report.evidence_url,
                status=report.status,
                priority=report.priority,
                assigned_to=report.assigned_to,
                version_id=report.version_id,
                created_at=report.created_at,
                updated_at=report.updated_at,
            )
        except Exception:
            await db.rollback()
            raise

    async def reopen_report_internal(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        expected_version: int,
        reopen_reason: str,
        admin_id: uuid.UUID,
        quorum_context: Any,
    ) -> Tuple[Report, Any]:
        """Internal execution helper for Quorum-approved case reopening."""
        stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
        report = (await db.execute(stmt)).scalar_one_or_none()
        if not report:
            raise ReportNotFoundError(f"Report {report_id} not found.")
        if report.version_id != expected_version:
            raise VersionConflictError(expected_version, report.version_id)
        if report.status not in (ReportStatus.RESOLVED, ReportStatus.DISMISSED):
            raise InvalidStateTransitionError(report.status, ReportStatus.UNDER_REVIEW, "Report is not in a closed state.")

        from_status = report.status
        now = datetime.now(timezone.utc)
        report.status = ReportStatus.UNDER_REVIEW
        report.version_id += 1
        report.status_version += 1
        report.updated_at = now
        report.terminal_at = None

        audit_entry = await audit_service.append_entry(
            db=db,
            report_id=report.id,
            action="REPORT_REOPENED",
            actor_type="MODERATOR",
            actor_id=admin_id,
            metadata={
                "from_status": from_status.value,
                "to_status": ReportStatus.UNDER_REVIEW.value,
                "reopen_reason": reopen_reason.strip(),
                "quorum_id": str(quorum_context.quorum_id),
            },
            created_at=now,
        )
        return report, audit_entry

    async def update_report_priority(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        new_priority: ReportPriority,
        expected_version: int,
        moderator: Moderator,
    ) -> ModeratorReportResponse:
        """Atomically modify report priority with row-locking and mandatory OCC."""
        try:
            stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
            result = await db.execute(stmt)
            report = result.scalar_one_or_none()

            if report is None:
                raise ReportNotFoundError(f"Report {report_id} not found.")

            if report.version_id != expected_version:
                raise VersionConflictError(expected_version, report.version_id)

            if report.status in (ReportStatus.RESOLVED, ReportStatus.DISMISSED, ReportStatus.WITHDRAWN):
                raise InvalidStateTransitionError(
                    report.status, report.status, "Cannot modify priority on closed or withdrawn reports."
                )

            from_priority = report.priority
            now = datetime.now(timezone.utc)

            report.priority = new_priority
            report.version_id += 1
            report.updated_at = now

            await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action="REPORT_PRIORITY_CHANGED",
                actor_type="MODERATOR",
                actor_id=moderator.id,
                metadata={
                    "from_priority": from_priority.value,
                    "to_priority": new_priority.value,
                },
                created_at=now,
            )

            await db.commit()
            await db.refresh(report)

            moderator_actions_total.labels(action="priority_change").inc()
            logger.info(
                "Report priority updated: report_id=%s, from=%s, to=%s, version=%s",
                report.id,
                from_priority.value,
                new_priority.value,
                report.version_id,
            )

            return ModeratorReportResponse(
                id=report.id,
                category=report.category,
                description=report.description,
                evidence_url=report.evidence_url,
                status=report.status,
                priority=report.priority,
                assigned_to=report.assigned_to,
                version_id=report.version_id,
                created_at=report.created_at,
                updated_at=report.updated_at,
            )
        except Exception:
            await db.rollback()
            raise

    async def update_report_assignment(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        target_moderator_id: Optional[uuid.UUID],
        expected_version: int,
        moderator: Moderator,
    ) -> ModeratorReportResponse:
        """Atomically assign or unassign report with row-locking, role checks, and OCC."""
        try:
            stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
            result = await db.execute(stmt)
            report = result.scalar_one_or_none()

            if report is None:
                raise ReportNotFoundError(f"Report {report_id} not found.")

            if report.version_id != expected_version:
                raise VersionConflictError(expected_version, report.version_id)

            if report.status == ReportStatus.WITHDRAWN:
                raise InvalidStateTransitionError(
                    report.status, report.status, "Cannot assign or unassign withdrawn reports."
                )

            # Authorization logic
            is_admin = moderator.role == ModeratorRole.ADMIN
            is_current_assignee = report.assigned_to == moderator.id
            is_self_claim = target_moderator_id == moderator.id

            if target_moderator_id is None:
                # Unassignment: only ADMIN or current assignee
                if not (is_admin or is_current_assignee):
                    raise UnauthorizedActionError("Only an admin or the current assignee can unassign this report.")
            else:
                # Assigning to someone
                if is_self_claim:
                    # Self-claim allowed if unassigned or already assigned to self, or admin
                    if report.assigned_to is not None and not is_current_assignee and not is_admin:
                        raise UnauthorizedActionError("Report is currently assigned to another moderator.")
                else:
                    # Assigning to someone else: only ADMIN or current assignee handing off
                    if not (is_admin or is_current_assignee):
                        raise UnauthorizedActionError("Only an admin or current assignee can reassign this report.")

                # Target moderator must exist and be active
                target_stmt = sa.select(Moderator).where(Moderator.id == target_moderator_id)
                target_res = await db.execute(target_stmt)
                target_mod = target_res.scalar_one_or_none()

                if target_mod is None:
                    raise InvalidAssignmentError("Target moderator not found.")
                if not target_mod.is_active:
                    raise InvalidAssignmentError("Cannot assign report to an inactive moderator.")

            from_assigned = report.assigned_to
            now = datetime.now(timezone.utc)

            report.assigned_to = target_moderator_id
            report.version_id += 1
            report.updated_at = now

            if target_moderator_id is None:
                action = "REPORT_UNASSIGNED"
                meta = {"previous_assigned_to": str(from_assigned) if from_assigned else None}
            else:
                action = "REPORT_ASSIGNED"
                meta = {
                    "from_assigned_to": str(from_assigned) if from_assigned else None,
                    "to_assigned_to": str(target_moderator_id),
                }

            await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action=action,
                actor_type="MODERATOR",
                actor_id=moderator.id,
                metadata=meta,
                created_at=now,
            )

            await db.commit()
            await db.refresh(report)

            metric_label = "unassign" if target_moderator_id is None else "assign"
            moderator_actions_total.labels(action=metric_label).inc()
            logger.info(
                "Report assignment updated: report_id=%s, from=%s, to=%s, version=%s",
                report.id,
                from_assigned,
                target_moderator_id,
                report.version_id,
            )

            return ModeratorReportResponse(
                id=report.id,
                category=report.category,
                description=report.description,
                evidence_url=report.evidence_url,
                status=report.status,
                priority=report.priority,
                assigned_to=report.assigned_to,
                version_id=report.version_id,
                created_at=report.created_at,
                updated_at=report.updated_at,
            )
        except Exception:
            await db.rollback()
            raise

    async def add_report_update(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        message: str,
        update_type: ReportUpdateType,
        expected_version: int,
        moderator_id: uuid.UUID,
    ) -> ModeratorUpdateResponse:
        """Atomically create a report update/note with row-locking and mandatory OCC."""
        try:
            stmt = sa.select(Report).where(Report.id == report_id).with_for_update()
            result = await db.execute(stmt)
            report = result.scalar_one_or_none()

            if report is None:
                raise ReportNotFoundError(f"Report {report_id} not found.")

            if report.version_id != expected_version:
                raise VersionConflictError(expected_version, report.version_id)

            if report.status == ReportStatus.WITHDRAWN:
                raise InvalidStateTransitionError(
                    report.status, report.status, "Cannot post updates to withdrawn reports."
                )

            if update_type == ReportUpdateType.PUBLIC_UPDATE and report.status in (
                ReportStatus.RESOLVED,
                ReportStatus.DISMISSED,
            ):
                raise InvalidStateTransitionError(
                    report.status, report.status, "Cannot post public updates to closed reports."
                )

            now = datetime.now(timezone.utc)
            report.version_id += 1
            report.updated_at = now

            update = ReportUpdate(
                report_id=report.id,
                message=message,
                type=update_type,
                created_by=moderator_id,
            )
            db.add(update)
            await db.flush()

            await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action="REPORT_UPDATE_CREATED",
                actor_type="MODERATOR",
                actor_id=moderator_id,
                metadata={
                    "update_id": str(update.id),
                    "update_type": update_type.value,
                },
                created_at=now,
            )

            await db.commit()
            await db.refresh(update)

            moderator_actions_total.labels(action="update_created").inc()
            logger.info(
                "Report update created: report_id=%s, type=%s, moderator_id=%s, version=%s",
                report.id,
                update_type.value,
                moderator_id,
                report.version_id,
            )

            return ModeratorUpdateResponse(
                id=update.id,
                message=update.message,
                type=update.type,
                created_at=update.created_at,
                created_by=update.created_by,
            )
        except Exception:
            await db.rollback()
            raise

    async def get_case_timeline(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        *,
        limit: int = 20,
        cursor: Optional[str] = None,
    ) -> TimelineListResponse:
        """Retrieve unified cursor-paginated timeline for a case in reverse chronological order."""
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")

        # Verify report existence
        rep_check = await db.execute(sa.select(Report.id).where(Report.id == report_id))
        if not rep_check.scalar_one_or_none():
            raise ReportNotFoundError(f"Report {report_id} not found.")

        # Decode cursor if provided
        cursor_filter = None
        if cursor:
            cursor_dt, cursor_id = decode_timeline_cursor(cursor)
            cursor_filter = sa.or_(
                AuditLog.created_at < cursor_dt,
                sa.and_(AuditLog.created_at == cursor_dt, AuditLog.id < cursor_id),
            )

        # Count total events for report
        total_stmt = sa.select(sa.func.count(AuditLog.id)).where(AuditLog.report_id == report_id)
        total = (await db.execute(total_stmt)).scalar() or 0

        # Query events with limit + 1 to detect next page
        query = (
            sa.select(AuditLog, Moderator.role, Moderator.username)
            .outerjoin(Moderator, AuditLog.moderator_id == Moderator.id)
            .where(AuditLog.report_id == report_id)
        )
        if cursor_filter is not None:
            query = query.where(cursor_filter)

        query = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit + 1)
        res = await db.execute(query)
        rows = res.all()

        has_next = len(rows) > limit
        page_rows = rows[:limit]

        next_cursor = None
        if has_next:
            last_item = page_rows[-1][0]
            next_cursor = encode_timeline_cursor(last_item.created_at, last_item.id)

        items = []
        for audit, mod_role, mod_username in page_rows:
            actor_role = mod_role.value if mod_role else "SYSTEM"
            meta = audit.metadata_ or {}

            # Generate privacy-safe human readable summary
            summary = self._build_event_summary(audit.action, meta)

            items.append(
                TimelineEventResponse(
                    id=audit.id,
                    timestamp=audit.created_at,
                    event_type=audit.action,
                    actor_role=actor_role,
                    actor_username=mod_username,
                    summary=summary,
                    metadata=meta,
                )
            )

        return TimelineListResponse(items=items, next_cursor=next_cursor, total=total)

    def _build_event_summary(self, action: str, meta: Dict[str, Any]) -> str:
        """Produce safe human-readable summary without leaking secrets or raw whistleblower content."""
        if action == "REPORT_STATUS_CHANGED":
            return f"Status transitioned from {meta.get('from_status', 'UNKNOWN')} to {meta.get('to_status', 'UNKNOWN')}"
        elif action == "REPORT_REOPENED":
            reason = meta.get("reopen_reason", "")
            return f"Report reopened: {reason}"
        elif action == "REPORT_PRIORITY_CHANGED":
            return f"Priority changed from {meta.get('from_priority', 'UNKNOWN')} to {meta.get('to_priority', 'UNKNOWN')}"
        elif action == "REPORT_ASSIGNED":
            return "Report assigned to moderator"
        elif action == "REPORT_UNASSIGNED":
            return "Report unassigned"
        elif action == "REPORT_UPDATE_CREATED":
            u_type = meta.get("update_type", "UPDATE")
            return f"Added {u_type.lower().replace('_', ' ')}"
        elif action == "EVIDENCE_UPLOADED":
            count = meta.get("attachments_count", 1)
            return f"Uploaded {count} evidence file(s)"
        return f"{action} recorded"

    async def get_dashboard_stats(
        self,
        db: AsyncSession,
        *,
        current_moderator_id: uuid.UUID,
        since: Optional[datetime] = None,
    ) -> DashboardStatsResponse:
        """Compute consolidated dashboard aggregate metrics in a single SQL query."""
        stmt = sa.select(
            sa.func.count().filter(Report.status == ReportStatus.SUBMITTED).label("count_submitted"),
            sa.func.count().filter(Report.status == ReportStatus.UNDER_REVIEW).label("count_under_review"),
            sa.func.count().filter(Report.status == ReportStatus.RESOLVED).label("count_resolved"),
            sa.func.count().filter(Report.status == ReportStatus.DISMISSED).label("count_dismissed"),
            sa.func.count().filter(Report.priority == ReportPriority.LOW).label("priority_low"),
            sa.func.count().filter(Report.priority == ReportPriority.MEDIUM).label("priority_medium"),
            sa.func.count().filter(Report.priority == ReportPriority.HIGH).label("priority_high"),
            sa.func.count().filter(Report.priority == ReportPriority.CRITICAL).label("priority_critical"),
            sa.func.count().filter(
                Report.assigned_to.is_(None),
                Report.status.in_([ReportStatus.SUBMITTED, ReportStatus.UNDER_REVIEW]),
            ).label("unassigned_active"),
            sa.func.count().filter(
                Report.assigned_to == current_moderator_id,
                Report.status.in_([ReportStatus.SUBMITTED, ReportStatus.UNDER_REVIEW]),
            ).label("my_active_cases"),
            sa.func.count().filter(
                Report.assigned_to.in_(
                    sa.select(Moderator.id).where(Moderator.is_active == False)
                ),
                Report.status.in_([ReportStatus.SUBMITTED, ReportStatus.UNDER_REVIEW]),
            ).label("assigned_to_inactive_count"),
        )
        if since is not None:
            stmt = stmt.where(Report.created_at >= since)

        res = await db.execute(stmt)
        row = res.one()

        return DashboardStatsResponse(
            count_submitted=row.count_submitted or 0,
            count_under_review=row.count_under_review or 0,
            count_resolved=row.count_resolved or 0,
            count_dismissed=row.count_dismissed or 0,
            priority_low=row.priority_low or 0,
            priority_medium=row.priority_medium or 0,
            priority_high=row.priority_high or 0,
            priority_critical=row.priority_critical or 0,
            unassigned_active=row.unassigned_active or 0,
            my_active_cases=row.my_active_cases or 0,
            assigned_to_inactive_count=row.assigned_to_inactive_count or 0,
        )


moderator_service = ModeratorService()

