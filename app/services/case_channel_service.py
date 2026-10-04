import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from fastapi import HTTPException, Request, Response, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.redis import get_redis
from app.models.audit_log import AuditLog
from app.models.case_message import CaseMessage, CaseMessageModeratorReadState
from app.models.enums import MessageSenderType, ReportStatus
from app.models.moderator import Moderator
from app.models.report import Report
from app.schemas.case_message import (
    CaseMessageListResponse,
    CaseMessageResponse,
    CaseNotificationResponse,
    MessageReadAckResponse,
    NotificationStatusAckResponse,
)

logger = logging.getLogger(__name__)

UUID4_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

# Atomic Lua Script: Compare-and-Set IN_PROGRESS -> COMPLETED with owner token check
LUA_IDEMP_CAS_SCRIPT = """
local val = redis.call('get', KEYS[1])
if not val then
    return 0
end
local decoded = cjson.decode(val)
if decoded.state == 'IN_PROGRESS' and decoded.owner_token == ARGV[1] then
    redis.call('set', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
    return 1
end
return 0
"""

# Atomic Lua Script: Compare-and-Delete IN_PROGRESS on failure with owner token check
LUA_IDEMP_CAD_SCRIPT = """
local val = redis.call('get', KEYS[1])
if not val then
    return 0
end
local decoded = cjson.decode(val)
if decoded.state == 'IN_PROGRESS' and decoded.owner_token == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


class CaseClosedError(Exception):
    """Raised when an action is attempted on a closed (RESOLVED/DISMISSED) case."""
    pass


class MessageNotFoundError(Exception):
    """Raised when a message is not found for the given report."""
    pass


class InvalidCursorError(Exception):
    """Raised when a keyset cursor is invalid, expired, or tampered with."""
    pass


def add_no_store_cache_headers(response: Response) -> None:
    """Apply strict no-store HTTP cache control headers to prevent client and intermediary caching."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"


async def read_and_validate_message_payload(request: Request) -> str:
    """Validate raw byte ceiling (64 KiB), parse JSON, and extract validated message content.

    Enforces real transport-level byte limits before or during body streaming,
    rejecting oversized payloads with 413 Request Entity Too Large.
    """
    # 1. Early Content-Length check
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            cl_int = int(cl)
            if cl_int > settings.MAX_MESSAGE_REQUEST_BODY:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Request body exceeds maximum allowed size of {settings.MAX_MESSAGE_REQUEST_BODY} bytes (64 KiB).",
                )
        except ValueError:
            pass

    # 2. Chunked / streamed body size check
    body_chunks = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > settings.MAX_MESSAGE_REQUEST_BODY:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Request body exceeds maximum allowed size of {settings.MAX_MESSAGE_REQUEST_BODY} bytes (64 KiB).",
            )
        body_chunks.append(chunk)

    raw_body = b"".join(body_chunks)
    if not raw_body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body cannot be empty.",
        )

    try:
        data = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid JSON payload.",
        )

    if not isinstance(data, dict) or "content" not in data or not isinstance(data["content"], str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Field 'content' is required and must be a string.",
        )

    content = data["content"]
    if len(content) < 1 or len(content) > settings.MAX_MESSAGE_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Message content must be between 1 and {settings.MAX_MESSAGE_LENGTH} characters.",
        )

    return content


def generate_public_message_id() -> str:
    """Generate high-entropy CSPRNG public message identifier (e.g. msg_...)."""
    return f"msg_{secrets.token_urlsafe(18)}"



def sign_cursor(report_id: uuid.UUID, created_at: datetime, public_id: str) -> str:
    """Encode and sign keyset cursor binding report_id, created_at, and public_id."""
    iso_time = created_at.isoformat()
    raw_payload = f"{report_id}:{iso_time}:{public_id}"
    secret_bytes = settings.CURSOR_SECRET.encode("utf-8")
    sig = hmac.new(secret_bytes, raw_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    token_dict = {
        "t": iso_time,
        "pid": public_id,
        "sig": sig,
    }
    json_bytes = json.dumps(token_dict, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")


def verify_and_decode_cursor(report_id: uuid.UUID, cursor_str: str) -> Tuple[datetime, str]:
    """Verify HMAC signature and decode keyset cursor returning (created_at, public_id)."""
    if len(cursor_str) > 512:
        raise InvalidCursorError("Cursor exceeds maximum permitted length")

    # Re-pad base64
    padded = cursor_str + "=" * (-len(cursor_str) % 4)
    try:
        json_bytes = base64.urlsafe_b64decode(padded)
        token_dict = json.loads(json_bytes.decode("utf-8"))
        iso_time = token_dict["t"]
        public_id = token_dict["pid"]
        provided_sig = token_dict["sig"]
    except Exception:
        raise InvalidCursorError("Malformed cursor format")

    raw_payload = f"{report_id}:{iso_time}:{public_id}"
    secret_bytes = settings.CURSOR_SECRET.encode("utf-8")
    expected_sig = hmac.new(secret_bytes, raw_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise InvalidCursorError("Cursor signature verification failed")

    try:
        dt = datetime.fromisoformat(iso_time)
    except Exception:
        raise InvalidCursorError("Invalid cursor timestamp")

    return dt, public_id


class CaseChannelService:
    """Business logic for anonymous case conversations, read tracking, and notifications."""

    # --------------------------------------------------------------------------
    # Idempotency Protocol Helpers
    # --------------------------------------------------------------------------

    def build_redis_idempotency_key(
        self,
        sender_type: MessageSenderType,
        report_id: uuid.UUID,
        idempotency_key: str,
        moderator_id: Optional[uuid.UUID] = None,
    ) -> str:
        """Construct fully-scoped Redis idempotency key."""
        if sender_type == MessageSenderType.REPORTER:
            return f"idemp:message_create:reporter:{report_id}:{idempotency_key}"
        return f"idemp:message_create:moderator:{report_id}:{moderator_id}:{idempotency_key}"

    async def reserve_idempotency_key(
        self,
        redis_key: str,
        content: str,
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Reserve idempotency key atomically with owner token.

        Returns:
            Tuple[owner_token, cached_response_data]
            If cached_response_data is not None, request is already completed.
        """
        redis_client = await get_redis()
        owner_token = secrets.token_hex(16)
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        reservation_payload = json.dumps({
            "state": "IN_PROGRESS",
            "owner_token": owner_token,
            "content_hash": content_hash,
            "created_at": time.time(),
        })

        # Atomic SET NX EX
        acquired = await redis_client.set(
            redis_key,
            reservation_payload,
            ex=settings.IDEMPOTENCY_IN_PROGRESS_TTL_SECONDS,
            nx=True,
        )

        if acquired:
            return owner_token, None

        # Key already exists in Redis
        raw_val = await redis_client.get(redis_key)
        if not raw_val:
            # Race where previous reservation just expired
            acquired_retry = await redis_client.set(
                redis_key,
                reservation_payload,
                ex=settings.IDEMPOTENCY_IN_PROGRESS_TTL_SECONDS,
                nx=True,
            )
            if acquired_retry:
                return owner_token, None
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Concurrent request with identical idempotency key in progress.",
            )

        try:
            existing = json.loads(raw_val)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Invalid existing idempotency record.",
            )

        if existing.get("content_hash") != content_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key reused with different payload.",
            )

        if existing.get("state") == "COMPLETED":
            return "", existing.get("response")

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent request with identical idempotency key in progress.",
        )

    async def finalize_idempotency_completed(
        self,
        redis_key: str,
        owner_token: str,
        content: str,
        response_dict: Dict[str, Any],
    ) -> None:
        """Transition idempotency reservation to COMPLETED using Lua CAS."""
        redis_client = await get_redis()
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        completed_payload = json.dumps({
            "state": "COMPLETED",
            "content_hash": content_hash,
            "response": response_dict,
            "completed_at": time.time(),
        })

        await redis_client.eval(
            LUA_IDEMP_CAS_SCRIPT,
            1,
            redis_key,
            owner_token,
            completed_payload,
            settings.IDEMPOTENCY_TTL_SECONDS,
        )

    async def release_idempotency_reservation(
        self,
        redis_key: str,
        owner_token: str,
    ) -> None:
        """Release IN_PROGRESS reservation on error using Lua CAD."""
        if not owner_token:
            return
        try:
            redis_client = await get_redis()
            await redis_client.eval(
                LUA_IDEMP_CAD_SCRIPT,
                1,
                redis_key,
                owner_token,
            )
        except Exception as e:
            logger.warning("Failed to release idempotency reservation %s: %s", redis_key, str(e))

    # --------------------------------------------------------------------------
    # Message Creation (Reporter & Moderator)
    # --------------------------------------------------------------------------

    async def create_message(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        sender_type: MessageSenderType,
        content: str,
        moderator: Optional[Moderator] = None,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[CaseMessage, bool]:
        """Create a new message with terminal state check under row lock.

        Returns:
            Tuple[CaseMessage, is_recovered_replay]
        """
        # Validate idempotency key format if present
        if idempotency_key is not None:
            if len(idempotency_key) != 36 or not UUID4_REGEX.match(idempotency_key):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Invalid Idempotency-Key format. Must be canonical UUIDv4.",
                )

        redis_key = None
        owner_token = ""
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        if idempotency_key:
            redis_key = self.build_redis_idempotency_key(
                sender_type=sender_type,
                report_id=report_id,
                idempotency_key=idempotency_key,
                moderator_id=moderator.id if moderator else None,
            )
            owner_token, cached_resp = await self.reserve_idempotency_key(redis_key, content)
            if cached_resp is not None:
                # Return synthetic or re-queried message object
                stmt_cached = sa.select(CaseMessage).where(CaseMessage.public_id == cached_resp["id"])
                res = await db.execute(stmt_cached)
                cached_msg = res.scalar_one_or_none()
                if cached_msg:
                    return cached_msg, True

        try:
            # 1. Lock the Report row to serialize with case lifecycle transitions
            stmt_lock = sa.select(Report).where(Report.id == report_id).with_for_update()
            res_lock = await db.execute(stmt_lock)
            report = res_lock.scalar_one_or_none()

            if not report:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

            # 2. Terminal state enforcement
            if report.status in (ReportStatus.RESOLVED, ReportStatus.DISMISSED):
                raise CaseClosedError("Case is closed. Cannot post messages to a resolved or dismissed case.")

            # 3. DB Crash Recovery check for idempotency
            if idempotency_key:
                stmt_existing = sa.select(CaseMessage).where(
                    CaseMessage.report_id == report_id,
                    CaseMessage.sender_type == sender_type,
                    CaseMessage.idempotency_key == idempotency_key,
                )
                if sender_type == MessageSenderType.MODERATOR and moderator:
                    stmt_existing = stmt_existing.where(CaseMessage.moderator_id == moderator.id)
                res_existing = await db.execute(stmt_existing)
                existing_msg = res_existing.scalar_one_or_none()

                if existing_msg:
                    existing_hash = hashlib.sha256(existing_msg.content.encode("utf-8")).hexdigest()
                    if existing_hash != content_hash:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Idempotency key reused with different payload.",
                        )
                    # Reconstruct completed Redis state
                    resp_dict = {
                        "id": existing_msg.public_id,
                        "sender": existing_msg.sender_type.value,
                        "content": existing_msg.content,
                        "created_at": existing_msg.created_at.isoformat(),
                    }
                    if redis_key and owner_token:
                        await self.finalize_idempotency_completed(redis_key, owner_token, content, resp_dict)
                    return existing_msg, True

            # 4. Insert message
            public_id = generate_public_message_id()
            msg = CaseMessage(
                public_id=public_id,
                report_id=report_id,
                sender_type=sender_type,
                moderator_id=moderator.id if moderator else None,
                idempotency_key=idempotency_key,
                content=content,
            )
            db.add(msg)

            # 5. Update report metadata
            now = datetime.now(timezone.utc)
            report.updated_at = now
            if sender_type == MessageSenderType.MODERATOR:
                report.version_id += 1

            # 6. Audit logging (excluding message content or secrets)
            if sender_type == MessageSenderType.REPORTER:
                audit = AuditLog(
                    report_id=report_id,
                    moderator_id=None,
                    action="REPORTER_MESSAGE_SUBMITTED",
                    metadata_={
                        "public_id": public_id,
                        "message_length": len(content),
                    },
                )
            else:
                audit = AuditLog(
                    report_id=report_id,
                    moderator_id=moderator.id if moderator else None,
                    action="MODERATOR_PUBLIC_REPLY_CREATED",
                    metadata_={
                        "public_id": public_id,
                        "expected_version": report.version_id,
                    },
                )
            db.add(audit)

            await db.commit()
            await db.refresh(msg)

            # 7. Finalize Redis idempotency key
            if redis_key and owner_token:
                resp_dict = {
                    "id": msg.public_id,
                    "sender": msg.sender_type.value,
                    "content": msg.content,
                    "created_at": msg.created_at.isoformat(),
                }
                await self.finalize_idempotency_completed(redis_key, owner_token, content, resp_dict)

            return msg, False

        except Exception:
            await db.rollback()
            if redis_key and owner_token:
                await self.release_idempotency_reservation(redis_key, owner_token)
            raise

    # --------------------------------------------------------------------------
    # Keyset Cursor Pagination
    # --------------------------------------------------------------------------

    async def list_messages(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        cursor: Optional[str] = None,
        limit: int = 20,
        caller_sender_type: MessageSenderType = MessageSenderType.REPORTER,
        moderator_id: Optional[uuid.UUID] = None,
    ) -> CaseMessageListResponse:
        """List messages in chronological order with authenticated keyset pagination."""
        query = sa.select(CaseMessage).where(CaseMessage.report_id == report_id)

        if cursor:
            cursor_dt, cursor_pid = verify_and_decode_cursor(report_id, cursor)
            # Lookup underlying message ID for strict tuple tie-breaking
            stmt_c = sa.select(CaseMessage.id).where(
                CaseMessage.report_id == report_id,
                CaseMessage.public_id == cursor_pid,
            )
            res_c = await db.execute(stmt_c)
            cursor_id = res_c.scalar_one_or_none()
            if not cursor_id:
                raise InvalidCursorError("Cursor referenced unknown message")

            # Deterministic tuple pagination: created_at > :t OR (created_at = :t AND id > :id)
            query = query.where(
                sa.or_(
                    CaseMessage.created_at > cursor_dt,
                    sa.and_(
                        CaseMessage.created_at == cursor_dt,
                        CaseMessage.id > cursor_id,
                    ),
                )
            )

        query = query.order_by(CaseMessage.created_at.asc(), CaseMessage.id.asc()).limit(limit + 1)
        res = await db.execute(query)
        rows = list(res.scalars().all())

        has_more = len(rows) > limit
        items = rows[:limit]

        next_cursor = None
        if has_more and items:
            last_item = items[-1]
            next_cursor = sign_cursor(report_id, last_item.created_at, last_item.public_id)

        # Calculate unread count for the caller
        total_unread = await self.get_unread_message_count(
            db=db,
            report_id=report_id,
            caller_sender_type=caller_sender_type,
            moderator_id=moderator_id,
        )

        return CaseMessageListResponse(
            items=[
                CaseMessageResponse(
                    id=m.public_id,
                    sender=m.sender_type.value,
                    content=m.content,
                    created_at=m.created_at,
                )
                for m in items
            ],
            next_cursor=next_cursor,
            has_more=has_more,
            total_unread=total_unread,
        )

    # --------------------------------------------------------------------------
    # Read State & Unread Calculations (Deterministic Tuple Comparison)
    # --------------------------------------------------------------------------

    async def get_unread_message_count(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        caller_sender_type: MessageSenderType,
        moderator_id: Optional[uuid.UUID] = None,
    ) -> int:
        """Calculate unread messages using strict tuple comparison."""
        if caller_sender_type == MessageSenderType.REPORTER:
            # Reporter reads moderator messages
            stmt_rep = sa.select(
                Report.reporter_last_read_created_at,
                Report.reporter_last_read_message_id,
            ).where(Report.id == report_id)
            res_rep = await db.execute(stmt_rep)
            row = res_rep.one_or_none()
            if not row:
                return 0
            last_read_t, last_read_id = row

            query = sa.select(sa.func.count()).select_from(CaseMessage).where(
                CaseMessage.report_id == report_id,
                CaseMessage.sender_type == MessageSenderType.MODERATOR,
            )
            if last_read_t is not None and last_read_id is not None:
                query = query.where(
                    sa.or_(
                        CaseMessage.created_at > last_read_t,
                        sa.and_(
                            CaseMessage.created_at == last_read_t,
                            CaseMessage.id > last_read_id,
                        ),
                    )
                )
            res = await db.execute(query)
            return res.scalar_one() or 0

        else:
            # Moderator reads reporter messages
            if not moderator_id:
                return 0
            stmt_mod = sa.select(
                CaseMessageModeratorReadState.last_read_created_at,
                CaseMessageModeratorReadState.last_read_message_id,
            ).where(
                CaseMessageModeratorReadState.report_id == report_id,
                CaseMessageModeratorReadState.moderator_id == moderator_id,
            )
            res_mod = await db.execute(stmt_mod)
            row = res_mod.one_or_none()

            last_read_t = row[0] if row else None
            last_read_id = row[1] if row else None

            query = sa.select(sa.func.count()).select_from(CaseMessage).where(
                CaseMessage.report_id == report_id,
                CaseMessage.sender_type == MessageSenderType.REPORTER,
            )
            if last_read_t is not None and last_read_id is not None:
                query = query.where(
                    sa.or_(
                        CaseMessage.created_at > last_read_t,
                        sa.and_(
                            CaseMessage.created_at == last_read_t,
                            CaseMessage.id > last_read_id,
                        ),
                    )
                )
            res = await db.execute(query)
            return res.scalar_one() or 0

    async def advance_reporter_read_state(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        public_message_id: str,
    ) -> MessageReadAckResponse:
        """Advance reporter read high-water mark monotonically using tuple comparison."""
        # Find candidate message
        stmt_msg = sa.select(CaseMessage).where(
            CaseMessage.public_id == public_message_id,
            CaseMessage.report_id == report_id,
        )
        res_msg = await db.execute(stmt_msg)
        msg = res_msg.scalar_one_or_none()
        if not msg:
            raise MessageNotFoundError("Message not found on this report")

        # Load report for update
        stmt_rep = sa.select(Report).where(Report.id == report_id).with_for_update()
        res_rep = await db.execute(stmt_rep)
        report = res_rep.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        curr_t = report.reporter_last_read_created_at
        curr_id = report.reporter_last_read_message_id

        # Deterministic monotonic check: M > Curr
        is_newer = (
            curr_t is None
            or msg.created_at > curr_t
            or (msg.created_at == curr_t and msg.id > curr_id)
        )

        if is_newer:
            report.reporter_last_read_created_at = msg.created_at
            report.reporter_last_read_message_id = msg.id
            # Does NOT increment report.version_id or status_version
            await db.commit()
            await db.refresh(report)

        unread_count = await self.get_unread_message_count(
            db=db,
            report_id=report_id,
            caller_sender_type=MessageSenderType.REPORTER,
        )

        # Lookup public_id of the actual current high-water mark message
        ack_pid = msg.public_id if is_newer else None
        if not ack_pid and report.reporter_last_read_message_id:
            stmt_curr = sa.select(CaseMessage.public_id).where(CaseMessage.id == report.reporter_last_read_message_id)
            res_curr = await db.execute(stmt_curr)
            ack_pid = res_curr.scalar_one_or_none()

        return MessageReadAckResponse(
            acknowledged=True,
            last_read_message_id=ack_pid,
            last_read_at=report.reporter_last_read_created_at,
            unread_count=unread_count,
        )

    async def advance_moderator_read_state(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        moderator_id: uuid.UUID,
        public_message_id: str,
    ) -> MessageReadAckResponse:
        """Advance moderator read high-water mark monotonically using tuple comparison."""
        # Find candidate message
        stmt_msg = sa.select(CaseMessage).where(
            CaseMessage.public_id == public_message_id,
            CaseMessage.report_id == report_id,
        )
        res_msg = await db.execute(stmt_msg)
        msg = res_msg.scalar_one_or_none()
        if not msg:
            raise MessageNotFoundError("Message not found on this report")

        # Load or initialize read state row under lock
        stmt_state = sa.select(CaseMessageModeratorReadState).where(
            CaseMessageModeratorReadState.report_id == report_id,
            CaseMessageModeratorReadState.moderator_id == moderator_id,
        ).with_for_update()
        res_state = await db.execute(stmt_state)
        state = res_state.scalar_one_or_none()

        if not state:
            state = CaseMessageModeratorReadState(
                report_id=report_id,
                moderator_id=moderator_id,
                last_read_message_id=msg.id,
                last_read_created_at=msg.created_at,
            )
            db.add(state)
            await db.commit()
            await db.refresh(state)
        else:
            curr_t = state.last_read_created_at
            curr_id = state.last_read_message_id

            is_newer = (
                curr_t is None
                or msg.created_at > curr_t
                or (msg.created_at == curr_t and msg.id > curr_id)
            )

            if is_newer:
                state.last_read_created_at = msg.created_at
                state.last_read_message_id = msg.id
                state.updated_at = datetime.now(timezone.utc)
                await db.commit()
                await db.refresh(state)

        unread_count = await self.get_unread_message_count(
            db=db,
            report_id=report_id,
            caller_sender_type=MessageSenderType.MODERATOR,
            moderator_id=moderator_id,
        )

        ack_pid = None
        if state.last_read_message_id:
            stmt_curr = sa.select(CaseMessage.public_id).where(CaseMessage.id == state.last_read_message_id)
            res_curr = await db.execute(stmt_curr)
            ack_pid = res_curr.scalar_one_or_none()

        return MessageReadAckResponse(
            acknowledged=True,
            last_read_message_id=ack_pid,
            last_read_at=state.last_read_created_at,
            unread_count=unread_count,
        )

    # --------------------------------------------------------------------------
    # Notifications & Status Acknowledgment (Phase 12)
    # --------------------------------------------------------------------------

    async def get_case_notifications(
        self,
        db: AsyncSession,
        report: Report,
    ) -> CaseNotificationResponse:
        """Fetch pull-based notification status for an anonymous case."""
        unread_count = await self.get_unread_message_count(
            db=db,
            report_id=report.id,
            caller_sender_type=MessageSenderType.REPORTER,
        )
        has_status_update = report.status_version > report.reporter_acknowledged_status_version

        # Determine last activity timestamp
        stmt_last_msg = sa.select(sa.func.max(CaseMessage.created_at)).where(CaseMessage.report_id == report.id)
        res_last_msg = await db.execute(stmt_last_msg)
        last_msg_at = res_last_msg.scalar_one_or_none()

        last_activity_at = max(filter(None, [report.updated_at, last_msg_at])) if (report.updated_at or last_msg_at) else report.created_at

        return CaseNotificationResponse(
            status=report.status.value,
            status_version=report.status_version,
            has_status_update=has_status_update,
            unread_messages=unread_count,
            last_activity_at=last_activity_at,
        )

    async def acknowledge_notification_status(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        status_version: int,
    ) -> NotificationStatusAckResponse:
        """Acknowledge observed case status version monotonically."""
        stmt_rep = sa.select(Report).where(Report.id == report_id).with_for_update()
        res_rep = await db.execute(stmt_rep)
        report = res_rep.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        if status_version > report.status_version:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Status version exceeds current case version.",
            )

        if status_version > report.reporter_acknowledged_status_version:
            report.reporter_acknowledged_status_version = status_version
            # Does NOT increment report.version_id
            await db.commit()
            await db.refresh(report)

        return NotificationStatusAckResponse(
            acknowledged=True,
            acknowledged_version=report.reporter_acknowledged_status_version,
        )


case_channel_service = CaseChannelService()
