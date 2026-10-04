import asyncio
from datetime import datetime, timezone
import hashlib
import json
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
import sqlalchemy as sa

from app.core.config import settings
from app.core.security import create_access_token, derive_case_code_digest
from app.db.redis import get_redis
from app.models.case_message import CaseMessage, CaseMessageModeratorReadState
from app.models.enums import MessageSenderType, ModeratorRole, ReportCategory, ReportPriority, ReportStatus
from app.models.moderator import Moderator
from app.models.report import Report
from app.schemas.report import ReportCreate
from app.services.auth_service import auth_service
from app.services.case_channel_service import (
    case_channel_service,
    sign_cursor,
    verify_and_decode_cursor,
)
from app.services.report_service import report_service


# ==============================================================================
# Helpers
# ==============================================================================

async def setup_test_report(db_session: AsyncSession) -> tuple[Report, str]:
    """Helper to create a fresh report and return (report, plaintext_case_code)."""
    report_in = ReportCreate(
        category=ReportCategory.TECHNICAL,
        description="Anonymous case communication test report description.",
    )
    return await report_service.create_report(db=db_session, report_in=report_in)


async def create_moderator_headers(
    db_session: AsyncSession,
    role: ModeratorRole = ModeratorRole.MODERATOR,
    username: str = "test_mod_comm",
) -> tuple[Moderator, dict]:
    """Helper to create a moderator and return (moderator, auth_headers)."""
    mod = await auth_service.create_moderator(
        db_session,
        username=username,
        password="TestPassword123!",
        role=role,
        is_active=True,
    )
    token = create_access_token(subject=str(mod.id))
    return mod, {"Authorization": f"Bearer {token}"}


# ==============================================================================
# Phase 11: Two-Way Anonymous Case Communication Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_reporter_post_message_and_retrieve_conversation(client, db_session):
    """Verify whistleblower can post a message and list the conversation."""
    report, case_code = await setup_test_report(db_session)
    headers = {"X-Case-Code": case_code}

    # 1. Post message
    payload = {"content": "Hello moderator, I have additional details regarding this incident."}
    res_post = client.post("/api/v1/reports/messages", json=payload, headers=headers)
    assert res_post.status_code == 201
    data_post = res_post.json()
    assert data_post["id"].startswith("msg_")
    assert data_post["sender"] == "REPORTER"
    assert data_post["content"] == payload["content"]
    assert "created_at" in data_post
    # Privacy check: internal UUIDs never exposed
    assert data_post["id"] != str(report.id)

    # 2. List messages
    res_list = client.get("/api/v1/reports/messages", headers=headers)
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert len(data_list["items"]) == 1
    assert data_list["items"][0]["id"] == data_post["id"]
    assert data_list["has_more"] is False
    assert data_list["next_cursor"] is None
    assert data_list["total_unread"] == 0  # Whistleblower's own message is not unread to them


@pytest.mark.asyncio
async def test_moderator_post_message_and_reply(client, db_session):
    """Verify moderator can post a reply and whistleblower sees it without moderator identity."""
    report, case_code = await setup_test_report(db_session)
    mod, mod_headers = await create_moderator_headers(db_session)
    rep_headers = {"X-Case-Code": case_code}

    # 1. Moderator posts public reply
    mod_payload = {"content": "Thank you for the report. Could you specify which server was affected?"}
    res_mod = client.post(
        f"/api/v1/moderator/reports/{report.id}/messages",
        json=mod_payload,
        headers=mod_headers,
    )
    assert res_mod.status_code == 201
    data_mod = res_mod.json()
    assert data_mod["id"].startswith("msg_")
    assert data_mod["sender"] == "MODERATOR"
    assert data_mod["content"] == mod_payload["content"]
    # Verify moderator UUID is NOT in the public response
    assert "moderator_id" not in data_mod

    # 2. Whistleblower lists messages and sees unread count = 1
    res_list = client.get("/api/v1/reports/messages", headers=rep_headers)
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert len(data_list["items"]) == 1
    assert data_list["items"][0]["sender"] == "MODERATOR"
    assert data_list["total_unread"] == 1

    # 3. Whistleblower acknowledges read state
    msg_id = data_list["items"][0]["id"]
    res_ack = client.post(
        "/api/v1/reports/messages/read",
        json={"last_read_message_id": msg_id},
        headers=rep_headers,
    )
    assert res_ack.status_code == 200
    data_ack = res_ack.json()
    assert data_ack["acknowledged"] is True
    assert data_ack["last_read_message_id"] == msg_id
    assert data_ack["unread_count"] == 0


@pytest.mark.asyncio
async def test_moderator_read_state_advancement(client, db_session):
    """Verify per-moderator read state advancement and unread calculation."""
    report, case_code = await setup_test_report(db_session)
    mod, mod_headers = await create_moderator_headers(db_session)
    rep_headers = {"X-Case-Code": case_code}

    # 1. Reporter sends 2 messages
    res1 = client.post("/api/v1/reports/messages", json={"content": "Msg 1"}, headers=rep_headers)
    assert res1.status_code == 201
    msg1_id = res1.json()["id"]

    res2 = client.post("/api/v1/reports/messages", json={"content": "Msg 2"}, headers=rep_headers)
    assert res2.status_code == 201
    msg2_id = res2.json()["id"]

    # 2. Moderator lists messages: sees total_unread = 2
    res_mod_list = client.get(f"/api/v1/moderator/reports/{report.id}/messages", headers=mod_headers)
    assert res_mod_list.status_code == 200
    assert res_mod_list.json()["total_unread"] == 2

    # 3. Moderator acks msg1
    res_mod_ack1 = client.post(
        f"/api/v1/moderator/reports/{report.id}/messages/read",
        json={"last_read_message_id": msg1_id},
        headers=mod_headers,
    )
    assert res_mod_ack1.status_code == 200
    assert res_mod_ack1.json()["unread_count"] == 1

    # 4. Moderator acks msg2
    res_mod_ack2 = client.post(
        f"/api/v1/moderator/reports/{report.id}/messages/read",
        json={"last_read_message_id": msg2_id},
        headers=mod_headers,
    )
    assert res_mod_ack2.status_code == 200
    assert res_mod_ack2.json()["unread_count"] == 0


# ==============================================================================
# Idempotency & Redis Ownership Protection Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_idempotent_message_posting_and_replay(client, db_session):
    """Verify idempotent message submission returns cached response and prevents duplicate rows."""
    report, case_code = await setup_test_report(db_session)
    idempotency_key = str(uuid.uuid4())
    headers = {
        "X-Case-Code": case_code,
        "Idempotency-Key": idempotency_key,
    }
    payload = {"content": "Idempotent message test content."}

    # First attempt: creates message
    res1 = client.post("/api/v1/reports/messages", json=payload, headers=headers)
    assert res1.status_code == 201
    data1 = res1.json()

    # Second attempt with identical key and payload: cached replay
    res2 = client.post("/api/v1/reports/messages", json=payload, headers=headers)
    assert res2.status_code == 201
    assert res2.headers.get("X-Cache-Lookup") == "HIT"
    data2 = res2.json()
    assert data2["id"] == data1["id"]

    # Verify only one message exists in database
    stmt = sa.select(sa.func.count()).select_from(CaseMessage).where(CaseMessage.report_id == report.id)
    count = (await db_session.execute(stmt)).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_idempotency_key_payload_conflict_rejected(client, db_session):
    """Verify reusing an idempotency key with a different payload returns 409 Conflict."""
    report, case_code = await setup_test_report(db_session)
    idempotency_key = str(uuid.uuid4())
    headers = {
        "X-Case-Code": case_code,
        "Idempotency-Key": idempotency_key,
    }

    # 1. Post original payload
    res1 = client.post("/api/v1/reports/messages", json={"content": "Original message"}, headers=headers)
    assert res1.status_code == 201

    # 2. Post modified payload with same key
    res2 = client.post("/api/v1/reports/messages", json={"content": "Modified message"}, headers=headers)
    assert res2.status_code == 409
    assert "different payload" in res2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_redis_reservation_expiry_and_db_recovery(client, db_session):
    """Verify that if Redis key expires or is deleted, subsequent request recovers from DB."""
    report, case_code = await setup_test_report(db_session)
    idempotency_key = str(uuid.uuid4())
    headers = {
        "X-Case-Code": case_code,
        "Idempotency-Key": idempotency_key,
    }
    payload = {"content": "Crash recovery message test."}

    # 1. Create message
    res1 = client.post("/api/v1/reports/messages", json=payload, headers=headers)
    assert res1.status_code == 201
    msg1_id = res1.json()["id"]

    # 2. Simulate Redis key eviction / expiry
    redis_client = await get_redis()
    redis_key = case_channel_service.build_redis_idempotency_key(
        MessageSenderType.REPORTER, report.id, idempotency_key
    )
    await redis_client.delete(redis_key)

    # 3. Post again: DB recovery path detects existing row and recovers response
    res2 = client.post("/api/v1/reports/messages", json=payload, headers=headers)
    assert res2.status_code == 201
    assert res2.headers.get("X-Cache-Lookup") == "HIT"
    assert res2.json()["id"] == msg1_id


@pytest.mark.asyncio
async def test_late_owner_cannot_delete_or_overwrite_reservation(client, db_session):
    """Verify that a late request with an expired owner_token cannot delete or overwrite another reservation."""
    report, _ = await setup_test_report(db_session)
    idempotency_key = str(uuid.uuid4())
    redis_key = case_channel_service.build_redis_idempotency_key(
        MessageSenderType.REPORTER, report.id, idempotency_key
    )

    # Request A acquires reservation with token A
    token_a, _ = await case_channel_service.reserve_idempotency_key(redis_key, "content A")
    assert token_a

    # Simulate Request A expiring, and Request B acquiring new reservation with token B
    redis_client = await get_redis()
    await redis_client.delete(redis_key)
    token_b, _ = await case_channel_service.reserve_idempotency_key(redis_key, "content B")
    assert token_b != token_a

    # Late Request A attempts to release reservation: Lua CAD fails because owner_token doesn't match
    await case_channel_service.release_idempotency_reservation(redis_key, token_a)
    val_after_cad = await redis_client.get(redis_key)
    assert val_after_cad is not None
    data_after_cad = json.loads(val_after_cad)
    assert data_after_cad["owner_token"] == token_b  # Preserved!

    # Late Request A attempts to mark COMPLETED: Lua CAS fails
    await case_channel_service.finalize_idempotency_completed(
        redis_key, token_a, "content A", {"id": "fake_id"}
    )
    val_after_cas = await redis_client.get(redis_key)
    data_after_cas = json.loads(val_after_cas)
    assert data_after_cas["state"] == "IN_PROGRESS"  # Not overwritten!
    assert data_after_cas["owner_token"] == token_b


# ==============================================================================
# Request Body Ceiling & Large Unicode Payload Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_5000_character_multibyte_within_64k_ceiling(client, db_session):
    """Verify a valid 5,000-character payload with multi-byte and JSON-escaped chars succeeds within 64 KiB."""
    report, case_code = await setup_test_report(db_session)
    headers = {"X-Case-Code": case_code}

    # Construct 5,000 chars of emojis, quotes, backslashes, and symbols
    unit = "🚀✨\"\\—"  # 5 characters
    content = unit * 1000  # Exactly 5,000 characters
    assert len(content) == 5000

    raw_body_bytes = json.dumps({"content": content}).encode("utf-8")
    assert len(raw_body_bytes) > 16384  # Exceeds old 16 KiB ceiling
    assert len(raw_body_bytes) < 65536  # Within new 64 KiB ceiling

    res = client.post(
        "/api/v1/reports/messages",
        content=raw_body_bytes,
        headers={"Content-Type": "application/json", "X-Case-Code": case_code},
    )
    assert res.status_code == 201
    assert res.json()["content"] == content


@pytest.mark.asyncio
async def test_oversized_raw_request_body_rejected(client, db_session):
    """Verify request bodies exceeding 64 KiB (65,536 bytes) are rejected with 413 Content Too Large."""
    report, case_code = await setup_test_report(db_session)
    headers = {"X-Case-Code": case_code, "Content-Type": "application/json"}

    # Oversized payload (> 64 KiB)
    oversized_content = "A" * 70000
    oversized_body = json.dumps({"content": oversized_content}).encode("utf-8")

    res = client.post(
        "/api/v1/reports/messages",
        content=oversized_body,
        headers=headers,
    )
    assert res.status_code == 413
    assert "64 KiB" in res.json()["detail"] or "exceeds" in res.json()["detail"].lower()


# ==============================================================================
# Route Precedence & Cache-Control Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_static_routes_precedence_over_case_code(client):
    """Verify static /messages and /notifications routes do not enter dynamic /{case_code} handler."""
    # Calling /reports/messages without header returns 401 Unauthorized (from message handler)
    res_msg = client.get("/api/v1/reports/messages")
    assert res_msg.status_code == 401
    assert res_msg.json()["detail"] == "Case code credential required"

    # Calling /reports/notifications without header returns 401 Unauthorized (from notification handler)
    res_notif = client.get("/api/v1/reports/notifications")
    assert res_notif.status_code == 401
    assert res_notif.json()["detail"] == "Case code credential required"


@pytest.mark.asyncio
async def test_cache_control_no_store_headers(client, db_session):
    """Verify all anonymous endpoints emit strict Cache-Control: no-store headers."""
    report, case_code = await setup_test_report(db_session)
    headers = {"X-Case-Code": case_code}

    # 1. GET /reports/messages
    res_msg = client.get("/api/v1/reports/messages", headers=headers)
    assert res_msg.status_code == 200
    assert "no-store" in res_msg.headers.get("Cache-Control", "")
    assert res_msg.headers.get("Pragma") == "no-cache"

    # 2. GET /reports/notifications
    res_notif = client.get("/api/v1/reports/notifications", headers=headers)
    assert res_notif.status_code == 200
    assert "no-store" in res_notif.headers.get("Cache-Control", "")
    assert res_notif.headers.get("Pragma") == "no-cache"

    # 3. GET /reports/{case_code} (legacy tracking)
    res_track = client.get(f"/api/v1/reports/{case_code}")
    assert res_track.status_code == 200
    assert "no-store" in res_track.headers.get("Cache-Control", "")
    assert res_track.headers.get("Pragma") == "no-cache"


# ==============================================================================
# Terminal-State Concurrency & Reopen Lifecycle Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_terminal_state_concurrency_and_closed_case_rejection(client, db_session):
    """Verify message creation is blocked on resolved/dismissed cases, but reading remains permitted."""
    report, case_code = await setup_test_report(db_session)
    mod, mod_headers = await create_moderator_headers(db_session)
    rep_headers = {"X-Case-Code": case_code}

    # Post an initial message while open
    res_open = client.post("/api/v1/reports/messages", json={"content": "Open message"}, headers=rep_headers)
    assert res_open.status_code == 201

    # Transition report to UNDER_REVIEW then RESOLVED
    res_rev = client.patch(
        f"/api/v1/moderator/reports/{report.id}/status",
        json={"status": "UNDER_REVIEW", "expected_version": 1},
        headers=mod_headers,
    )
    assert res_rev.status_code == 200

    res_res = client.patch(
        f"/api/v1/moderator/reports/{report.id}/status",
        json={"status": "RESOLVED", "expected_version": 2},
        headers=mod_headers,
    )
    assert res_res.status_code == 200

    # Whistleblower attempts to post message to resolved case: 409 Conflict
    res_rep_blocked = client.post("/api/v1/reports/messages", json={"content": "Post-close message"}, headers=rep_headers)
    assert res_rep_blocked.status_code == 409
    assert "closed" in res_rep_blocked.json()["detail"].lower()

    # Moderator attempts to post message to resolved case: 409 Conflict
    res_mod_blocked = client.post(
        f"/api/v1/moderator/reports/{report.id}/messages",
        json={"content": "Post-close mod reply"},
        headers=mod_headers,
    )
    assert res_mod_blocked.status_code == 409
    assert "closed" in res_mod_blocked.json()["detail"].lower()

    # Historical reading is still allowed
    res_hist = client.get("/api/v1/reports/messages", headers=rep_headers)
    assert res_hist.status_code == 200
    assert len(res_hist.json()["items"]) == 1


@pytest.mark.asyncio
async def test_admin_reopen_restores_communication(client, db_session):
    """Verify reopening a closed case by admin restores communication capabilities."""
    report, case_code = await setup_test_report(db_session)
    admin_mod, admin_headers = await create_moderator_headers(db_session, role=ModeratorRole.ADMIN, username="admin_comm")
    rep_headers = {"X-Case-Code": case_code}

    # Move to RESOLVED
    client.patch(f"/api/v1/moderator/reports/{report.id}/status", json={"status": "UNDER_REVIEW", "expected_version": 1}, headers=admin_headers)
    client.patch(f"/api/v1/moderator/reports/{report.id}/status", json={"status": "RESOLVED", "expected_version": 2}, headers=admin_headers)

    # Reopen as ADMIN
    res_reopen = client.patch(
        f"/api/v1/moderator/reports/{report.id}/status",
        json={
            "status": "UNDER_REVIEW",
            "expected_version": 3,
            "reopen_reason": "New corroborating evidence surfaced requiring further review.",
        },
        headers=admin_headers,
    )
    assert res_reopen.status_code == 200

    # Message posting capability is restored
    res_post = client.post("/api/v1/reports/messages", json={"content": "New message post reopen"}, headers=rep_headers)
    assert res_post.status_code == 201


# ==============================================================================
# Keyset Pagination & Same-Timestamp Deterministic Ordering Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_same_timestamp_deterministic_tuple_ordering(client, db_session):
    """Verify deterministic ordering and unread counts when messages share exact same timestamp."""
    report, case_code = await setup_test_report(db_session)
    mod, _ = await create_moderator_headers(db_session, username="mod_same_time")
    rep_headers = {"X-Case-Code": case_code}

    # Insert two moderator messages with identical timestamps
    same_time = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    id1 = uuid.uuid4()
    id2 = uuid.uuid4()
    # Ensure id1 < id2 for deterministic check
    if id1 > id2:
        id1, id2 = id2, id1

    msg1 = CaseMessage(
        id=id1,
        public_id="msg_same_time_001",
        report_id=report.id,
        sender_type=MessageSenderType.MODERATOR,
        moderator_id=mod.id,
        content="First same-time message",
        created_at=same_time,
    )
    msg2 = CaseMessage(
        id=id2,
        public_id="msg_same_time_002",
        report_id=report.id,
        sender_type=MessageSenderType.MODERATOR,
        moderator_id=mod.id,
        content="Second same-time message",
        created_at=same_time,
    )
    db_session.add_all([msg1, msg2])
    await db_session.commit()

    # 1. List messages: should be ordered by (created_at ASC, id ASC)
    res_list = client.get("/api/v1/reports/messages", headers=rep_headers)
    assert res_list.status_code == 200
    items = res_list.json()["items"]
    assert len(items) == 2
    assert items[0]["id"] == "msg_same_time_001"
    assert items[1]["id"] == "msg_same_time_002"
    assert res_list.json()["total_unread"] == 2

    # 2. Acknowledge the first message
    res_ack1 = client.post(
        "/api/v1/reports/messages/read",
        json={"last_read_message_id": "msg_same_time_001"},
        headers=rep_headers,
    )
    assert res_ack1.status_code == 200
    assert res_ack1.json()["unread_count"] == 1

    # 3. Acknowledge the second message
    res_ack2 = client.post(
        "/api/v1/reports/messages/read",
        json={"last_read_message_id": "msg_same_time_002"},
        headers=rep_headers,
    )
    assert res_ack2.status_code == 200
    assert res_ack2.json()["unread_count"] == 0


# ==============================================================================
# Phase 12: Notification Status Version Tracking Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_notification_status_version_tracking_and_acknowledgment(client, db_session):
    """Verify pull-based notification status detection and acknowledgment."""
    report, case_code = await setup_test_report(db_session)
    mod, mod_headers = await create_moderator_headers(db_session)
    rep_headers = {"X-Case-Code": case_code}

    # Initial notification check
    res_init = client.get("/api/v1/reports/notifications", headers=rep_headers)
    assert res_init.status_code == 200
    data_init = res_init.json()
    assert data_init["status"] == "SUBMITTED"
    assert data_init["status_version"] == 1
    assert data_init["has_status_update"] is False
    assert data_init["unread_messages"] == 0

    # Moderator updates status to UNDER_REVIEW
    res_update = client.patch(
        f"/api/v1/moderator/reports/{report.id}/status",
        json={"status": "UNDER_REVIEW", "expected_version": 1},
        headers=mod_headers,
    )
    assert res_update.status_code == 200

    # Notification check now shows has_status_update = True
    res_updated = client.get("/api/v1/reports/notifications", headers=rep_headers)
    assert res_updated.status_code == 200
    data_updated = res_updated.json()
    assert data_updated["status"] == "UNDER_REVIEW"
    assert data_updated["status_version"] == 2
    assert data_updated["has_status_update"] is True

    # Reporter acknowledges status version 2
    res_ack = client.post(
        "/api/v1/reports/notifications/read",
        json={"status_version": 2},
        headers=rep_headers,
    )
    assert res_ack.status_code == 200
    assert res_ack.json()["acknowledged"] is True
    assert res_ack.json()["acknowledged_version"] == 2

    # Notification check now shows has_status_update = False
    res_final = client.get("/api/v1/reports/notifications", headers=rep_headers)
    assert res_final.json()["has_status_update"] is False

    # Acknowledging future/invalid status version > current version returns 422
    res_future = client.post(
        "/api/v1/reports/notifications/read",
        json={"status_version": 999},
        headers=rep_headers,
    )
    assert res_future.status_code == 422
    assert "exceeds" in res_future.json()["detail"].lower()


# ==============================================================================
# Security & Privacy Invariants Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_no_internal_uuid_or_moderator_leakage(client, db_session):
    """Verify that no public response exposes internal UUIDs, moderator IDs, case digests, or IPs."""
    report, case_code = await setup_test_report(db_session)
    mod, mod_headers = await create_moderator_headers(db_session)
    rep_headers = {"X-Case-Code": case_code}

    # Post message from reporter and moderator
    client.post("/api/v1/reports/messages", json={"content": "Reporter msg"}, headers=rep_headers)
    client.post(f"/api/v1/moderator/reports/{report.id}/messages", json={"content": "Mod msg"}, headers=mod_headers)

    # 1. Inspect message list JSON
    res_list = client.get("/api/v1/reports/messages", headers=rep_headers)
    body_text = res_list.text

    # Assertions against leakages
    assert str(report.id) not in body_text
    assert str(mod.id) not in body_text
    assert report.case_code_digest not in body_text
    assert "evidence_storage" not in body_text

    # 2. Inspect notification JSON
    res_notif = client.get("/api/v1/reports/notifications", headers=rep_headers)
    notif_text = res_notif.text
    assert str(report.id) not in notif_text
    assert str(mod.id) not in notif_text
    assert report.case_code_digest not in notif_text
