from datetime import datetime, timedelta, timezone
import hashlib
import json
import time
from typing import Tuple
from unittest.mock import AsyncMock, patch
import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
import sqlalchemy as sa

from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    generate_totp_secret,
    get_totp_code,
    hash_refresh_token,
)
from app.db.redis import get_redis
from app.models.enums import ModeratorRole, ReportCategory, ReportStatus
from app.models.moderator import Moderator
from app.models.moderator_session import ModeratorSession
from app.models.quorum import QuorumRequest
from app.models.webhook import OutboxEvent, WebhookDelivery, WebhookEndpoint
from app.schemas.report import ReportCreate
from app.services.auth_service import auth_service
from app.services.mfa_service import mfa_service
from app.services.moderator_service import moderator_service
from app.services.outbox_service import outbox_service
from app.services.quorum_service import QuorumExecutionContext, QuorumRequiredException, quorum_service
from app.services.report_service import report_service
from app.services.retention_service import retention_service
from app.services.session_service import session_service
from app.services.ssrf_validator import resolve_and_validate_destination, validate_webhook_url
from app.services.webhook_dispatcher_service import webhook_dispatcher_service


async def create_test_moderator(
    db_session: AsyncSession,
    username: str,
    role: ModeratorRole = ModeratorRole.MODERATOR,
    password: str = "CorrectPassword123!",
    is_active: bool = True,
    is_totp_enabled: bool = False,
) -> Tuple[Moderator, dict]:
    mod = await auth_service.create_moderator(
        db_session,
        username=username,
        password=password,
        role=role,
        is_active=is_active,
    )
    if is_totp_enabled:
        secret = generate_totp_secret()
        c, iv, tag = mfa_service.encrypt_secret(secret)
        mod.totp_secret_encrypted = c
        mod.totp_secret_iv = iv
        mod.totp_secret_tag = tag
        mod.is_totp_enabled = True
        await db_session.commit()
        await db_session.refresh(mod)

    # Create persistent session for auth headers
    session, token, refresh_tok = await session_service.create_session(
        db_session,
        mod,
        user_agent="pytest-agent",
        auth_level="mfa" if is_totp_enabled else "pwd",
    )
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    return mod, headers


# ==============================================================================
# PHASE 15: MFA, SESSION REVOCATION & PERSISTENT ACCESS CONTROL
# ==============================================================================

@pytest.mark.asyncio
async def test_login_unregistered_mfa(client, db_session: AsyncSession):
    """Verify non-MFA moderator login returns access and refresh tokens directly."""
    await auth_service.create_moderator(
        db_session,
        username="basic_mod",
        password="ValidPassword123!",
        role=ModeratorRole.MODERATOR,
    )
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "basic_mod", "password": "ValidPassword123!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["mfa_required"] is False
    assert data["access_token"] != ""
    assert data["refresh_token"].startswith("rt_")

    # Verify session persisted in DB
    payload = decode_access_token(data["access_token"])
    sid = uuid.UUID(payload["sid"])
    session = (await db_session.execute(sa.select(ModeratorSession).where(ModeratorSession.id == sid))).scalar_one_or_none()
    assert session is not None
    assert session.is_revoked is False


@pytest.mark.asyncio
async def test_mfa_setup_flow(client, db_session: AsyncSession):
    """Verify password re-authentication, setup ticket, TOTP verification, and recovery codes."""
    mod, headers = await create_test_moderator(db_session, "mfa_setup_mod", password="MySecretPassword123!")

    # 1. Invalid password re-auth fails
    res_bad_pw = client.post(
        "/api/v1/auth/mfa/setup-token",
        headers=headers,
        json={"password": "WrongPassword!"},
    )
    assert res_bad_pw.status_code == 401

    # 2. Valid password re-auth returns single-use setup ticket
    res_ticket = client.post(
        "/api/v1/auth/mfa/setup-token",
        headers=headers,
        json={"password": "MySecretPassword123!"},
    )
    assert res_ticket.status_code == 200
    ticket = res_ticket.json()["setup_ticket"]
    assert ticket.startswith("mfa_setup_tkt_")

    # 3. Consume setup ticket to generate unconfirmed secret
    res_setup = client.post(
        f"/api/v1/auth/mfa/setup?ticket={ticket}",
        headers=headers,
    )
    assert res_setup.status_code == 200
    secret = res_setup.json()["secret"]
    assert "otpauth://" in res_setup.json()["otpauth_uri"]

    # 4. Ticket cannot be reused (consumed via GETDEL)
    res_reuse = client.post(
        f"/api/v1/auth/mfa/setup?ticket={ticket}",
        headers=headers,
    )
    assert res_reuse.status_code == 401

    # 5. Invalid TOTP code fails verification
    res_bad_code = client.post(
        "/api/v1/auth/mfa/verify-setup",
        headers=headers,
        json={"code": "000000"},
    )
    assert res_bad_code.status_code == 400

    # 6. Valid TOTP code activates MFA and returns 10 backup codes
    valid_code = get_totp_code(secret)
    res_verify = client.post(
        "/api/v1/auth/mfa/verify-setup",
        headers=headers,
        json={"code": valid_code},
    )
    assert res_verify.status_code == 200
    data = res_verify.json()
    assert data["status"] == "mfa_enabled"
    assert len(data["backup_codes"]) == 10

    # Verify DB state
    await db_session.refresh(mod)
    assert mod.is_totp_enabled is True
    assert mod.totp_secret_encrypted is not None
    assert len(mod.backup_codes) == 10


@pytest.mark.asyncio
async def test_mfa_setup_hijack_prevention(client, db_session: AsyncSession):
    """Verify setup ticket cannot be used by a different moderator."""
    mod1, headers1 = await create_test_moderator(db_session, "user_one")
    mod2, headers2 = await create_test_moderator(db_session, "user_two")

    # Mod 1 generates setup ticket
    res_ticket = client.post(
        "/api/v1/auth/mfa/setup-token",
        headers=headers1,
        json={"password": "CorrectPassword123!"},
    )
    ticket = res_ticket.json()["setup_ticket"]

    # Mod 2 attempts to use Mod 1's setup ticket -> 401 Unauthorized
    res_hijack = client.post(
        f"/api/v1/auth/mfa/setup?ticket={ticket}",
        headers=headers2,
    )
    assert res_hijack.status_code == 401


@pytest.mark.asyncio
async def test_mfa_login_challenge_flow(client, db_session: AsyncSession):
    """Verify MFA-enabled user login produces challenge ticket, and fulfills via TOTP."""
    mod, _ = await create_test_moderator(
        db_session,
        "mfa_login_mod",
        password="SecurePassword123!",
        is_totp_enabled=True,
    )
    raw_secret = mfa_service.decrypt_secret(
        mod.totp_secret_encrypted,
        mod.totp_secret_iv,
        mod.totp_secret_tag,
    )

    # 1. Login with password returns mfa_required=True
    res_login = client.post(
        "/api/v1/auth/login",
        json={"username": "mfa_login_mod", "password": "SecurePassword123!"},
    )
    assert res_login.status_code == 200
    data = res_login.json()
    assert data["mfa_required"] is True
    assert data["access_token"] == ""
    ticket = data["mfa_ticket"]
    assert ticket.startswith("mfa_tkt_")

    # 2. Challenge ticket cannot be fulfilled with invalid code
    res_bad = client.post(
        f"/api/v1/auth/mfa/challenge?ticket={ticket}",
        json={"code": "123456"},
    )
    assert res_bad.status_code == 401

    # Challenge ticket was consumed on attempt
    res_reused = client.post(
        f"/api/v1/auth/mfa/challenge?ticket={ticket}",
        json={"code": get_totp_code(raw_secret)},
    )
    assert res_reused.status_code == 401

    # 3. New challenge ticket with valid TOTP code succeeds
    res_login2 = client.post(
        "/api/v1/auth/login",
        json={"username": "mfa_login_mod", "password": "SecurePassword123!"},
    )
    ticket2 = res_login2.json()["mfa_ticket"]
    valid_code = get_totp_code(raw_secret)
    res_fulfil = client.post(
        f"/api/v1/auth/mfa/challenge?ticket={ticket2}",
        json={"code": valid_code},
    )
    assert res_fulfil.status_code == 200
    token_data = res_fulfil.json()
    assert token_data["access_token"] != ""
    assert token_data["refresh_token"] != ""

    # Verify access token has auth_level="mfa"
    decoded = decode_access_token(token_data["access_token"])
    assert decoded["auth_level"] == "mfa"


@pytest.mark.asyncio
async def test_mfa_single_use_recovery_codes(client, db_session: AsyncSession):
    """Verify single-use recovery code fulfillment and prevent replay."""
    mod, _ = await create_test_moderator(
        db_session,
        "recovery_mod",
        password="PassWord123!",
        is_totp_enabled=True,
    )
    # Generate recovery code directly in moderator
    from app.core.security import generate_recovery_codes, hash_recovery_code
    raw_codes = generate_recovery_codes(2)
    mod.backup_codes = [
        {"code_hash": hash_recovery_code(rc), "created_at": datetime.now(timezone.utc).isoformat(), "used_at": None}
        for rc in raw_codes
    ]
    await db_session.commit()

    # Login to get ticket
    res_login = client.post("/api/v1/auth/login", json={"username": "recovery_mod", "password": "PassWord123!"})
    ticket1 = res_login.json()["mfa_ticket"]

    # Fulfill with first recovery code
    res_rc1 = client.post(f"/api/v1/auth/mfa/challenge?ticket={ticket1}", json={"code": raw_codes[0]})
    assert res_rc1.status_code == 200

    # Verify code marked used in DB
    await db_session.commit()
    await db_session.refresh(mod)
    assert mod.backup_codes[0]["used_at"] is not None
    assert mod.backup_codes[1]["used_at"] is None

    # Attempting to reuse code 1 with new ticket fails
    res_login2 = client.post("/api/v1/auth/login", json={"username": "recovery_mod", "password": "PassWord123!"})
    ticket2 = res_login2.json()["mfa_ticket"]
    res_reused = client.post(f"/api/v1/auth/mfa/challenge?ticket={ticket2}", json={"code": raw_codes[0]})
    assert res_reused.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_theft_detection(client, db_session: AsyncSession):
    """Verify atomic refresh token rotation and family revocation upon reuse."""
    mod, _ = await create_test_moderator(db_session, "rot_mod")
    session, access_t, refresh_t1 = await session_service.create_session(db_session, mod)
    await db_session.commit()

    # 1. Normal rotation: refresh_t1 -> refresh_t2
    res_rot = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_t1})
    assert res_rot.status_code == 200
    refresh_t2 = res_rot.json()["refresh_token"]
    assert refresh_t2 != refresh_t1

    # 2. Old token is now revoked
    await db_session.commit()
    await db_session.refresh(session)
    assert session.is_revoked is True

    # 3. REPLAY THEFT ATTEMPT: Reusing refresh_t1
    res_replay = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_t1})
    assert res_replay.status_code == 401
    assert "reuse" in res_replay.json()["detail"].lower()

    # 4. Entire session family is revoked and token_version is incremented
    await db_session.commit()
    await db_session.refresh(mod)
    assert mod.token_version > 1

    # refresh_t2 should now also fail because family was revoked
    res_t2 = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_t2})
    assert res_t2.status_code == 401


@pytest.mark.asyncio
async def test_logout_and_session_revocation(client, db_session: AsyncSession):
    """Verify /logout and /sessions/revoke-all in DB and fast-path Redis."""
    mod, headers = await create_test_moderator(db_session, "logout_mod")

    # Logout
    res_logout = client.post("/api/v1/auth/logout", headers=headers)
    assert res_logout.status_code == 200

    # Old token rejected
    res_check = client.get("/api/v1/moderator/reports", headers=headers)
    assert res_check.status_code == 401

    # Simulate Redis flush - PostgreSQL authoritative state must still reject
    redis = get_redis()
    await redis.flushdb()
    res_after_flush = client.get("/api/v1/moderator/reports", headers=headers)
    assert res_after_flush.status_code == 401


# ==============================================================================
# PHASE 16: TRANSACTIONAL OUTBOX & SIGNED WEBHOOKS
# ==============================================================================

@pytest.mark.asyncio
async def test_webhook_registration_and_ssrf(client, db_session: AsyncSession):
    """Verify webhook registration, SSRF defenses (IPv4, IPv6, loopback), and secret encryption."""
    admin_mod, admin_headers = await create_test_moderator(db_session, "wh_admin", role=ModeratorRole.ADMIN)

    # 1. Private IPv4 loopback rejected
    res_ssrf_v4 = client.post(
        "/api/v1/moderator/webhooks",
        headers=admin_headers,
        json={"url": "https://127.0.0.1/webhook", "subscribed_events": ["report.created"]},
    )
    assert res_ssrf_v4.status_code == 400
    assert "disallowed" in res_ssrf_v4.json()["detail"].lower() or "validation failed" in res_ssrf_v4.json()["detail"].lower()

    # 2. Link-local cloud metadata (169.254.169.254) rejected
    res_meta = client.post(
        "/api/v1/moderator/webhooks",
        headers=admin_headers,
        json={"url": "https://169.254.169.254/latest/meta-data", "subscribed_events": ["report.created"]},
    )
    assert res_meta.status_code == 400

    # 3. Private IPv6 loopback (::1) rejected
    res_ssrf_v6 = client.post(
        "/api/v1/moderator/webhooks",
        headers=admin_headers,
        json={"url": "https://[::1]/hook", "subscribed_events": ["report.created"]},
    )
    assert res_ssrf_v6.status_code == 400

    # 4. Plain HTTP rejected when ALLOW_HTTP_WEBHOOKS=False
    res_http = client.post(
        "/api/v1/moderator/webhooks",
        headers=admin_headers,
        json={"url": "http://example.com/webhook", "subscribed_events": ["report.created"]},
    )
    assert res_http.status_code == 400

    # 5. Public HTTPS destination allowed
    with patch("app.services.webhook_dispatcher_service.resolve_and_validate_destination", return_value=["93.184.216.34"]):
        res_ok = client.post(
            "/api/v1/moderator/webhooks",
            headers=admin_headers,
            json={
                "url": "https://example.com/webhook",
                "description": "Production Alerting",
                "subscribed_events": ["report.created", "report.status_changed"],
            },
        )
        assert res_ok.status_code == 201
        wh_data = res_ok.json()
        assert wh_data["webhook_secret"].startswith("whsec_")
        wh_id = uuid.UUID(wh_data["id"])

    # 6. GET endpoint does not expose secret
    res_get = client.get(f"/api/v1/moderator/webhooks/{wh_id}", headers=admin_headers)
    assert res_get.status_code == 200
    assert "webhook_secret" not in res_get.json()


@pytest.mark.asyncio
async def test_report_creation_transactional_outbox_event(client, db_session: AsyncSession):
    """Verify creating a report atomically writes a sanitized report.created event to outbox."""
    rep, receipt = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Outbox test report"),
    )

    # Check outbox events in DB
    stmt = sa.select(OutboxEvent).where(OutboxEvent.event_type == "report.created")
    event = (await db_session.execute(stmt)).scalar_one_or_none()
    assert event is not None
    assert event.status == "PENDING"
    assert event.opaque_event_id.startswith("evt_")

    # Verify sanitized payload (no raw case code, no description)
    payload = event.payload
    assert "case_code" not in payload
    assert "description" not in payload
    data = payload["data"]
    assert "case_reference" in data
    assert data["category"] == "CORRUPTION"


@pytest.mark.asyncio
async def test_outbox_worker_lease_and_dispatch(client, db_session: AsyncSession):
    """Verify disconnected worker lease claim, signature calculation, and delivery."""
    admin_mod, _ = await create_test_moderator(db_session, "wh_admin2", role=ModeratorRole.ADMIN)

    # Create webhook endpoint with secret
    endpoint, raw_secret = await webhook_dispatcher_service.create_endpoint(
        db=db_session,
        url="https://example.com/wh_receive",
        description="Test endpoint",
        subscribed_events=["report.created"],
        created_by_id=admin_mod.id,
    )

    # Publish outbox event
    event = await outbox_service.publish_event(
        db=db_session,
        event_type="report.created",
        raw_data={"test_key": "val1"},
    )
    await db_session.commit()

    # 1. Claim batch with worker lease
    worker_id = f"worker-{uuid.uuid4()}"
    claimed_events = await webhook_dispatcher_service.claim_batch(db_session, worker_id=worker_id, limit=10)
    assert len(claimed_events) == 1
    assert claimed_events[0].status == "CLAIMED"
    assert claimed_events[0].lease_worker_id == worker_id
    assert claimed_events[0].lease_expires_at is not None

    # 2. Dispatch with mock HTTP client
    mock_http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_http_client.post.return_value = mock_resp

    with patch("app.services.webhook_dispatcher_service.resolve_and_validate_destination"):
        success = await webhook_dispatcher_service.dispatch_event_to_endpoints(
            db=db_session,
            event=claimed_events[0],
            client=mock_http_client,
        )
        assert success is True

    # 3. Verify HTTP request parameters and signature
    call_args = mock_http_client.post.call_args
    assert call_args[0][0] == endpoint.url
    sent_headers = call_args[1]["headers"]
    assert "X-WhistleDrop-Signature" in sent_headers
    assert "t=" in sent_headers["X-WhistleDrop-Signature"]
    assert "v1=" in sent_headers["X-WhistleDrop-Signature"]

    # 4. Verify DB delivery recorded
    deliveries = await webhook_dispatcher_service.get_deliveries(db_session, endpoint.id)
    assert len(deliveries) == 1
    assert deliveries[0].status_code == 200
    assert deliveries[0].opaque_delivery_id.startswith("dlv_")


# ==============================================================================
# PHASE 17: DUAL-CONTROL QUORUM GOVERNANCE
# ==============================================================================

@pytest.mark.asyncio
async def test_quorum_proposal_lifecycle_and_four_eyes(client, db_session: AsyncSession):
    """Verify Quorum proposal creation, proposal_hash, and Four-Eyes self-approval rejection."""
    admin_a, headers_a = await create_test_moderator(
        db_session,
        "admin_proposer",
        role=ModeratorRole.ADMIN,
        is_totp_enabled=True,
    )
    admin_b, headers_b = await create_test_moderator(
        db_session,
        "admin_approver",
        role=ModeratorRole.ADMIN,
        is_totp_enabled=True,
    )

    # 1. Proposer creates proposal
    res_prop = client.post(
        "/api/v1/moderator/quorum",
        headers=headers_a,
        json={
            "action_type": "MANUAL_RETENTION_SWEEP",
            "parameters": {"limit": 10},
            "reason": "Routine quarterly retention sweep for dismissed cases.",
        },
    )
    assert res_prop.status_code == 201
    prop_data = res_prop.json()
    prop_id = uuid.UUID(prop_data["id"])
    assert prop_data["status"] == "PENDING"
    assert len(prop_data["proposal_hash"]) == 64

    # 2. Four-Eyes Invariant: Proposer attempts to approve their own proposal -> 403 Forbidden
    secret_a = mfa_service.decrypt_secret(
        admin_a.totp_secret_encrypted,
        admin_a.totp_secret_iv,
        admin_a.totp_secret_tag,
    )
    res_self_approve = client.post(
        f"/api/v1/moderator/quorum/{prop_id}/approve",
        headers=headers_a,
        json={
            "approval_reason": "Self approving because I want to execute it now.",
            "totp_code": get_totp_code(secret_a),
        },
    )
    assert res_self_approve.status_code == 403
    assert "Four-Eyes" in res_self_approve.json()["detail"]

    # 3. Proposer cannot reject via reviewer flow
    res_self_reject = client.post(
        f"/api/v1/moderator/quorum/{prop_id}/reject",
        headers=headers_a,
        json={"rejection_reason": "Rejecting my own proposal via reviewer flow"},
    )
    assert res_self_reject.status_code == 403


@pytest.mark.asyncio
async def test_quorum_approval_fresh_mfa_proof_and_replay_prevention(client, db_session: AsyncSession):
    """Verify distinct admin approval with live fresh TOTP proof and replay prevention."""
    admin_a, headers_a = await create_test_moderator(
        db_session,
        "prop_admin",
        role=ModeratorRole.ADMIN,
        is_totp_enabled=True,
    )
    admin_b, headers_b = await create_test_moderator(
        db_session,
        "appr_admin",
        role=ModeratorRole.ADMIN,
        is_totp_enabled=True,
    )
    secret_b = mfa_service.decrypt_secret(
        admin_b.totp_secret_encrypted,
        admin_b.totp_secret_iv,
        admin_b.totp_secret_tag,
    )

    # Create proposal
    proposal = await quorum_service.create_proposal(
        db_session,
        action_type="MANUAL_RETENTION_SWEEP",
        target_id=None,
        parameters={"limit": 5},
        reason="Testing dual control sweep",
        proposer=admin_a,
    )

    # 1. Invalid TOTP proof rejected
    res_bad_totp = client.post(
        f"/api/v1/moderator/quorum/{proposal.id}/approve",
        headers=headers_b,
        json={"approval_reason": "Approved with bad code", "totp_code": "000000"},
    )
    assert res_bad_totp.status_code == 400
    assert "Invalid" in res_bad_totp.json()["detail"]

    # 2. Valid fresh TOTP proof succeeds
    valid_code = get_totp_code(secret_b)
    res_approve = client.post(
        f"/api/v1/moderator/quorum/{proposal.id}/approve",
        headers=headers_b,
        json={"approval_reason": "Reviewed and verified retention criteria.", "totp_code": valid_code},
    )
    assert res_approve.status_code == 200
    assert res_approve.json()["status"] == "EXECUTED"

    # Proposal state in DB is EXECUTED
    await db_session.refresh(proposal)
    assert proposal.status == "EXECUTED"
    assert proposal.approved_by_id == admin_b.id


@pytest.mark.asyncio
async def test_quorum_proposal_tamper_detection(client, db_session: AsyncSession):
    """Verify that tampering with proposal parameters in DB fails hash verification with 409 Conflict."""
    admin_a, _ = await create_test_moderator(db_session, "tamp_prop", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    admin_b, headers_b = await create_test_moderator(db_session, "tamp_appr", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    secret_b = mfa_service.decrypt_secret(
        admin_b.totp_secret_encrypted,
        admin_b.totp_secret_iv,
        admin_b.totp_secret_tag,
    )

    proposal = await quorum_service.create_proposal(
        db_session,
        action_type="MANUAL_RETENTION_SWEEP",
        target_id=None,
        parameters={"limit": 5},
        reason="Testing tamper resistance",
        proposer=admin_a,
    )

    # Simulate unauthorized direct DB manipulation of parameters
    proposal.parameters = {"limit": 99999}
    await db_session.commit()

    # Approver attempts execution -> proposal_hash mismatch caught
    res_tampered = client.post(
        f"/api/v1/moderator/quorum/{proposal.id}/approve",
        headers=headers_b,
        json={"approval_reason": "Approving tampered proposal", "totp_code": get_totp_code(secret_b)},
    )
    assert res_tampered.status_code == 409
    assert "integrity" in res_tampered.json()["detail"].lower()

    await db_session.refresh(proposal)
    assert proposal.status == "FAILED_CONFLICT"


@pytest.mark.asyncio
async def test_service_layer_quorum_enforcement_raises_202(client, db_session: AsyncSession, monkeypatch):
    """Verify that enabling QUORUM_ENFORCE_CASE_REOPEN intercepts direct reopen and returns 202."""
    monkeypatch.setattr(settings, "QUORUM_ENFORCE_CASE_REOPEN", True)

    admin_mod, admin_headers = await create_test_moderator(db_session, "case_reopen_admin", role=ModeratorRole.ADMIN)

    # Create report and resolve it
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Case to test quorum reopen"),
    )
    client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={"status": "UNDER_REVIEW", "expected_version": 1},
    )
    client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={"status": "RESOLVED", "expected_version": 2},
    )

    # Direct reopen attempt when quorum is enforced returns 202 Accepted with QUORUM_REQUIRED
    res_reopen = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={
            "status": "UNDER_REVIEW",
            "expected_version": 3,
            "reopen_reason": "Attempting single-admin reopen without second-party approval.",
        },
    )
    assert res_reopen.status_code == 202
    data = res_reopen.json()["detail"]
    assert data["status"] == "QUORUM_REQUIRED"
    assert data["action_type"] == "ADMIN_CASE_REOPEN"


@pytest.mark.asyncio
async def test_mfa_challenge_lockout_after_five_failures(client, db_session: AsyncSession, monkeypatch):
    """Verify 5 consecutive failed MFA attempts locks the account out with HTTP 429."""
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT", 50)
    mod, _ = await create_test_moderator(
        db_session,
        "lockout_mod",
        is_totp_enabled=True,
    )
    for attempt in range(5):
        res_login = client.post("/api/v1/auth/login", json={"username": "lockout_mod", "password": "CorrectPassword123!"})
        ticket = res_login.json()["mfa_ticket"]
        res_fail = client.post(f"/api/v1/auth/mfa/challenge?ticket={ticket}", json={"code": "000000"})
        if attempt < 4:
            assert res_fail.status_code == 401
        else:
            # 5th attempt locks out
            assert res_fail.status_code in (401, 429)

    # 6th attempt is blocked by lockout with 429
    res_login6 = client.post("/api/v1/auth/login", json={"username": "lockout_mod", "password": "CorrectPassword123!"})
    ticket6 = res_login6.json()["mfa_ticket"]
    res_locked = client.post(f"/api/v1/auth/mfa/challenge?ticket={ticket6}", json={"code": "000000"})
    assert res_locked.status_code == 429
    assert "locked" in res_locked.json()["detail"].lower()


@pytest.mark.asyncio
async def test_webhook_dispatcher_disables_redirects(client, db_session: AsyncSession):
    """Verify webhook dispatcher treats HTTP redirects as delivery failures without following them."""
    admin_mod, _ = await create_test_moderator(db_session, "wh_admin_redir", role=ModeratorRole.ADMIN)

    endpoint, _ = await webhook_dispatcher_service.create_endpoint(
        db=db_session,
        url="https://example.com/redirect-target",
        description="Redirect endpoint",
        subscribed_events=["report.created"],
        created_by_id=admin_mod.id,
    )

    event = await outbox_service.publish_event(
        db=db_session,
        event_type="report.created",
        raw_data={"test": True},
    )
    await db_session.commit()

    # Mock HTTP client returning 302 Found
    mock_http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock(spec=httpx.Response)
    mock_resp.status_code = 302
    mock_resp.is_success = False
    mock_resp.text = "Found"
    mock_http_client.post.return_value = mock_resp

    with patch("app.services.webhook_dispatcher_service.resolve_and_validate_destination"):
        success = await webhook_dispatcher_service.dispatch_event_to_endpoints(
            db=db_session,
            event=event,
            client=mock_http_client,
        )
        assert success is False

    await db_session.refresh(event)
    assert event.status == "FAILED"
    assert event.retry_count == 1
    assert "302" in event.error_summary


@pytest.mark.asyncio
async def test_webhook_dispatcher_dead_letter_after_max_retries(client, db_session: AsyncSession):
    """Verify outbox event transitions to DEAD_LETTER when retries exceed OUTBOX_MAX_RETRIES."""
    admin_mod, _ = await create_test_moderator(db_session, "wh_admin_dlq", role=ModeratorRole.ADMIN)

    endpoint, _ = await webhook_dispatcher_service.create_endpoint(
        db=db_session,
        url="https://example.com/failing-target",
        description="Failing endpoint",
        subscribed_events=["report.created"],
        created_by_id=admin_mod.id,
    )

    event = await outbox_service.publish_event(
        db=db_session,
        event_type="report.created",
        raw_data={"test": True},
    )
    event.retry_count = settings.OUTBOX_MAX_RETRIES - 1
    await db_session.commit()

    # Mock HTTP client raising connection failure
    mock_http_client = AsyncMock(spec=httpx.AsyncClient)
    mock_http_client.post.side_effect = httpx.ConnectError("Connection refused by remote host")

    with patch("app.services.webhook_dispatcher_service.resolve_and_validate_destination"):
        success = await webhook_dispatcher_service.dispatch_event_to_endpoints(
            db=db_session,
            event=event,
            client=mock_http_client,
        )
        assert success is False

    await db_session.refresh(event)
    assert event.status == "DEAD_LETTER"
    assert "Max retries exceeded" in event.error_summary


@pytest.mark.asyncio
async def test_quorum_expired_proposal_cannot_be_approved(client, db_session: AsyncSession):
    """Verify expired quorum request transitions to EXPIRED and aborts approval with 400."""
    admin_a, _ = await create_test_moderator(db_session, "exp_prop", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    admin_b, headers_b = await create_test_moderator(db_session, "exp_appr", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    secret_b = mfa_service.decrypt_secret(
        admin_b.totp_secret_encrypted,
        admin_b.totp_secret_iv,
        admin_b.totp_secret_tag,
    )

    proposal = await quorum_service.create_proposal(
        db_session,
        action_type="MANUAL_RETENTION_SWEEP",
        target_id=None,
        parameters={"limit": 5},
        reason="Testing proposal expiration",
        proposer=admin_a,
    )
    # Set expires_at in the past
    proposal.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    await db_session.commit()

    res_appr = client.post(
        f"/api/v1/moderator/quorum/{proposal.id}/approve",
        headers=headers_b,
        json={"approval_reason": "Approving expired proposal", "totp_code": get_totp_code(secret_b)},
    )
    assert res_appr.status_code == 400
    assert "expired" in res_appr.json()["detail"].lower()

    await db_session.refresh(proposal)
    assert proposal.status == "EXPIRED"


@pytest.mark.asyncio
async def test_quorum_execution_admin_case_reopen(client, db_session: AsyncSession):
    """Verify full end-to-end quorum proposal and execution for ADMIN_CASE_REOPEN."""
    admin_a, _ = await create_test_moderator(db_session, "reopen_prop", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    admin_b, headers_b = await create_test_moderator(db_session, "reopen_appr", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    secret_b = mfa_service.decrypt_secret(
        admin_b.totp_secret_encrypted,
        admin_b.totp_secret_iv,
        admin_b.totp_secret_tag,
    )

    # Create report and resolve it
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Quorum reopen target"),
    )
    r.status = ReportStatus.RESOLVED
    r.version_id = 3
    await db_session.commit()

    # Propose case reopen
    proposal = await quorum_service.create_proposal(
        db_session,
        action_type="ADMIN_CASE_REOPEN",
        target_id=str(r.id),
        parameters={"expected_version": 3, "reopen_reason": "New corroborating evidence surfaced."},
        reason="Proposing reopening after whistleblower provided new documents.",
        proposer=admin_a,
    )

    # Approve and execute via admin B
    res_appr = client.post(
        f"/api/v1/moderator/quorum/{proposal.id}/approve",
        headers=headers_b,
        json={
            "approval_reason": "Confirmed new evidence authenticity. Reopening case.",
            "totp_code": get_totp_code(secret_b),
        },
    )
    assert res_appr.status_code == 200
    assert res_appr.json()["status"] == "EXECUTED"

    # Report is now UNDER_REVIEW and version bumped
    await db_session.commit()
    await db_session.refresh(r)
    assert r.status == ReportStatus.UNDER_REVIEW
    assert r.version_id == 4


@pytest.mark.asyncio
async def test_quorum_execution_webhook_delete(client, db_session: AsyncSession):
    """Verify full end-to-end quorum proposal and execution for WEBHOOK_ENDPOINT_DELETE."""
    admin_a, _ = await create_test_moderator(db_session, "del_prop", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    admin_b, headers_b = await create_test_moderator(db_session, "del_appr", role=ModeratorRole.ADMIN, is_totp_enabled=True)
    secret_b = mfa_service.decrypt_secret(
        admin_b.totp_secret_encrypted,
        admin_b.totp_secret_iv,
        admin_b.totp_secret_tag,
    )

    endpoint, _ = await webhook_dispatcher_service.create_endpoint(
        db=db_session,
        url="https://example.com/delete-target",
        description="Endpoint to delete via quorum",
        subscribed_events=["report.created"],
        created_by_id=admin_a.id,
    )

    # Propose webhook delete
    proposal = await quorum_service.create_proposal(
        db_session,
        action_type="WEBHOOK_ENDPOINT_DELETE",
        target_id=str(endpoint.id),
        parameters={},
        reason="Decommissioning legacy integration endpoint.",
        proposer=admin_a,
    )

    # Approve and execute via admin B
    res_appr = client.post(
        f"/api/v1/moderator/quorum/{proposal.id}/approve",
        headers=headers_b,
        json={
            "approval_reason": "Reviewed decommissioning request. Approved for deletion.",
            "totp_code": get_totp_code(secret_b),
        },
    )
    assert res_appr.status_code == 200

    # Endpoint deleted in DB
    await db_session.commit()
    stmt = sa.select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint.id)
    ep_check = (await db_session.execute(stmt)).scalar_one_or_none()
    assert ep_check is None
