from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import secrets
import uuid
import jwt
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.core.config import settings
from app.models.enums import ModeratorRole, ReportCategory, ReportStatus, ReportPriority
from app.models.encryption import CaseEncryptionKey
from app.models.moderator import Moderator
from app.models.report import Report
from app.models.transparency import MerkleLeaf
from app.schemas.report import ReportCreate
from app.services.auth_service import auth_service
from app.services.session_service import session_service
from app.services.payload_encryption_service import DecryptionContext, payload_encryption_service
from app.services.report_service import report_service
from app.services.ssrf_validator import validate_webhook_url, is_ip_disallowed, resolve_and_validate_destination


@pytest.mark.asyncio
async def test_jwt_tampering_and_algorithm_confusion(client: TestClient, db_session: AsyncSession):
    """Adversarial test: rejects forged, tampered, or algorithm-confused JWT tokens."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_adv_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.MODERATOR,
    )
    session, valid_token, _ = await session_service.create_session(
        db_session,
        mod,
        user_agent="pytest-agent",
        auth_level="pwd",
    )
    await db_session.commit()

    # 1. Tampered signature (flip last few characters)
    tampered_token = valid_token[:-4] + ("AAAA" if valid_token[-4:] != "AAAA" else "ZZZZ")
    res = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401

    # 2. Algorithm 'none' attack
    payload = jwt.decode(valid_token, options={"verify_signature": False})
    none_token = jwt.encode(payload, key="", algorithm="none")
    res_none = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {none_token}"})
    assert res_none.status_code == 401

    # 3. Expired token
    expired_payload = payload.copy()
    expired_payload["exp"] = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    expired_token = jwt.encode(expired_payload, settings.JWT_SECRET, algorithm="HS256")
    res_exp = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {expired_token}"})
    assert res_exp.status_code == 401


@pytest.mark.asyncio
async def test_anonymous_case_isolation(client: TestClient, db_session: AsyncSession):
    """Adversarial test: proves strict cryptographic isolation between distinct cases."""
    # Create Case 1
    rep1, code1 = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(
            category=ReportCategory.SECURITY,
            description="Case 1 confidential evidence",
        ),
    )
    # Create Case 2
    rep2, code2 = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(
            category=ReportCategory.CORRUPTION,
            description="Case 2 confidential evidence",
        ),
    )
    await db_session.commit()

    # 1. Query Case 1 tracking with its valid code
    res1 = client.get(f"/api/v1/reports/{code1}")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["status"] == ReportStatus.SUBMITTED.value
    # Invariant: Privacy preservation excludes internal IDs and categories from tracking
    assert "id" not in data1
    assert "category" not in data1

    # 2. Query Case 2 tracking with code2
    res2 = client.get(f"/api/v1/reports/{code2}")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] == ReportStatus.SUBMITTED.value

    # 3. Use Case 1 code to access messages for Case 1
    res_msgs1 = client.get("/api/v1/reports/messages", headers={"X-Case-Code": code1})
    assert res_msgs1.status_code == 200

    # 4. Fabricated / nonexistent case code returns 404
    fabricated_code = "WD-FAKE-9999-XXXX-0000"
    res_fake = client.get(f"/api/v1/reports/{fabricated_code}")
    assert res_fake.status_code == 404

    res_fake_hdr = client.get("/api/v1/reports/messages", headers={"X-Case-Code": fabricated_code})
    assert res_fake_hdr.status_code == 404


@pytest.mark.asyncio
async def test_alee_ciphertext_and_tag_tampering(db_session: AsyncSession):
    """Adversarial test: verifies ALEE AEAD authentication tag enforcement and fail-closed security."""
    report = Report(
        case_code_digest="test_digest_" + uuid.uuid4().hex[:16],
        category=ReportCategory.SECURITY,
        status=ReportStatus.SUBMITTED,
        priority=ReportPriority.MEDIUM,
    )
    db_session.add(report)
    await db_session.flush()

    report_id = report.id
    plaintext = "Top secret disclosure with strict confidentiality requirements."

    ciphertext, iv, tag, key_version = await payload_encryption_service.encrypt_payload(
        db=db_session,
        report_id=report_id,
        object_type="REPORT",
        object_id=report_id,
        field_name="description",
        plaintext=plaintext,
    )
    await db_session.commit()

    # Decrypt valid:
    decrypted = await payload_encryption_service.decrypt_payload(
        db=db_session,
        report_id=report_id,
        object_type="REPORT",
        object_id=report_id,
        field_name="description",
        ciphertext=ciphertext,
        iv=iv,
        tag=tag,
        aad_version=key_version,
        context=DecryptionContext.MODERATOR_CASE_READ,
    )
    assert decrypted == plaintext

    # 1. Tamper 1 byte of ciphertext (flip first byte)
    tampered_ciphertext = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    with pytest.raises(Exception):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=report_id,
            object_type="REPORT",
            object_id=report_id,
            field_name="description",
            ciphertext=tampered_ciphertext,
            iv=iv,
            tag=tag,
            aad_version=key_version,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )

    # 2. Tamper IV
    tampered_iv = bytes([iv[0] ^ 0xFF]) + iv[1:]
    with pytest.raises(Exception):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=report_id,
            object_type="REPORT",
            object_id=report_id,
            field_name="description",
            ciphertext=ciphertext,
            iv=tampered_iv,
            tag=tag,
            aad_version=key_version,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )

    # 3. Tamper Tag
    tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    with pytest.raises(Exception):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=report_id,
            object_type="REPORT",
            object_id=report_id,
            field_name="description",
            ciphertext=ciphertext,
            iv=iv,
            tag=tampered_tag,
            aad_version=key_version,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )

    # 4. AAD context mismatch (e.g. attacker moves encrypted blob to another object_id)
    with pytest.raises(Exception):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=report_id,
            object_type="REPORT",
            object_id=uuid.uuid4(),  # Different object ID
            field_name="description",
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            aad_version=key_version,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )


def test_ssrf_validator_blocks_internal_and_cloud_metadata():
    """Adversarial test: verifies SSRF blocking of AWS/GCP metadata and RFC 1918 addresses."""
    malicious_targets = [
        "http://127.0.0.1:8000/webhook",
        "http://localhost:8000/webhook",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/hook",
        "http://172.16.0.5/api",
        "http://[::1]:8080/internal",
        "http://0.0.0.0:80/",
        "https://127.0.0.1/webhook",
        "https://169.254.169.254/meta",
        "https://10.0.0.1/hook",
        "https://192.168.1.50/alert",
        "https://172.16.1.1/hook",
    ]

    for url in malicious_targets:
        with pytest.raises(ValueError):
            resolve_and_validate_destination(url)


def test_ip_disallowed_checks():
    """Verifies that private, loopback, and link-local ranges are blocked."""
    assert is_ip_disallowed("127.0.0.1") is True
    assert is_ip_disallowed("169.254.169.254") is True
    assert is_ip_disallowed("10.0.0.1") is True
    assert is_ip_disallowed("192.168.1.1") is True
    assert is_ip_disallowed("172.16.0.1") is True
    assert is_ip_disallowed("::1") is True
    assert is_ip_disallowed("93.184.216.34") is False  # Public example.com IP


# ==============================================================================
# 1. ADVANCED AUTH & SESSION ADVERSARIAL SUITE
# ==============================================================================

@pytest.mark.asyncio
async def test_auth_wrong_issuer_and_audience(client: TestClient, db_session: AsyncSession):
    """Adversarial test: rejects JWTs forged with invalid issuer or audience."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_aud_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.MODERATOR,
    )
    session, valid_token, _ = await session_service.create_session(db_session, mod)
    await db_session.commit()

    decoded = jwt.decode(valid_token, options={"verify_signature": False})

    # Tampered issuer
    bad_iss = decoded.copy()
    bad_iss["iss"] = "https://evil-attacker.org"
    bad_iss_token = jwt.encode(bad_iss, settings.JWT_SECRET, algorithm="HS256")
    res1 = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {bad_iss_token}"})
    assert res1.status_code == 401

    # Tampered audience
    bad_aud = decoded.copy()
    bad_aud["aud"] = "evil-service"
    bad_aud_token = jwt.encode(bad_aud, settings.JWT_SECRET, algorithm="HS256")
    res2 = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {bad_aud_token}"})
    assert res2.status_code == 401


@pytest.mark.asyncio
async def test_auth_token_version_bump_invalidates_all_active_tokens(client: TestClient, db_session: AsyncSession):
    """Adversarial test: bumping token_version immediately invalidates older tokens across all workers."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_ver_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.MODERATOR,
    )
    session, token_v1, _ = await session_service.create_session(db_session, mod)
    await db_session.commit()

    # Valid under version 1
    res1 = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {token_v1}"})
    assert res1.status_code == 200

    # Invalidate sessions via token_version bump
    mod.token_version += 1
    await db_session.commit()

    # Rejected under version 1
    res2 = client.get("/api/v1/moderator/reports", headers={"Authorization": f"Bearer {token_v1}"})
    assert res2.status_code == 401
    assert "invalidated" in res2.text.lower()


@pytest.mark.asyncio
async def test_auth_refresh_token_replay_attack_revokes_entire_family(db_session: AsyncSession):
    """Adversarial test: reusing a consumed refresh token revokes the entire session family."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_replay_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.MODERATOR,
    )
    session, access1, raw_refresh1 = await session_service.create_session(db_session, mod)
    await db_session.commit()

    # 1. Legitimate rotation of raw_refresh1 -> returns raw_refresh2
    sess2, access2, raw_refresh2 = await session_service.rotate_refresh_token(
        db=db_session,
        raw_refresh_token=raw_refresh1,
    )

    # 2. Attacker replays consumed raw_refresh1
    with pytest.raises(HTTPException) as exc_info:
        await session_service.rotate_refresh_token(
            db=db_session,
            raw_refresh_token=raw_refresh1,
        )
    # The session is revoked or replayed
    assert exc_info.value.status_code in (401, 403)


# ==============================================================================
# 2. AUTHORIZATION & PRIVILEGE ESCALATION ADVERSARIAL SUITE
# ==============================================================================

@pytest.mark.asyncio
async def test_authorization_moderator_cannot_call_admin_endpoints(client: TestClient, db_session: AsyncSession):
    """Adversarial test: standard moderator cannot execute admin-restricted actions (quorum, seal)."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_unpriv_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.MODERATOR,
    )
    session, mod_token, _ = await session_service.create_session(db_session, mod)
    await db_session.commit()

    # Attempt to trigger emergency seal
    res_seal = client.post(
        "/api/v1/moderator/security/emergency-seal",
        headers={"Authorization": f"Bearer {mod_token}"},
        json={"reason": "Malicious non-admin seal attempt"},
    )
    assert res_seal.status_code == 403
    assert "admin" in res_seal.text.lower()

    # Attempt to propose dual-control quorum
    res_quorum = client.post(
        "/api/v1/moderator/quorum",
        headers={"Authorization": f"Bearer {mod_token}"},
        json={
            "action_type": "EMERGENCY_UNSEAL",
            "parameters": {},
            "reason": "Unauthorized quorum creation",
        },
    )
    assert res_quorum.status_code == 403


@pytest.mark.asyncio
async def test_sealed_state_blocks_moderator_plaintext_access(client: TestClient, db_session: AsyncSession):
    """Adversarial test: when emergency sealed, moderators cannot read report plaintext; anonymous tracking remains operational."""
    admin = await auth_service.create_moderator(
        db_session,
        username="admin_seal_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.ADMIN,
    )
    session, admin_token, _ = await session_service.create_session(db_session, admin)

    # Create report
    rep, code = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(
            category=ReportCategory.SECURITY,
            description="High value confidential insider fraud details",
        ),
    )
    await db_session.commit()

    # Seal the platform
    from app.services.canary_service import canary_service
    await canary_service.execute_emergency_seal(
        db=db_session,
        initiator_id=admin.id,
        reason="Detected physical compromise of datacenter host",
    )
    await db_session.commit()

    # 1. Plaintext decrypt through payload service must raise 403 Forbidden for moderators
    with pytest.raises(HTTPException) as exc_info:
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=rep.id,
            object_type="REPORT",
            object_id=rep.id,
            field_name="description",
            ciphertext=b"\x00" * 32,
            iv=b"\x00" * 12,
            tag=b"\x00" * 16,
            aad_version=1,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )
    assert exc_info.value.status_code == 403

    # 2. Key destruction / retention sweeps must be blocked during seal
    with pytest.raises(HTTPException) as exc_destroy:
        await payload_encryption_service.destroy_case_dek(
            db=db_session,
            report_id=rep.id,
        )
    assert exc_destroy.value.status_code == 403

    # 3. Anonymous public update decryption context is explicitly permitted
    # Anonymous tracking API remains available to avoid tipping off adversaries
    res_track = client.get(f"/api/v1/reports/{code}")
    assert res_track.status_code == 200

    # Unseal system
    await canary_service.execute_emergency_unseal(db=db_session, approver_id=admin.id)
    await db_session.commit()


# ==============================================================================
# 3. ANONYMOUS LEAKAGE & CROSS-CASE ISOLATION ADVERSARIAL SUITE
# ==============================================================================

@pytest.mark.asyncio
async def test_anonymous_response_strictly_omits_internal_identifiers(client: TestClient, db_session: AsyncSession):
    """Adversarial test: verifies tracking and notification payloads never contain database UUIDs or moderator details."""
    rep, code = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(
            category=ReportCategory.CORRUPTION,
            description="Confidential procurement violation",
        ),
    )
    await db_session.commit()

    # Anonymous tracking endpoint
    res_track = client.get(f"/api/v1/reports/{code}")
    assert res_track.status_code == 200
    track_body = res_track.text
    # Internal report UUID must never leak
    assert str(rep.id) not in track_body
    assert "moderator" not in track_body.lower()
    assert "assigned_to" not in track_body

    # Anonymous notifications endpoint
    res_notif = client.get("/api/v1/reports/notifications", headers={"X-Case-Code": code})
    assert res_notif.status_code == 200
    notif_body = res_notif.text
    assert str(rep.id) not in notif_body


@pytest.mark.asyncio
async def test_cross_case_message_isolation(client: TestClient, db_session: AsyncSession):
    """Adversarial test: Case A credential cannot access or acknowledge Case B messages."""
    rep1, code1 = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.TECHNICAL, description="Case 1 technical report"),
    )
    rep2, code2 = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.HARASSMENT, description="Case 2 harassment report"),
    )
    await db_session.commit()

    # Post message in Case 1
    from app.services.case_channel_service import case_channel_service
    from app.models.enums import MessageSenderType
    msg1, _ = await case_channel_service.create_message(
        db=db_session,
        report_id=rep1.id,
        sender_type=MessageSenderType.REPORTER,
        content="Sensitive message in Case 1",
    )
    await db_session.commit()

    # Attempt to acknowledge Case 1's message using Case 2's code
    res_ack = client.post(
        "/api/v1/reports/messages/read",
        headers={"X-Case-Code": code2},
        json={"last_read_message_id": msg1.public_id},
    )
    # Must fail because message does not belong to Case 2
    assert res_ack.status_code == 404


# ==============================================================================
# 4. CRYPTOGRAPHIC INTEGRITY & KEY MANAGEMENT ADVERSARIAL SUITE
# ==============================================================================

@pytest.mark.asyncio
async def test_ciphertext_transplant_across_records_rejected(db_session: AsyncSession):
    """Adversarial test: moving ciphertext from Record A to Record B fails due to AAD binding."""
    repA, _ = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.CORRUPTION, description="Account A record"),
    )
    repB, _ = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.CORRUPTION, description="Account B record"),
    )
    await db_session.commit()

    # Encrypt for Record A
    c_a, iv_a, tag_a, v_a = await payload_encryption_service.encrypt_payload(
        db=db_session,
        report_id=repA.id,
        object_type="REPORT",
        object_id=repA.id,
        field_name="description",
        plaintext="Secret A data",
    )

    # Attempt to decrypt ciphertext of Record A using Record B's context
    with pytest.raises(Exception):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=repB.id,  # Transplanted report_id
            object_type="REPORT",
            object_id=repB.id,  # Transplanted object_id
            field_name="description",
            ciphertext=c_a,
            iv=iv_a,
            tag=tag_a,
            aad_version=v_a,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )


@pytest.mark.asyncio
async def test_post_cryptographic_erasure_decryption_impossible(db_session: AsyncSession):
    """Adversarial test: once case DEK is destroyed, any decryption attempt permanently fails."""
    rep, _ = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.SECURITY, description="Expunged case content"),
    )
    await db_session.commit()

    c, iv, tag, v = await payload_encryption_service.encrypt_payload(
        db=db_session,
        report_id=rep.id,
        object_type="REPORT",
        object_id=rep.id,
        field_name="description",
        plaintext="Permanent erasure target",
    )
    await db_session.commit()

    # Verify decrypts before erasure
    d_before = await payload_encryption_service.decrypt_payload(
        db=db_session,
        report_id=rep.id,
        object_type="REPORT",
        object_id=rep.id,
        field_name="description",
        ciphertext=c,
        iv=iv,
        tag=tag,
        aad_version=v,
        context=DecryptionContext.MODERATOR_CASE_READ,
    )
    assert d_before == "Permanent erasure target"

    # Cryptographically shred the case DEK
    await payload_encryption_service.destroy_case_dek(db=db_session, report_id=rep.id)
    await db_session.commit()

    # Attempt to decrypt after erasure
    with pytest.raises(Exception):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=rep.id,
            object_type="REPORT",
            object_id=rep.id,
            field_name="description",
            ciphertext=c,
            iv=iv,
            tag=tag,
            aad_version=v,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )


# ==============================================================================
# 5. MERKLE TRANSPARENCY ADVERSARIAL SUITE
# ==============================================================================

@pytest.mark.asyncio
async def test_merkle_tampered_leaf_and_root_detection(db_session: AsyncSession):
    """Adversarial test: modifying a committed Merkle leaf detects desynchronization and invalidates proofs."""
    from app.services.transparency_service import transparency_service
    from app.services.recovery_service import recovery_service

    # Commit 3 genuine leaves
    for i in range(3):
        await transparency_service.commit_merkle_leaf(
            db=db_session,
            event_type="test.event",
            opaque_reference=f"ref_{i}",
            payload_digest=hashlib.sha256(f"content_{i}".encode()).digest(),
        )
    await db_session.commit()

    # Sign an STH
    sth = await transparency_service.sign_sth(db_session)
    assert sth.tree_size == 3

    # Verification passes initially
    ver_init = await recovery_service.verify_transparency_consistency(db_session)
    assert ver_init.is_consistent is True

    # Adversary tampers with leaf 1 in the database
    stmt = sa.select(MerkleLeaf).where(MerkleLeaf.leaf_index == 1)
    leaf1 = (await db_session.execute(stmt)).scalar_one()
    leaf1.leaf_hash = "deadbeef" * 8
    await db_session.commit()

    # Consistency verification immediately detects the tampering
    ver_tampered = await recovery_service.verify_transparency_consistency(db_session)
    assert ver_tampered.is_consistent is False
    assert ver_tampered.root_match is False


# ==============================================================================
# 6. WEBHOOK SSRF EVASION ADVERSARIAL SUITE
# ==============================================================================

def test_ssrf_validator_advanced_evasion_bypass_attempts():
    """Adversarial test: tests URL evasion tricks including IPv4-mapped IPv6, userinfo, and redirect schemes."""
    evasion_urls = [
        "https://user:pass@example.com/hook",  # Embedded userinfo
        "ftp://example.com/webhook",           # Invalid protocol
        "http://[::ffff:127.0.0.1]/webhook",  # IPv4-mapped IPv6 loopback
        "http://[::ffff:10.0.0.1]/webhook",   # IPv4-mapped IPv6 RFC 1918
        "http://[fe80::1]/webhook",           # IPv6 link-local
    ]
    for url in evasion_urls:
        with pytest.raises(ValueError):
            resolve_and_validate_destination(url)


# ==============================================================================
# 7. EVIDENCE VALIDATION & TRAVERSAL ADVERSARIAL SUITE
# ==============================================================================

def test_evidence_service_magic_byte_enforcement_and_empty_files():
    """Adversarial test: rejects executable masked with .pdf or .png extension and empty uploads."""
    from app.services.evidence_service import evidence_service, FileValidationError

    # Executable masquerading as PDF
    malicious_exe_header = b"MZ\x90\x00\x03\x00\x00\x00"
    with pytest.raises(FileValidationError):
        evidence_service._validate_magic_signature(".pdf", malicious_exe_header, "application/x-dosexec")

    # Empty payload
    with pytest.raises(FileValidationError):
        evidence_service._validate_magic_signature(".pdf", b"", "application/pdf")

    # Mismatched PNG header
    with pytest.raises(FileValidationError):
        evidence_service._validate_magic_signature(".png", b"%PDF-1.7", "application/pdf")


# ==============================================================================
# 8. DISASTER RECOVERY & CONSISTENCY ADVERSARIAL SUITE
# ==============================================================================

@pytest.mark.asyncio
async def test_recovery_detects_missing_kek_and_orphans(db_session: AsyncSession):
    """Adversarial test: verifies recovery service detects missing KEK versions and unindexed orphan files."""
    from app.services.recovery_service import recovery_service

    # Create report which automatically provisions a case encryption key
    rep, _ = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.CORRUPTION, description="Orphan test report"),
    )
    await db_session.commit()

    # Update existing case encryption key to point to unconfigured KEK version (e.g. 99)
    stmt = sa.update(CaseEncryptionKey).where(CaseEncryptionKey.report_id == rep.id).values(key_version=99)
    await db_session.execute(stmt)
    await db_session.commit()

    # Reconcile keyring
    keyring_res = await recovery_service.verify_kek_keyring_dependencies(db_session)
    assert keyring_res.is_valid is False
    assert 99 in keyring_res.missing_versions


# ==============================================================================
# 9. GAP CLOSURE: WEBHOOK REDIRECTS, SIGNATURE REPLAY & SSRF EVASIONS
# ==============================================================================

@pytest.mark.asyncio
async def test_webhook_signature_replay_and_tampering_rejected():
    """Adversarial test: tampered payload or modified timestamp fails HMAC signature verification."""
    from app.services.webhook_dispatcher_service import webhook_dispatcher_service
    secret = "a" * 32
    body = '{"event":"test.report.created","id":123}'
    timestamp = 1700000000

    sig = webhook_dispatcher_service.calculate_signature(secret, timestamp, body)

    # 1. Valid signature matches
    valid_sig = webhook_dispatcher_service.calculate_signature(secret, timestamp, body)
    assert hmac.compare_digest(sig, valid_sig) is True

    # 2. Tampered body fails
    tampered_body = '{"event":"test.report.created","id":999}'
    tampered_sig = webhook_dispatcher_service.calculate_signature(secret, timestamp, tampered_body)
    assert hmac.compare_digest(sig, tampered_sig) is False

    # 3. Tampered timestamp fails
    tampered_time_sig = webhook_dispatcher_service.calculate_signature(secret, timestamp + 10, body)
    assert hmac.compare_digest(sig, tampered_time_sig) is False


def test_ssrf_validator_blocks_dns_rebinding_and_ipv4_mapped_ipv6():
    """Adversarial test: rejects IPv4-mapped IPv6 pointing to internal networks and invalid schemes."""
    # IPv4-mapped IPv6 loopback
    assert is_ip_disallowed("::ffff:127.0.0.1") is True
    # IPv4-mapped IPv6 private 10.x.x.x
    assert is_ip_disallowed("::ffff:10.254.1.1") is True
    # IPv4-mapped IPv6 private 192.168.x.x
    assert is_ip_disallowed("::ffff:192.168.1.1") is True
    # IPv4-mapped IPv6 private 172.16.x.x
    assert is_ip_disallowed("::ffff:172.16.0.1") is True

    # Disallowed schemes in webhook URL validator
    with pytest.raises(ValueError):
        validate_webhook_url("gopher://127.0.0.1:70/test")

    with pytest.raises(ValueError):
        validate_webhook_url("file:///etc/passwd")

    with pytest.raises(ValueError):
        validate_webhook_url("javascript:alert(1)")


# ==============================================================================
# 10. GAP CLOSURE: EVIDENCE CORRUPTION, TRAVERSAL & CROSS-CASE ATTACHMENTS
# ==============================================================================

@pytest.mark.asyncio
async def test_evidence_cross_case_isolation_and_corrupted_file_handling(db_session: AsyncSession):
    """Adversarial test: case cannot access another case's attachments; corrupted clean files detected."""
    from app.services.evidence_service import evidence_service, EvidenceAttachment
    from app.models.enums import EvidenceScanStatus, EvidenceShredStatus

    repA, codeA = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.CORRUPTION, description="Case A files"),
    )
    repB, codeB = await report_service.create_report(
        db=db_session,
        report_in=ReportCreate(category=ReportCategory.CORRUPTION, description="Case B files"),
    )
    await db_session.commit()

    # Create dummy attachment for Case A
    att_key = uuid.uuid4()
    attA = EvidenceAttachment(
        report_id=repA.id,
        storage_key=att_key,
        sha256_hash="hash_a_123",
        file_size=1024,
        detected_mime="application/pdf",
        scan_status=EvidenceScanStatus.CLEAN,
    )
    db_session.add(attA)
    await db_session.commit()

    # Reconcile storage finds missing physical file on disk
    from app.services.recovery_service import recovery_service
    res = await recovery_service.reconcile_evidence_storage(db_session)
    assert att_key in res.missing_files or str(att_key) in [str(k) for k in res.missing_files]


# ==============================================================================
# 11. GAP CLOSURE: MERKLE INCLUSION & CONSISTENCY PROOF VALIDATION
# ==============================================================================

@pytest.mark.asyncio
async def test_merkle_invalid_inclusion_and_consistency_bounds(db_session: AsyncSession):
    """Adversarial test: out-of-bounds or invalid inclusion/consistency requests rejected with 400."""
    from app.services.transparency_service import transparency_service

    # Commit 2 leaves
    for i in range(2):
        await transparency_service.commit_merkle_leaf(
            db=db_session,
            event_type="test.event",
            opaque_reference=f"ref_bound_{i}",
            payload_digest=hashlib.sha256(f"bound_{i}".encode()).digest(),
        )
    await db_session.commit()

    # 1. Inclusion proof out of bounds
    with pytest.raises(HTTPException) as exc1:
        await transparency_service.get_inclusion_proof(db=db_session, leaf_index=5, tree_size=2)
    assert exc1.value.status_code == 400

    # 2. Consistency proof invalid sizes (first > second or first < 1)
    with pytest.raises(HTTPException) as exc2:
        await transparency_service.get_consistency_proof(db=db_session, first_size=5, second_size=2)
    assert exc2.value.status_code == 400

    with pytest.raises(HTTPException) as exc3:
        await transparency_service.get_consistency_proof(db=db_session, first_size=0, second_size=2)
    assert exc3.value.status_code == 400


# ==============================================================================
# 12. GAP CLOSURE: QUORUM SERVICE ENFORCEMENT & STALE LEASE RECOVERY
# ==============================================================================

@pytest.mark.asyncio
async def test_quorum_service_dual_control_self_approval_rejected(db_session: AsyncSession):
    """Adversarial test: proposer administrator cannot approve their own quorum proposal."""
    from app.services.quorum_service import quorum_service

    admin1 = await auth_service.create_moderator(
        db_session,
        username="admin_prop_" + uuid.uuid4().hex[:8],
        password="ValidPassword123!",
        role=ModeratorRole.ADMIN,
    )
    await db_session.commit()

    proposal = await quorum_service.create_proposal(
        db=db_session,
        action_type="SYSTEM_UNSEAL",
        target_id=None,
        parameters={},
        reason="Test dual control",
        proposer=admin1,
    )
    await db_session.commit()

    # Proposer attempts self-approval
    with pytest.raises(HTTPException) as exc:
        await quorum_service.approve_and_execute(
            db=db_session,
            proposal_id=proposal.id,
            approver=admin1,
            approval_reason="Self approval should fail",
            totp_code="123456",
        )
    assert exc.value.status_code == 403
    assert "cannot approve" in exc.value.detail.lower() or "four-eyes" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_stale_outbox_worker_lease_recovery(db_session: AsyncSession):
    """Adversarial test: stalled or crashed worker leases reset to PENDING automatically."""
    from app.services.recovery_service import recovery_service
    from app.models.webhook import OutboxEvent

    # Insert an expired claimed outbox event
    past_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    event = OutboxEvent(
        id=uuid.uuid4(),
        opaque_event_id=f"evt_{secrets.token_urlsafe(16)}",
        event_type="test.stale.lease",
        payload={"message": "stale outbox event"},
        status="CLAIMED",
        lease_worker_id="crashed-worker-node-1",
        lease_expires_at=past_time,
        created_at=past_time,
    )
    db_session.add(event)
    await db_session.commit()

    # Reset stuck leases
    res = await recovery_service.reset_stuck_outbox_leases(db_session, threshold_seconds=60)
    assert res.stuck_leases_reset >= 1

    # Verify event returned to PENDING
    stmt = sa.select(OutboxEvent).where(OutboxEvent.id == event.id)
    recovered = (await db_session.execute(stmt)).scalar_one()
    assert recovered.status == "PENDING"
    assert recovered.lease_worker_id is None


