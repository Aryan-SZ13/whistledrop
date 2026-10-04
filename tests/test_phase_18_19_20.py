from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from typing import Tuple
from unittest.mock import AsyncMock, patch
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import generate_totp_secret, get_totp_code
from app.models.encryption import CaseEncryptionKey
from app.models.enums import MessageSenderType, ModeratorRole, ReportCategory, ReportStatus, ReportUpdateType
from app.models.moderator import Moderator
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.models.case_message import CaseMessage
from app.models.security_state import SystemSecurityState, WarrantCanary
from app.models.transparency import MerkleLeaf, MerkleTreeState, SignedTreeHead
from app.schemas.report import ReportCreate
from app.services.auth_service import auth_service
from app.services.canary_service import canary_service
from app.services.case_channel_service import case_channel_service
from app.services.case_export_service import CaseExportError, case_export_service
from app.services.mfa_service import mfa_service
from app.services.moderator_service import moderator_service
from app.services.payload_encryption_service import (
    DecryptionContext,
    payload_encryption_service,
)
from app.services.report_service import report_service
from app.services.retention_service import retention_service
from app.services.session_service import session_service
from app.services.transparency_service import transparency_service


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
# PHASE 18: APPLICATION-LEVEL PAYLOAD ENCRYPTION & UNIFIED ERASURE
# ==============================================================================

@pytest.mark.asyncio
async def test_alee_report_submission_encrypts_payload(db_session: AsyncSession):
    """Verify report submission encrypts description at rest and leaves plaintext column NULL."""
    payload = ReportCreate(
        category=ReportCategory.CORRUPTION,
        description="Highly sensitive executive embezzlement details in secret ledger.",
    )
    report, case_code = await report_service.create_report(db_session, payload)

    # Direct DB inspection
    stmt = sa.select(Report).where(Report.id == report.id)
    stored_report = (await db_session.execute(stmt)).scalar_one()

    assert stored_report.description is None
    assert stored_report.description_encrypted is not None
    assert stored_report.description_iv is not None
    assert stored_report.description_tag is not None
    assert len(stored_report.description_iv) == 12
    assert len(stored_report.description_tag) == 16
    assert stored_report.description_aad_version == 1

    # Verify per-case DEK is persisted
    stmt_key = sa.select(CaseEncryptionKey).where(CaseEncryptionKey.report_id == report.id)
    key_row = (await db_session.execute(stmt_key)).scalar_one()
    assert key_row.is_destroyed is False
    assert len(key_row.dek_encrypted) == 32
    assert len(key_row.dek_iv) == 12
    assert len(key_row.dek_tag) == 16


@pytest.mark.asyncio
async def test_alee_moderator_reads_decrypted_report(db_session: AsyncSession):
    """Verify moderator read properly decrypts plaintext description."""
    secret_text = "Internal investigation notes regarding regulatory non-compliance."
    payload = ReportCreate(
        category=ReportCategory.SECURITY,
        description=secret_text,
    )
    report, _ = await report_service.create_report(db_session, payload)

    detail = await moderator_service.get_report_detail_by_id(db_session, report.id)
    assert detail is not None
    assert detail.description == secret_text


@pytest.mark.asyncio
async def test_alee_case_message_encryption_and_decryption(db_session: AsyncSession):
    """Verify case channel messages are encrypted at rest and decrypted for participants."""
    report, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.TECHNICAL, description="Financial fraud initial report."),
    )

    # Post whistleblower message
    msg_text = "Follow up with bank transaction ID #998822."
    msg, _ = await case_channel_service.create_message(
        db=db_session,
        report_id=report.id,
        sender_type=MessageSenderType.REPORTER,
        content=msg_text,
    )

    # Direct DB inspection verifies ciphertext
    stmt = sa.select(
        CaseMessage.content,
        CaseMessage.content_encrypted,
        CaseMessage.content_iv,
        CaseMessage.content_tag,
    ).where(CaseMessage.id == msg.id)
    raw_content, raw_encrypted, raw_iv, raw_tag = (await db_session.execute(stmt)).one()
    assert raw_content is None
    assert raw_encrypted is not None
    assert raw_iv is not None
    assert raw_tag is not None

    # Reporter retrieves messages
    rep_list = await case_channel_service.list_messages(
        db=db_session,
        report_id=report.id,
        caller_sender_type=MessageSenderType.REPORTER,
    )
    assert len(rep_list.items) == 1
    assert rep_list.items[0].content == msg_text

    # Moderator retrieves messages
    mod, _ = await create_test_moderator(db_session, "channel_mod_1")
    mod_list = await case_channel_service.list_messages(
        db=db_session,
        report_id=report.id,
        caller_sender_type=MessageSenderType.MODERATOR,
        moderator_id=mod.id,
    )
    assert len(mod_list.items) == 1
    assert mod_list.items[0].content == msg_text


@pytest.mark.asyncio
async def test_alee_report_update_encryption_and_tracking(db_session: AsyncSession):
    """Verify moderator public update is encrypted at rest and decryptable by case-code bearer."""
    report, case_code = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.HARASSMENT, description="Workplace discrimination report."),
    )
    mod, _ = await create_test_moderator(db_session, "update_mod_1")

    update_msg = "Your case has been forwarded to external oversight."
    await moderator_service.add_report_update(
        db=db_session,
        report_id=report.id,
        message=update_msg,
        update_type=ReportUpdateType.PUBLIC_UPDATE,
        expected_version=1,
        moderator_id=mod.id,
    )

    # Direct DB inspection
    stmt = sa.select(ReportUpdate.message, ReportUpdate.message_encrypted).where(ReportUpdate.report_id == report.id)
    raw_message, raw_encrypted = (await db_session.execute(stmt)).one()
    assert raw_message is None
    assert raw_encrypted is not None

    # Anonymous tracking retrieves and decrypts public update
    tracking = await report_service.get_report_tracking(db_session, case_code)
    assert tracking is not None
    assert len(tracking.updates) == 1
    assert tracking.updates[0].message == update_msg


@pytest.mark.asyncio
async def test_alee_aad_mismatch_fails_decryption(db_session: AsyncSession):
    """Verify that tampering with AAD context parameters raises payload integrity error."""
    report, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.TECHNICAL, description="Toxic dump site coordinates."),
    )

    stmt = sa.select(Report).where(Report.id == report.id)
    rep = (await db_session.execute(stmt)).scalar_one()

    # Wrong object_type in AAD must fail tag validation
    with pytest.raises(ValueError, match="Payload integrity violation"):
        await payload_encryption_service.decrypt_payload(
            db=db_session,
            report_id=rep.id,
            object_type="WRONG_OBJECT_TYPE",
            object_id=rep.id,
            field_name="description",
            ciphertext=rep.description_encrypted,
            iv=rep.description_iv,
            tag=rep.description_tag,
            aad_version=rep.description_aad_version,
            context=DecryptionContext.MODERATOR_CASE_READ,
        )


@pytest.mark.asyncio
async def test_alee_unified_cryptographic_erasure_on_withdrawal(db_session: AsyncSession):
    """Verify whistleblower withdrawal transactionally destroys both case payload DEK and evidence DEKs."""
    report, case_code = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.HARASSMENT, description="Confidential harassment log."),
    )

    # Withdraw report
    await retention_service.withdraw_report(
        report_id=report.id,
        reason="Whistleblower requested complete withdrawal.",
        db=db_session,
    )
    await db_session.commit()

    # Verify CaseEncryptionKey is zeroed and marked destroyed
    stmt_key = sa.select(CaseEncryptionKey).where(CaseEncryptionKey.report_id == report.id)
    key_row = (await db_session.execute(stmt_key)).scalar_one()
    assert key_row.is_destroyed is True
    assert key_row.dek_encrypted == b"\x00" * 32
    assert key_row.dek_iv == b"\x00" * 12
    assert key_row.dek_tag == b"\x00" * 16

    # Attempting to decrypt destroyed payload must raise error
    with pytest.raises(ValueError, match="Case encryption key has been destroyed"):
        await payload_encryption_service.unwrap_case_dek(db_session, report.id)


@pytest.mark.asyncio
async def test_alee_key_rewrap(client, db_session: AsyncSession):
    """Verify POST /reports/{report_id}/rewrap-keys rewraps DEK under active KEK."""
    report, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Case to test key rewrap."),
    )
    _, headers = await create_test_moderator(db_session, "rewrap_admin", role=ModeratorRole.ADMIN)

    res = client.post(f"/api/v1/moderator/reports/{report.id}/rewrap-keys", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "rewrapped"
    assert "new_key_version" in data


# ==============================================================================
# PHASE 19: RFC 6962 APPEND-ONLY MERKLE TRANSPARENCY LOG
# ==============================================================================

@pytest.mark.asyncio
async def test_merkle_leaf_committed_atomically_with_report(db_session: AsyncSession):
    """Verify that report creation commits an immutable Merkle leaf with contiguous index."""
    report1, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="First report for Merkle tree."),
    )
    report2, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.TECHNICAL, description="Second report for Merkle tree."),
    )

    receipt1 = getattr(report1, "_merkle_receipt", None)
    receipt2 = getattr(report2, "_merkle_receipt", None)

    assert receipt1 is not None
    assert receipt2 is not None
    assert receipt2.leaf_index == receipt1.leaf_index + 1
    assert receipt2.tree_size == receipt1.tree_size + 1
    assert len(receipt1.leaf_hash) == 64
    assert len(receipt2.leaf_hash) == 64


@pytest.mark.asyncio
async def test_merkle_sth_generation_and_signature(client, db_session: AsyncSession):
    """Verify STH generation computes valid MTH and generates Ed25519 signature."""
    # Ensure at least 2 leaves exist
    await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Report for STH validation A."),
    )
    await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Report for STH validation B."),
    )

    sth = await transparency_service.sign_sth(db_session)
    assert sth.tree_size >= 2
    assert len(sth.root_hash) == 64
    assert len(sth.signature) == 128  # 64 bytes hex-encoded

    # Verify public endpoint
    res = client.get("/api/v1/transparency/sth")
    assert res.status_code == 200
    data = res.json()
    assert data["tree_size"] == sth.tree_size
    assert data["root_hash"] == sth.root_hash
    assert data["signature"] == sth.signature


@pytest.mark.asyncio
async def test_merkle_inclusion_proof_verification(client, db_session: AsyncSession):
    """Verify that inclusion proof is mathematically valid against root hash."""
    report, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description="Report to verify Merkle inclusion."),
    )
    receipt = getattr(report, "_merkle_receipt")
    leaf_index = receipt.leaf_index

    # Sign an STH to capture this leaf
    sth = await transparency_service.sign_sth(db_session)

    res = client.get(f"/api/v1/transparency/proof/inclusion?leaf_index={leaf_index}&tree_size={sth.tree_size}")
    assert res.status_code == 200
    data = res.json()
    assert data["leaf_index"] == leaf_index
    assert data["tree_size"] == sth.tree_size
    assert "audit_path" in data

    # Standalone mathematical verification of the audit path
    is_valid = transparency_service.verify_inclusion_proof_standalone(
        leaf_hash=receipt.leaf_hash,
        leaf_index=leaf_index,
        tree_size=sth.tree_size,
        audit_path=data["audit_path"],
        root_hash=sth.root_hash,
    )
    assert is_valid is True


@pytest.mark.asyncio
async def test_merkle_consistency_proof(client, db_session: AsyncSession):
    """Verify consistency proof between two historical tree sizes."""
    # Create first batch and sign STH 1
    await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Consistency batch 1."),
    )
    sth1 = await transparency_service.sign_sth(db_session)

    # Create second batch and sign STH 2
    await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Consistency batch 2."),
    )
    sth2 = await transparency_service.sign_sth(db_session)

    res = client.get(f"/api/v1/transparency/proof/consistency?first_tree_size={sth1.tree_size}&second_tree_size={sth2.tree_size}")
    assert res.status_code == 200
    data = res.json()
    assert data["first_tree_size"] == sth1.tree_size
    assert data["second_tree_size"] == sth2.tree_size
    assert isinstance(data["consistency_path"], list)


# ==============================================================================
# PHASE 20: WARRANT CANARY, DEAD-MAN SWITCH & EMERGENCY ACCESS SEALING
# ==============================================================================

@pytest.mark.asyncio
async def test_warrant_canary_publishing_and_signature(client, db_session: AsyncSession):
    """Verify warrant canary generation, monotonic sequence, and Ed25519 signature."""
    admin, _ = await create_test_moderator(db_session, "canary_admin", role=ModeratorRole.ADMIN)

    statement = "WhistleDrop has received 0 national security letters or gag orders as of this date."
    canary = await canary_service.publish_canary(
        db=db_session,
        admin_id=admin.id,
        statement_text=statement,
        validity_days=30,
    )
    await db_session.commit()
    assert canary.canary_sequence >= 1
    assert canary.statement_hash == hashlib.sha256(statement.encode("utf-8")).hexdigest()
    assert len(canary.signature) == 128

    # Query public endpoint
    res = client.get("/api/v1/canary/latest")
    assert res.status_code == 200
    data = res.json()
    assert data["canary_sequence"] == canary.canary_sequence
    assert data["is_current"] is True
    assert data["signature"] == canary.signature

    # Query canary history endpoint
    res_hist = client.get("/api/v1/canary/history")
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert len(hist) >= 1


@pytest.mark.asyncio
async def test_dead_man_switch_check_in_with_totp(client, db_session: AsyncSession):
    """Verify dead-man's switch check-in requires valid TOTP and advances window."""
    admin, headers = await create_test_moderator(
        db_session, "dms_admin", role=ModeratorRole.ADMIN, is_totp_enabled=True
    )

    # Get valid TOTP code
    raw_secret = mfa_service.decrypt_secret(
        admin.totp_secret_encrypted, admin.totp_secret_iv, admin.totp_secret_tag
    )
    valid_code = get_totp_code(raw_secret)

    # Invalid code fails
    res_bad = client.post(
        "/api/v1/moderator/security/check-in",
        headers=headers,
        json={"totp_code": "000000"},
    )
    assert res_bad.status_code == 401

    # Valid code succeeds
    res_good = client.post(
        "/api/v1/moderator/security/check-in",
        headers=headers,
        json={"totp_code": valid_code},
    )
    assert res_good.status_code == 200
    assert res_good.json()["status"] == "ok"


# ==============================================================================
# CRITICAL HARDENED INVARIANT: EMERGENCY ACCESS SEALING
# Operator plaintext-access control while preserving whistleblower availability
# ==============================================================================

@pytest.mark.asyncio
async def test_emergency_seal_enforcement_boundary(client, db_session: AsyncSession):
    """
    CRITICAL SECURITY CONTRACT TEST:
    During SEALED state:
    ALLOWED:
      - Anonymous report submission
      - Anonymous case tracking
      - Decryption of PUBLIC_UPDATE content for anonymous tracking
      - Anonymous whistleblower messaging
    BLOCKED:
      - Moderator report plaintext inspection (403)
      - Moderator message plaintext inspection (403)
      - Sensitive case exports (403)
      - Key rewrap operations (403)
    """
    # 1. Setup report and moderator
    report, case_code = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Top secret executive corruption report."),
    )
    mod, mod_headers = await create_test_moderator(db_session, "seal_audit_mod", role=ModeratorRole.ADMIN)

    # Add a public update before sealing
    await moderator_service.add_report_update(
        db=db_session,
        report_id=report.id,
        message="Preliminary investigation commenced.",
        update_type=ReportUpdateType.PUBLIC_UPDATE,
        expected_version=1,
        moderator_id=mod.id,
    )

    # 2. ENGAGE EMERGENCY SEAL
    seal_res = client.post(
        "/api/v1/moderator/security/emergency-seal",
        headers=mod_headers,
        json={"reason": "Compromised credential suspected; emergency containment active."},
    )
    assert seal_res.status_code == 200
    assert seal_res.json()["status"] == "sealed"

    # Verify system security state reflects sealed
    assert await canary_service.is_system_sealed(db_session) is True

    # --------------------------------------------------------------------------
    # VERIFY BLOCKED OPERATIONS FOR OPERATORS / MODERATORS
    # --------------------------------------------------------------------------

    # 3a. Moderator report detail inspection is BLOCKED with 403
    res_mod_view = client.get(f"/api/v1/moderator/reports/{report.id}", headers=mod_headers)
    assert res_mod_view.status_code == 403
    assert "sealed" in res_mod_view.json()["detail"].lower()

    # 3b. Moderator message list inspection is BLOCKED with 403
    res_mod_msg = client.get(f"/api/v1/moderator/reports/{report.id}/messages", headers=mod_headers)
    assert res_mod_msg.status_code == 403

    # 3c. Case export is BLOCKED with 403
    res_mod_export = client.get(f"/api/v1/moderator/reports/{report.id}/export", headers=mod_headers)
    assert res_mod_export.status_code == 403

    # 3d. Key rewrap is BLOCKED with 403
    res_mod_rewrap = client.post(f"/api/v1/moderator/reports/{report.id}/rewrap-keys", headers=mod_headers)
    assert res_mod_rewrap.status_code == 403

    # --------------------------------------------------------------------------
    # VERIFY ALLOWED OPERATIONS FOR ANONYMOUS WHISTLEBLOWERS
    # --------------------------------------------------------------------------

    # 4a. Anonymous report submission SUCCEEDS during seal
    sub_res = client.post(
        "/api/v1/reports",
        json={
            "category": "SECURITY",
            "description": "Hazardous toxic spill occurring right now during emergency seal.",
        },
    )
    assert sub_res.status_code == 201
    new_case_code = sub_res.json()["case_code"]
    assert new_case_code is not None

    # 4b. Anonymous case tracking SUCCEEDS and decrypts PUBLIC_UPDATE during seal
    track_res = client.get(f"/api/v1/reports/{case_code}")
    assert track_res.status_code == 200
    track_data = track_res.json()
    assert len(track_data["updates"]) == 1
    assert track_data["updates"][0]["message"] == "Preliminary investigation commenced."

    # 4c. Whistleblower messaging SUCCEEDS during seal
    msg_post_res = client.post(
        "/api/v1/reports/messages",
        headers={"X-Case-Code": case_code},
        json={"content": "Whistleblower sending message during emergency seal."},
    )
    assert msg_post_res.status_code == 201

    msg_get_res = client.get(
        "/api/v1/reports/messages",
        headers={"X-Case-Code": case_code},
    )
    assert msg_get_res.status_code == 200
    msgs = msg_get_res.json()["items"]
    assert any("Whistleblower sending message" in m["content"] for m in msgs)

    # --------------------------------------------------------------------------
    # 5. DISENGAGE EMERGENCY SEAL & VERIFY RESTORATION
    # --------------------------------------------------------------------------
    unseal_res = client.post("/api/v1/moderator/security/emergency-unseal", headers=mod_headers)
    assert unseal_res.status_code == 200
    assert unseal_res.json()["status"] == "unsealed"

    # Moderator can now inspect report plaintext again
    res_mod_restored = client.get(f"/api/v1/moderator/reports/{report.id}", headers=mod_headers)
    assert res_mod_restored.status_code == 200
    assert res_mod_restored.json()["description"] == "Top secret executive corruption report."
