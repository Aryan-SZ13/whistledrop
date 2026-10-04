from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import uuid
import zipfile

import pytest
import pytest_asyncio
import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.security import create_access_token, derive_case_code_digest, hash_password
from app.db.redis import get_redis
from app.models.audit_log import AuditLog
from app.models.enums import (
    EvidenceScanStatus,
    EvidenceShredStatus,
    ModeratorRole,
    ReportCategory,
    ReportPriority,
    ReportStatus,
)
from app.models.evidence import EvidenceAttachment
from app.models.moderator import Moderator
from app.models.report import Report
from app.services.audit_service import audit_service
from app.services.case_export_service import case_export_service
from app.services.evidence_service import evidence_service
from app.services.retention_service import retention_service
from app.services.shredder_service import shredder_service


@pytest_asyncio.fixture
async def sample_moderator(db_session):
    mod = Moderator(
        username=f"lead_mod_{uuid.uuid4().hex[:6]}",
        password_hash=hash_password("StrongPass123!"),
        role=ModeratorRole.ADMIN,
        is_active=True,
    )
    db_session.add(mod)
    await db_session.commit()
    await db_session.refresh(mod)
    return mod


@pytest_asyncio.fixture
async def moderator_headers(sample_moderator):
    token = create_access_token(subject=str(sample_moderator.id))
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_audit_chain_sequential_hmac_genesis(db_session):
    report = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.CORRUPTION,
        description="Testing genesis audit block with valid character length",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    entry = await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_SUBMITTED",
        actor_type="REPORTER",
        actor_id=None,
        metadata={"category": "CORRUPTION"},
    )
    await db_session.commit()

    assert entry.sequence_number == 1
    assert entry.previous_hash == "0" * 64
    assert len(entry.entry_hash) == 64

    # Verify calculation
    calc = audit_service.compute_entry_hash(
        hash_version=entry.hash_version,
        report_id=report.id,
        sequence_number=1,
        created_at_iso=entry.created_at.isoformat(),
        action="REPORT_SUBMITTED",
        actor_id=None,
        actor_role="SYSTEM",
        details={"category": "CORRUPTION"},
        previous_hash="0" * 64,
    )
    assert entry.entry_hash == calc


@pytest.mark.asyncio
async def test_audit_chain_progression_across_events(db_session, sample_moderator):
    report = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.HARASSMENT,
        description="Testing chain progression across sequential lifecycle events",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    e1 = await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_SUBMITTED",
        actor_type="REPORTER",
        actor_id=None,
        metadata={"step": 1},
    )
    e2 = await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_STATUS_CHANGED",
        actor_type="MODERATOR",
        actor_id=sample_moderator.id,
        metadata={"from": "SUBMITTED", "to": "UNDER_REVIEW"},
    )
    e3 = await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_PRIORITY_CHANGED",
        actor_type="MODERATOR",
        actor_id=sample_moderator.id,
        metadata={"priority": "HIGH"},
    )
    await db_session.commit()

    assert e1.sequence_number == 1
    assert e2.sequence_number == 2
    assert e3.sequence_number == 3

    assert e2.previous_hash == e1.entry_hash
    assert e3.previous_hash == e2.entry_hash

    # Verify entire chain
    res = await audit_service.verify_chain(db_session, report.id)
    assert res["is_valid"] is True
    assert res["total_entries"] == 3
    assert res["broken_sequence_number"] is None


@pytest.mark.asyncio
async def test_audit_chain_verification_detects_tampering(db_session, sample_moderator):
    report = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.CORRUPTION,
        description="Testing tamper detection for chained audit records",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_SUBMITTED",
        actor_type="REPORTER",
        actor_id=None,
        metadata={"test": "genesis"},
    )
    e2 = await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_STATUS_CHANGED",
        actor_type="MODERATOR",
        actor_id=sample_moderator.id,
        metadata={"target": "tamper"},
    )
    await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="REPORT_PRIORITY_CHANGED",
        actor_type="MODERATOR",
        actor_id=sample_moderator.id,
        metadata={"step": "final"},
    )
    await db_session.commit()

    # Tamper with e2's details in the DB directly
    await db_session.execute(
        sa.update(AuditLog)
        .where(AuditLog.id == e2.id)
        .values(metadata_={"target": "hacked_value"})
    )
    await db_session.commit()

    # Verify detection
    res = await audit_service.verify_chain(db_session, report.id)
    assert res["is_valid"] is False
    assert res["broken_sequence_number"] == 2


@pytest.mark.asyncio
async def test_audit_chain_verification_detects_deleted_entry(db_session):
    report = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.TECHNICAL,
        description="Testing entry deletion detection in audit log",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="STEP_1",
        actor_type="REPORTER",
        actor_id=None,
    )
    e2 = await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="STEP_2",
        actor_type="REPORTER",
        actor_id=None,
    )
    await audit_service.append_entry(
        db=db_session,
        report_id=report.id,
        action="STEP_3",
        actor_type="REPORTER",
        actor_id=None,
    )
    await db_session.commit()

    # Delete e2
    await db_session.execute(sa.delete(AuditLog).where(AuditLog.id == e2.id))
    await db_session.commit()

    # Verify detection of broken sequence
    res = await audit_service.verify_chain(db_session, report.id)
    assert res["is_valid"] is False
    assert res["broken_sequence_number"] == 3
    assert "expected 2" in res["error_detail"]


def test_envelope_encryption_roundtrip():
    payload = b"Top secret whistleblower evidence content!"
    enc = shredder_service.encrypt_evidence_content(payload)

    assert enc.ciphertext != payload
    assert len(enc.wrapped_dek) > 0
    assert enc.kek_key_id == settings.EVIDENCE_KEK_KEY_ID

    decrypted = shredder_service.decrypt_evidence_content(
        ciphertext=enc.ciphertext,
        wrapped_dek=enc.wrapped_dek,
        dek_nonce=enc.dek_nonce,
        dek_tag=enc.dek_tag,
        file_nonce=enc.file_nonce,
        file_tag=enc.file_tag,
        kek_key_id=enc.kek_key_id,
    )
    assert decrypted == payload


def test_envelope_encryption_random_deks():
    payload = b"Identical plaintext for both runs"
    enc1 = shredder_service.encrypt_evidence_content(payload)
    enc2 = shredder_service.encrypt_evidence_content(payload)

    assert enc1.wrapped_dek != enc2.wrapped_dek
    assert enc1.ciphertext != enc2.ciphertext
    assert enc1.file_nonce != enc2.file_nonce
    assert enc1.dek_nonce != enc2.dek_nonce


def test_evidence_decryption_fails_with_destroyed_dek():
    payload = b"Payload with key about to be shredded"
    enc = shredder_service.encrypt_evidence_content(payload)

    with pytest.raises(Exception):
        shredder_service.decrypt_evidence_content(
            ciphertext=enc.ciphertext,
            wrapped_dek=b"",  # Invalid/destroyed wrapped DEK
            dek_nonce=enc.dek_nonce,
            dek_tag=enc.dek_tag,
            file_nonce=enc.file_nonce,
            file_tag=enc.file_tag,
            kek_key_id=enc.kek_key_id,
        )


@pytest.mark.asyncio
async def test_evidence_promotion_envelope_encrypts(client: TestClient, db_session):
    # 1. Create report
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "SECURITY",
            "description": "Evidence upload and promotion encryption test description",
        },
    )
    assert res.status_code == 201
    case_code = res.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = (await db_session.execute(stmt_id)).scalar_one()

    # 2. Upload evidence
    content = b"Encrypted on approval payload content"
    files = [("files", ("secret.txt", io.BytesIO(content), "text/plain"))]
    res_up = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=files,
    )
    assert res_up.status_code == 200

    stmt_att = sa.select(EvidenceAttachment).where(
        EvidenceAttachment.report_id == report_id
    )
    att = (await db_session.execute(stmt_att)).scalar_one()

    # 3. Verify in DB that wrapped_dek and envelope metadata exist
    await db_session.refresh(att)
    assert att.wrapped_dek is not None
    assert att.file_nonce is not None
    assert att.file_tag is not None
    assert att.kek_key_id == settings.EVIDENCE_KEK_KEY_ID
    assert att.shred_status == EvidenceShredStatus.ACTIVE.value

    # Verify file on disk is ciphertext, not plaintext
    app_file = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{att.storage_key}.bin"
    assert app_file.is_file()
    c_bytes = app_file.read_bytes()
    assert c_bytes != content


@pytest.mark.asyncio
async def test_moderator_evidence_download_decrypts(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    # 1. Create report
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "SECURITY",
            "description": "Verifying decrypted download for moderator description",
        },
    )
    case_code = res.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = (await db_session.execute(stmt_id)).scalar_one()

    # 2. Upload evidence
    content = b"Verified decrypted evidence for moderator view"
    files = [("files", ("audit.txt", io.BytesIO(content), "text/plain"))]
    res_up = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=files,
    )
    assert res_up.status_code == 200

    stmt_att = sa.select(EvidenceAttachment).where(
        EvidenceAttachment.report_id == report_id
    )
    att = (await db_session.execute(stmt_att)).scalar_one()

    # 3. Download evidence as moderator
    res_dl = client.get(
        f"/api/v1/moderator/reports/{report_id}/evidence/{att.id}",
        headers=moderator_headers,
    )
    assert res_dl.status_code == 200
    assert res_dl.content == content


@pytest.mark.asyncio
async def test_whistleblower_case_withdrawal(client: TestClient, db_session):
    # 1. Create report
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "OTHER",
            "description": "Report to be withdrawn by whistleblower description",
        },
    )
    case_code = res.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = (await db_session.execute(stmt_id)).scalar_one()

    # 2. Upload evidence
    files = [("files", ("evidence.txt", io.BytesIO(b"Confidential notes"), "text/plain"))]
    res_up = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=files,
    )
    assert res_up.status_code == 200

    stmt_att = sa.select(EvidenceAttachment).where(
        EvidenceAttachment.report_id == report_id
    )
    att = (await db_session.execute(stmt_att)).scalar_one()

    # 3. Withdraw case
    res_with = client.post(
        "/api/v1/reports/withdraw",
        headers={"X-Case-Code": case_code},
        json={"reason": "Safety concerns, withdrawing case.", "confirm": True},
    )
    assert res_with.status_code == 200
    data = res_with.json()
    assert data["status"] == "WITHDRAWN"
    assert data["evidence_shred_status"] == EvidenceShredStatus.KEY_DESTROYED.value
    assert data["terminal_at"] is not None

    # 4. Verify DB state: DEK is destroyed, audit tombstones exist
    await db_session.refresh(att)
    assert att.wrapped_dek is None
    assert att.shred_status == EvidenceShredStatus.KEY_DESTROYED.value

    # Check audit log contains REPORT_WITHDRAWN and REPORT_CRYPTOGRAPHICALLY_SHREDDED
    stmt_audit = (
        sa.select(AuditLog)
        .where(AuditLog.report_id == att.report_id)
        .order_by(AuditLog.sequence_number.asc())
    )
    audits = (await db_session.execute(stmt_audit)).scalars().all()
    actions = [a.action for a in audits]
    assert "REPORT_WITHDRAWN" in actions
    assert "REPORT_CRYPTOGRAPHICALLY_SHREDDED" in actions

    # Verify audit chain integrity still holds perfectly
    verify_res = await audit_service.verify_chain(db_session, att.report_id)
    assert verify_res["is_valid"] is True


@pytest.mark.asyncio
async def test_withdrawal_idempotency(client: TestClient):
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "OTHER",
            "description": "Withdrawing twice must succeed idempotently description",
        },
    )
    case_code = res.json()["case_code"]

    res1 = client.post(
        "/api/v1/reports/withdraw",
        headers={"X-Case-Code": case_code},
        json={"reason": "First attempt", "confirm": True},
    )
    assert res1.status_code == 200

    res2 = client.post(
        "/api/v1/reports/withdraw",
        headers={"X-Case-Code": case_code},
        json={"reason": "Second attempt", "confirm": True},
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "WITHDRAWN"


@pytest.mark.asyncio
async def test_case_export_archive_structure_and_signature(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    # 1. Create report with message and evidence
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "SECURITY",
            "description": "Checking ZIP structure and Ed25519 signature description",
        },
    )
    case_code = res.json()["case_code"]

    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = str((await db_session.execute(stmt_id)).scalar_one())

    # Add message
    client.post(
        "/api/v1/reports/messages",
        headers={"X-Case-Code": case_code},
        json={"content": "Export test whistleblower message"},
    )

    # Upload evidence
    evidence_payload = b"Exportable proof payload content"
    files = [("files", ("proof.txt", io.BytesIO(evidence_payload), "text/plain"))]
    res_up = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=files,
    )
    assert res_up.status_code == 200

    stmt_att = sa.select(EvidenceAttachment).where(
        EvidenceAttachment.report_id == uuid.UUID(report_id)
    )
    att = (await db_session.execute(stmt_att)).scalar_one()

    # 2. Call export endpoint
    res_exp = client.get(
        f"/api/v1/moderator/reports/{report_id}/export",
        headers=moderator_headers,
    )
    assert res_exp.status_code == 200
    assert res_exp.headers["Content-Type"] == "application/zip"

    zip_bytes = res_exp.content
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "manifest.json" in namelist
        assert "manifest.sig" in namelist
        assert "signing_key.pub" in namelist
        assert "report_metadata.json" in namelist
        assert "channel_messages.json" in namelist
        assert "audit_chain.json" in namelist

        # Verify decrypted evidence inside ZIP
        ev_files = [n for n in namelist if n.startswith("evidence/")]
        assert len(ev_files) == 1
        assert zf.read(ev_files[0]) == evidence_payload

    # 3. Independent archive verification
    temp_zip = Path(settings.EXPORT_TEMP_DIR) / f"verify_test_{report_id}.zip"
    temp_zip.write_bytes(zip_bytes)
    try:
        is_valid, errors = case_export_service.verify_case_export_archive(temp_zip)
        assert is_valid is True, f"Export verification failed: {errors}"
        assert len(errors) == 0
    finally:
        if temp_zip.is_file():
            temp_zip.unlink()


@pytest.mark.asyncio
async def test_case_export_rejects_untrusted_fingerprint(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "OTHER",
            "description": "Ensuring verification rejects untrusted signing anchors",
        },
    )
    case_code = res.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = str((await db_session.execute(stmt_id)).scalar_one())

    res_exp = client.get(
        f"/api/v1/moderator/reports/{report_id}/export",
        headers=moderator_headers,
    )
    assert res_exp.status_code == 200

    temp_zip = Path(settings.EXPORT_TEMP_DIR) / f"verify_untrusted_{report_id}.zip"
    temp_zip.write_bytes(res_exp.content)
    try:
        # Verify with non-matching trusted fingerprint
        is_valid, errors = case_export_service.verify_case_export_archive(
            temp_zip, trusted_fingerprints=["SHA256:00000000000000000000000000000000"]
        )
        assert is_valid is False
        assert any("Untrusted public key fingerprint" in e for e in errors)
    finally:
        if temp_zip.is_file():
            temp_zip.unlink()


@pytest.mark.asyncio
async def test_case_export_detects_tampered_manifest(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "OTHER",
            "description": "Ensuring modified manifest breaks signature verification",
        },
    )
    case_code = res.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = str((await db_session.execute(stmt_id)).scalar_one())

    res_exp = client.get(
        f"/api/v1/moderator/reports/{report_id}/export",
        headers=moderator_headers,
    )
    assert res_exp.status_code == 200

    # Build tampered archive
    orig_zf = zipfile.ZipFile(io.BytesIO(res_exp.content), "r")
    tampered_buf = io.BytesIO()
    with zipfile.ZipFile(tampered_buf, "w") as new_zf:
        for item in orig_zf.infolist():
            content = orig_zf.read(item.filename)
            if item.filename == "manifest.json":
                m = json.loads(content.decode("utf-8"))
                m["tampered"] = True
                content = json.dumps(m).encode("utf-8")
            new_zf.writestr(item, content)

    temp_zip = Path(settings.EXPORT_TEMP_DIR) / f"verify_tampered_{report_id}.zip"
    temp_zip.write_bytes(tampered_buf.getvalue())
    try:
        is_valid, errors = case_export_service.verify_case_export_archive(temp_zip)
        assert is_valid is False
        assert any("signature verification failed" in e.lower() for e in errors)
    finally:
        if temp_zip.is_file():
            temp_zip.unlink()


@pytest.mark.asyncio
async def test_case_export_fails_on_shredded_case(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "CORRUPTION",
            "description": "Attempting to export a shredded case must return 410 Gone",
        },
    )
    case_code = res.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = (await db_session.execute(stmt_id)).scalar_one()

    # Mark shredded in DB
    await db_session.execute(
        sa.update(Report)
        .where(Report.id == report_id)
        .values(is_shredded=True, shredded_at=datetime.now(timezone.utc))
    )
    await db_session.commit()

    res_exp = client.get(
        f"/api/v1/moderator/reports/{report_id}/export",
        headers=moderator_headers,
    )
    assert res_exp.status_code == 410
    assert "Cannot export shredded case" in res_exp.json()["detail"]


@pytest.mark.asyncio
async def test_whistleblower_verification_receipt(client: TestClient):
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "SECURITY",
            "description": "Whistleblower cryptographic receipt verification description",
        },
    )
    assert res.status_code == 201
    case_code = res.json()["case_code"]

    res_rec = client.get(
        "/api/v1/reports/verification",
        headers={"X-Case-Code": case_code},
    )
    assert res_rec.status_code == 200
    data = res_rec.json()

    assert data["audit_sequence_number"] >= 1
    assert len(data["latest_entry_hash"]) == 64
    assert data["signing_key_id"] == settings.EXPORT_SIGNING_KEY_ID

    # Verify signature
    sig_bytes = bytes.fromhex(data["verification_receipt_signature"])
    assert len(sig_bytes) == 64


@pytest.mark.asyncio
async def test_verification_receipt_rate_limiting(client: TestClient):
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "OTHER",
            "description": "Checking rate limit enforcement description here",
        },
    )
    assert res.status_code == 201
    case_code = res.json()["case_code"]

    # Repeated requests within limit
    for _ in range(settings.VERIFICATION_RECEIPT_RATE_LIMIT):
        r = client.get(
            "/api/v1/reports/verification",
            headers={"X-Case-Code": case_code},
        )
        assert r.status_code == 200

    # Next request must be rate limited
    r_limit = client.get(
        "/api/v1/reports/verification",
        headers={"X-Case-Code": case_code},
    )
    assert r_limit.status_code == 429
    assert "Too many requests" in r_limit.json()["detail"]


@pytest.mark.asyncio
async def test_retention_preview_eligibility(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    now = datetime.now(timezone.utc)

    # 1. Expired report
    rep_expired = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.CORRUPTION,
        description="Expired description with at least 10 chars",
        status=ReportStatus.RESOLVED,
        terminal_at=now - timedelta(days=2),
        is_shredded=False,
    )
    # 2. Active non-expired terminal report
    rep_active = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.CORRUPTION,
        description="Active description with at least 10 chars",
        status=ReportStatus.RESOLVED,
        terminal_at=now + timedelta(days=10),
        is_shredded=False,
    )
    # 3. Already shredded report
    rep_shredded = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.CORRUPTION,
        description="Shredded description with at least 10 chars",
        status=ReportStatus.RESOLVED,
        terminal_at=now - timedelta(days=5),
        is_shredded=True,
    )
    db_session.add_all([rep_expired, rep_active, rep_shredded])
    await db_session.commit()

    # Call preview
    res = client.get("/api/v1/moderator/retention/preview", headers=moderator_headers)
    assert res.status_code == 200
    data = res.json()

    eligible_ids = [item["report_id"] for item in data["reports"]]
    assert str(rep_expired.id) in eligible_ids
    assert str(rep_active.id) not in eligible_ids
    assert str(rep_shredded.id) not in eligible_ids


@pytest.mark.asyncio
async def test_retention_execute_sweep(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    now = datetime.now(timezone.utc)

    # Create expired report
    rep = Report(
        case_code_digest=derive_case_code_digest(f"wdc_{uuid.uuid4().hex}"),
        category=ReportCategory.OTHER,
        description="Sensitive content to be redacted in retention sweep",
        status=ReportStatus.RESOLVED,
        terminal_at=now - timedelta(days=1),
        is_shredded=False,
    )
    db_session.add(rep)
    await db_session.commit()
    await db_session.refresh(rep)

    # Add evidence attachment
    enc = shredder_service.encrypt_evidence_content(b"Sensitive evidence")
    storage_uuid = uuid.uuid4()
    app_file = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{storage_uuid}.bin"
    app_file.parent.mkdir(parents=True, exist_ok=True)
    app_file.write_bytes(enc.ciphertext)

    att = EvidenceAttachment(
        report_id=rep.id,
        storage_key=storage_uuid,
        detected_mime="application/pdf",
        file_size=len(enc.ciphertext),
        sha256_hash=hashlib.sha256(b"Sensitive evidence").hexdigest(),
        scan_status=EvidenceScanStatus.CLEAN,
        shred_status=EvidenceShredStatus.ACTIVE.value,
        wrapped_dek=enc.wrapped_dek,
        dek_nonce=enc.dek_nonce,
        dek_tag=enc.dek_tag,
        file_nonce=enc.file_nonce,
        file_tag=enc.file_tag,
        kek_key_id=enc.kek_key_id,
        encryption_version=enc.encryption_version,
    )
    db_session.add(att)
    await db_session.commit()

    # Run execution sweep
    res = client.post(
        "/api/v1/moderator/retention/execute",
        headers=moderator_headers,
        json={"limit": 50},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["lock_acquired"] is True
    assert data["processed_count"] >= 1
    assert data["shredded_evidence_count"] >= 1

    # Verify report is shredded & description redacted in DB
    await db_session.refresh(rep)
    assert rep.is_shredded is True
    assert rep.shredded_at is not None
    assert "[REDACTED PURSUANT TO DATA RETENTION/WITHDRAWAL POLICY]" in rep.description

    # Verify evidence DEK is shredded
    await db_session.refresh(att)
    assert att.wrapped_dek is None
    assert att.shred_status == EvidenceShredStatus.KEY_DESTROYED.value

    # Verify audit chain has tombstone record
    stmt_audit = (
        sa.select(AuditLog)
        .where(
            AuditLog.report_id == rep.id,
            AuditLog.action == "REPORT_RETENTION_SHREDDED",
        )
    )
    tombstone = (await db_session.execute(stmt_audit)).scalar_one_or_none()
    assert tombstone is not None


@pytest.mark.asyncio
async def test_retention_execute_distributed_lock(
    client: TestClient, sample_moderator, moderator_headers
):
    redis = await get_redis()
    lock_key = "lock:retention_execution"

    # Pre-acquire the lock
    await redis.set(lock_key, "held_by_other_process", ex=60)
    try:
        res = client.post(
            "/api/v1/moderator/retention/execute",
            headers=moderator_headers,
            json={"limit": 10},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["lock_acquired"] is False
        assert data["processed_count"] == 0
    finally:
        await redis.delete(lock_key)


@pytest.mark.asyncio
async def test_audit_export_no_store_headers(
    client: TestClient, db_session, sample_moderator, moderator_headers
):
    res_rep = client.post(
        "/api/v1/reports",
        json={
            "category": "OTHER",
            "description": "Verifying Cache-Control headers with valid character description",
        },
    )
    case_code = res_rep.json()["case_code"]
    stmt_id = sa.select(Report.id).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    report_id = str((await db_session.execute(stmt_id)).scalar_one())

    # 1. Verification receipt
    res_rec = client.get(
        "/api/v1/reports/verification",
        headers={"X-Case-Code": case_code},
    )
    assert res_rec.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert res_rec.headers["Pragma"] == "no-cache"
    assert res_rec.headers["Expires"] == "0"

    # 2. Case withdrawal
    res_with = client.post(
        "/api/v1/reports/withdraw",
        headers={"X-Case-Code": case_code},
        json={"confirm": True},
    )
    assert res_with.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"

    # 3. Case export
    res_exp = client.get(
        f"/api/v1/moderator/reports/{report_id}/export",
        headers=moderator_headers,
    )
    assert res_exp.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"
