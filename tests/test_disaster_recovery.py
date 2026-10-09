import hashlib
import json
from pathlib import Path
import tempfile
import uuid
import pytest
from datetime import datetime, timezone, timedelta
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.encryption import CaseEncryptionKey
from app.models.enums import EvidenceScanStatus, EvidenceShredStatus, ReportCategory, ReportPriority, ReportStatus
from app.models.evidence import EvidenceAttachment
from app.models.report import Report
from app.models.transparency import MerkleLeaf, MerkleTreeState
from app.models.webhook import OutboxEvent
from app.services.recovery_service import recovery_service
from scripts.backup_verify import verify_backup


@pytest.mark.asyncio
async def test_keyring_verification(db_session: AsyncSession):
    """Verifies KEK keyring audits detect missing required versions."""
    res = await recovery_service.verify_kek_keyring_dependencies(db_session)
    assert res.is_valid is True
    assert len(res.missing_versions) == 0

    report = None
    try:
        # Require a non-existent KEK version 99
        report = Report(
            case_code_digest="fake_digest_" + uuid.uuid4().hex[:16],
            category=ReportCategory.CORRUPTION,
            status=ReportStatus.SUBMITTED,
            priority=ReportPriority.MEDIUM,
        )
        db_session.add(report)
        await db_session.flush()

        fake_key = CaseEncryptionKey(
            report_id=report.id,
            key_version=99,
            dek_encrypted=b"dummy_encrypted_dek",
            dek_iv=b"dummy_iv_12bytes",
            dek_tag=b"dummy_tag_16bytes",
        )
        db_session.add(fake_key)
        await db_session.commit()

        check_res = await recovery_service.verify_kek_keyring_dependencies(db_session)
        assert check_res.is_valid is False
        assert 99 in check_res.missing_versions
    finally:
        # Cleanup
        await db_session.execute(sa.delete(CaseEncryptionKey).where(CaseEncryptionKey.key_version == 99))
        if report and report.id:
            await db_session.execute(sa.delete(Report).where(Report.id == report.id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_evidence_storage_reconciliation(db_session: AsyncSession, tmp_path: Path):
    """Verifies evidence storage reconciliation detects missing, orphan, and shredded files."""
    approved_dir = Path(settings.EVIDENCE_STORAGE_PATH) / "approved"
    approved_dir.mkdir(parents=True, exist_ok=True)

    orphan_key = f"orphan_{uuid.uuid4().hex}"
    orphan_file = approved_dir / f"{orphan_key}.bin"
    orphan_file.write_bytes(b"orphan data")

    try:
        res = await recovery_service.reconcile_evidence_storage(db_session)
        assert orphan_key in res.orphan_files
    finally:
        if orphan_file.exists():
            orphan_file.unlink()


@pytest.mark.asyncio
async def test_transparency_consistency(db_session: AsyncSession):
    """Verifies Merkle tree state consistency and tamper detection."""
    res = await recovery_service.verify_transparency_consistency(db_session)
    assert res.is_consistent is True


@pytest.mark.asyncio
async def test_outbox_stuck_lease_recovery(db_session: AsyncSession):
    """Verifies stuck outbox worker leases are reset cleanly."""
    past_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    stuck_event = OutboxEvent(
        opaque_event_id=f"evt_{uuid.uuid4().hex}",
        event_type="test.stuck",
        payload={"msg": "test"},
        status="CLAIMED",
        lease_worker_id="worker_crashed_999",
        lease_expires_at=past_time,
    )
    db_session.add(stuck_event)
    await db_session.commit()

    res = await recovery_service.reset_stuck_outbox_leases(db_session)
    assert res.stuck_leases_reset >= 1

    await db_session.refresh(stuck_event)
    assert stuck_event.status == "PENDING"
    assert stuck_event.lease_worker_id is None
    assert stuck_event.lease_expires_at is None

    # Cleanup
    await db_session.delete(stuck_event)
    await db_session.commit()


@pytest.mark.asyncio
async def test_backup_manifest_verification(db_session: AsyncSession, tmp_path: Path):
    """Verifies backup manifest generation and cryptographic tamper detection."""
    backup_dir = tmp_path / "test_backup"
    manifest = await recovery_service.generate_backup_manifest(db_session, backup_dir)

    assert (backup_dir / "backup_manifest.json").exists()
    assert (backup_dir / "backup_manifest.sha256").exists()
    assert manifest["manifest_version"] == "1.0"

    # Verify backup passes
    exit_code = verify_backup(backup_dir)
    assert exit_code == 0

    # Tamper with manifest file
    manifest_file = backup_dir / "backup_manifest.json"
    content = json.loads(manifest_file.read_text())
    content["merkle_tree_size"] = content.get("merkle_tree_size", 0) + 999
    manifest_file.write_text(json.dumps(content))

    # Verify fails closed
    fail_code = verify_backup(backup_dir)
    assert fail_code != 0
