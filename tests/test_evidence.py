import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import logging
from typing import Tuple
import os
from pathlib import Path
import shutil
from unittest.mock import AsyncMock, patch
import uuid

import pytest
import sqlalchemy as sa
from fastapi import status
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.security import derive_case_code_digest
from app.models.enums import EvidenceScanStatus, ModeratorRole, ReportCategory, ReportStatus
from app.models.evidence import EvidenceAttachment
from app.models.moderator import Moderator
from app.models.report import Report
from app.services.clamav_service import clamav_service
from app.services.evidence_service import (
    AttachmentQuotaExceededError,
    FileValidationError,
    InsufficientStorageError,
    evidence_service,
)

# Test fixtures and binary samples
SAMPLE_PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
SAMPLE_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
SAMPLE_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
SAMPLE_WEBP = b"RIFF\x1a\x00\x00\x00WEBPVP8 \x0e\x00\x00\x000\x01\x00\x9d\x01*\x01\x00\x01\x00\x02\x004%\xa4%"
SAMPLE_TXT = b"This is a legitimate whistleblower incident log in plain text format."
SAMPLE_CSV = b"id,timestamp,event\n1,2026-10-04T00:00:00Z,access_granted\n2,2026-10-04T00:01:00Z,data_extracted\n"


@pytest.fixture(autouse=True)
def clean_storage():
    """Ensure evidence storage directory is clean before and after tests."""
    storage_root = Path(settings.EVIDENCE_STORAGE_PATH).resolve()
    for d in (storage_root / "quarantine", storage_root / "approved"):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)
    storage_root.mkdir(parents=True, exist_ok=True)
    evidence_service._ensure_storage_directories()
    yield
    for d in (storage_root / "quarantine", storage_root / "approved"):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)


def create_report_helper(client: TestClient) -> str:
    """Helper to create an anonymous report and return its case code."""
    res = client.post(
        "/api/v1/reports",
        json={
            "category": "SECURITY",
            "description": "Critical security incident regarding data leakage on internal server.",
        },
    )
    assert res.status_code == status.HTTP_201_CREATED
    return res.json()["case_code"]


def create_moderator_token(client: TestClient, db_session) -> Tuple[str, uuid.UUID]:
    """Helper to create an active moderator and return access token and moderator ID."""
    from app.core.security import create_access_token, get_password_hash

    mod = Moderator(
        username=f"mod_{uuid.uuid4().hex[:8]}",
        password_hash=get_password_hash("ValidModeratorPassword123!"),
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )
    # Using sync-style insertion or direct commit
    return mod


# ============================================================================
# 1. FILE VALIDATION & ALLOWLIST TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_valid_file_types_accepted(client: TestClient):
    """Verify that all 6 explicitly allowed file types are accepted and promoted on clean scan."""
    case_code = create_report_helper(client)

    test_files = [
        ("files", ("evidence.pdf", SAMPLE_PDF, "application/pdf")),
        ("files", ("screenshot.png", SAMPLE_PNG, "image/png")),
        ("files", ("photo.jpg", SAMPLE_JPEG, "image/jpeg")),
        ("files", ("graphic.webp", SAMPLE_WEBP, "image/webp")),
        ("files", ("notes.txt", SAMPLE_TXT, "text/plain")),
    ]

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)

        res = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=test_files,
        )

        assert res.status_code == status.HTTP_200_OK
        data = res.json()
        assert data["status"] == "ACCEPTED"
        assert data["attachments_accepted"] == 5
        assert data["total_bytes"] > 0
        assert mock_scan.call_count == 5


@pytest.mark.asyncio
async def test_valid_csv_accepted(client: TestClient):
    """Verify CSV file is accepted."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        res = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("audit.csv", SAMPLE_CSV, "text/csv"))],
        )
        assert res.status_code == status.HTTP_200_OK
        assert res.json()["attachments_accepted"] == 1


@pytest.mark.asyncio
async def test_unsupported_extension_rejected(client: TestClient):
    """Files with unapproved extensions (e.g. .exe, .sh, .py) must be rejected with 422."""
    case_code = create_report_helper(client)

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("script.sh", b"#!/bin/bash\necho hack\n", "text/plain"))],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    detail = res.json()["detail"]
    assert "Unsupported file extension" in detail or "Prohibited file format" in detail


@pytest.mark.asyncio
async def test_prohibited_archive_formats_rejected(client: TestClient):
    """All archive formats (.zip, .tar, .7z) must be rejected with 422."""
    case_code = create_report_helper(client)

    for arch_name in ["bomb.zip", "data.tar.gz", "evidence.7z"]:
        res = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", (arch_name, b"PK\x03\x04fakezipcontent", "application/zip"))],
        )
        assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Prohibited file format" in res.json()["detail"]


@pytest.mark.asyncio
async def test_mime_mismatch_rejected(client: TestClient):
    """Mismatched Content-Type header (e.g. .pdf with image/png header) must be rejected."""
    case_code = create_report_helper(client)

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("doc.pdf", SAMPLE_PDF, "image/png"))],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "Invalid Content-Type" in res.json()["detail"]


@pytest.mark.asyncio
async def test_magic_byte_mismatch_rejected(client: TestClient):
    """File claims to be .png with image/png header, but content is executable / not PNG."""
    case_code = create_report_helper(client)

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("image.png", b"MZ\x90\x00\x03\x00fake_executable", "image/png"))],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "Invalid PNG file signature" in res.json()["detail"]


@pytest.mark.asyncio
async def test_binary_in_text_file_rejected(client: TestClient):
    """Text file containing null bytes or binary control characters must be rejected."""
    case_code = create_report_helper(client)

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("notes.txt", b"Hello\x00world\x01\x02", "text/plain"))],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "Binary content detected" in res.json()["detail"]


@pytest.mark.asyncio
async def test_empty_file_rejected(client: TestClient):
    """Empty (0-byte) file must be rejected with 422."""
    case_code = create_report_helper(client)

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("empty.txt", b"", "text/plain"))],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "empty" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_duplicate_sha256_in_submission_rejected(client: TestClient):
    """Uploading two identical files with the same SHA-256 in one request must be rejected."""
    case_code = create_report_helper(client)

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[
            ("files", ("doc1.pdf", SAMPLE_PDF, "application/pdf")),
            ("files", ("doc2.pdf", SAMPLE_PDF, "application/pdf")),
        ],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "Duplicate attachment detected" in res.json()["detail"]


# ============================================================================
# 2. STREAMING & QUOTA LIMIT TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_early_multipart_count_enforcement(client: TestClient):
    """Sending more than MAX_ATTACHMENTS_PER_REPORT (5) files must be rejected early."""
    case_code = create_report_helper(client)

    files = [
        ("files", (f"note_{i}.txt", f"Log entry {i}".encode(), "text/plain"))
        for i in range(6)
    ]

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=files,
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "Cannot attach more than 5 files" in res.json()["detail"]


@pytest.mark.asyncio
async def test_per_file_size_limit_enforced(client: TestClient, monkeypatch):
    """File exceeding MAX_ATTACHMENT_SIZE_MB must be rejected during streaming."""
    case_code = create_report_helper(client)
    # Monkeypatch to small limit for test
    monkeypatch.setattr(settings, "MAX_ATTACHMENT_SIZE_MB", 1)

    oversized_data = b"A" * (2 * 1024 * 1024)  # 2 MiB > 1 MiB limit
    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("large.txt", oversized_data, "text/plain"))],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "exceeds maximum allowed size" in res.json()["detail"]


@pytest.mark.asyncio
async def test_cumulative_size_limit_enforced(client: TestClient, monkeypatch):
    """Batch cumulative size exceeding MAX_TOTAL_ATTACHMENT_BYTES must be rejected."""
    case_code = create_report_helper(client)
    monkeypatch.setattr(settings, "MAX_TOTAL_ATTACHMENT_BYTES", 1024 * 1024)  # 1 MiB limit

    file1 = b"B" * (600 * 1024)
    file2 = b"C" * (600 * 1024)
    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[
            ("files", ("part1.txt", file1, "text/plain")),
            ("files", ("part2.txt", file2, "text/plain")),
        ],
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "Cumulative attachments size exceeds maximum" in res.json()["detail"]


@pytest.mark.asyncio
async def test_preflight_storage_rejection(client: TestClient, monkeypatch):
    """When disk free space is below MIN_FREE_STORAGE_MB, uploads are rejected with 507."""
    case_code = create_report_helper(client)
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda path: shutil._ntuple_diskusage(1000 * 1024 * 1024, 950 * 1024 * 1024, 50 * 1024 * 1024),
    )

    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": case_code},
        files=[("files", ("notes.txt", SAMPLE_TXT, "text/plain"))],
    )
    assert res.status_code == status.HTTP_507_INSUFFICIENT_STORAGE
    assert "Storage temporarily unavailable" in res.json()["detail"]


@pytest.mark.asyncio
async def test_concurrency_quota_enforcement(client: TestClient):
    """Uploading files across requests enforcing the 5-attachment per report quota."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)

        # First request attaches 4 files
        res1 = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[
                ("files", (f"file_{i}.txt", f"Content {i}".encode(), "text/plain"))
                for i in range(4)
            ],
        )
        assert res1.status_code == status.HTTP_200_OK

        # Second request attempts to attach 2 more (total 6 > 5) -> must be rejected with 409
        res2 = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[
                ("files", ("extra1.txt", b"Extra 1 content", "text/plain")),
                ("files", ("extra2.txt", b"Extra 2 content", "text/plain")),
            ],
        )
        assert res2.status_code == status.HTTP_409_CONFLICT
        assert "Report attachment quota exceeded" in res2.json()["detail"]


# ============================================================================
# 3. AUTHENTICATION, REDACTION & PRIVACY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_case_code_header_required(client: TestClient):
    """Missing or empty X-Case-Code header returns 401 Unauthorized."""
    res = client.post(
        "/api/v1/reports/evidence",
        files=[("files", ("notes.txt", SAMPLE_TXT, "text/plain"))],
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Case code credential required" in res.json()["detail"]


@pytest.mark.asyncio
async def test_invalid_case_code_returns_404(client: TestClient):
    """Non-existent case code returns 404 Not Found."""
    res = client.post(
        "/api/v1/reports/evidence",
        headers={"X-Case-Code": "wdc_nonexistent1234567890"},
        files=[("files", ("notes.txt", SAMPLE_TXT, "text/plain"))],
    )
    assert res.status_code == status.HTTP_404_NOT_FOUND
    assert "Report not found" in res.json()["detail"]


@pytest.mark.asyncio
async def test_case_code_never_logged(client: TestClient, caplog):
    """Raw X-Case-Code header value must never appear in application logs at any log level."""
    secret_code = "wdc_supersecretcasecode999"
    valid_code = create_report_helper(client)

    with caplog.at_level(logging.DEBUG):
        # 1. Non-existent case code returns 404
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": secret_code},
            files=[("files", ("notes.txt", SAMPLE_TXT, "text/plain"))],
        )
        # 2. Valid case code with validation error (rejected format) returns 422
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": valid_code},
            files=[("files", ("malicious.exe", b"MZbadexecutable", "application/x-msdownload"))],
        )
        # 3. Successful upload
        with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = ("OK", None)
            client.post(
                "/api/v1/reports/evidence",
                headers={"X-Case-Code": valid_code},
                files=[("files", ("notes.txt", SAMPLE_TXT, "text/plain"))],
            )

    for record in caplog.records:
        msg = record.getMessage()
        rec_str = str(record.__dict__)
        assert secret_code not in msg, f"Plaintext secret case code leaked in log message: {msg}"
        assert secret_code not in rec_str, f"Plaintext secret case code leaked in record metadata: {rec_str}"
        assert valid_code not in msg, f"Plaintext valid case code leaked in log message: {msg}"
        assert valid_code not in rec_str, f"Plaintext valid case code leaked in record metadata: {rec_str}"


@pytest.mark.asyncio
async def test_public_tracking_excludes_evidence_metadata(client: TestClient):
    """Public tracking endpoint GET /reports/{case_code} must NOT reveal evidence metadata."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("evidence.pdf", SAMPLE_PDF, "application/pdf"))],
        )

    tracking_res = client.get(f"/api/v1/reports/{case_code}")
    assert tracking_res.status_code == status.HTTP_200_OK
    data = tracking_res.json()
    assert "evidence" not in data
    assert "attachments" not in data
    assert "files" not in data


@pytest.mark.asyncio
async def test_original_filename_not_in_database(client: TestClient, db_session):
    """Original client-supplied filename is never stored in evidence_attachments."""
    case_code = create_report_helper(client)
    unique_client_filename = "john_doe_payroll_screenshot_super_identifying.png"

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", (unique_client_filename, SAMPLE_PNG, "image/png"))],
        )

    stmt = sa.text("SELECT * FROM evidence_attachments")
    res = await db_session.execute(stmt)
    rows = res.fetchall()
    assert len(rows) == 1
    row_dict = rows[0]._asdict()
    for col_val in row_dict.values():
        assert unique_client_filename not in str(col_val)


# ============================================================================
# 4. CLAMAV SCANNING & STATE MACHINE TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_clamav_clean_promotion(client: TestClient, db_session):
    """Clean ClamAV scan promotes file from quarantine/ to approved/ with CLEAN status."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        res = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("clean_doc.pdf", SAMPLE_PDF, "application/pdf"))],
        )
        assert res.status_code == status.HTTP_200_OK

    stmt = sa.select(EvidenceAttachment)
    res = await db_session.execute(stmt)
    attachment = res.scalar_one()

    assert attachment.scan_status == EvidenceScanStatus.CLEAN
    assert attachment.scanned_at is not None

    quar_path = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{attachment.storage_key}.bin"
    app_path = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{attachment.storage_key}.bin"

    assert not quar_path.is_file()
    assert app_path.is_file()
    assert app_path.stat().st_size == len(SAMPLE_PDF)


@pytest.mark.asyncio
async def test_clamav_infected_file_deleted(client: TestClient, db_session):
    """Infected file detected by ClamAV is deleted from quarantine and marked INFECTED."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("FOUND", "Eicar-Test-Signature")
        res = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("virus.txt", SAMPLE_TXT, "text/plain"))],
        )
        assert res.status_code == status.HTTP_200_OK

    stmt = sa.select(EvidenceAttachment)
    res = await db_session.execute(stmt)
    attachment = res.scalar_one()

    assert attachment.scan_status == EvidenceScanStatus.INFECTED

    quar_path = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{attachment.storage_key}.bin"
    app_path = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{attachment.storage_key}.bin"

    # Both quarantine and approved files must NOT exist
    assert not quar_path.is_file()
    assert not app_path.is_file()


@pytest.mark.asyncio
async def test_clamav_timeout_fails_closed(client: TestClient, db_session):
    """Scanner timeout leaves file in quarantine and transitions DB to SCAN_FAILED."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("ERROR", "Scan timed out")
        res = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("doc.pdf", SAMPLE_PDF, "application/pdf"))],
        )
        assert res.status_code == status.HTTP_200_OK

    stmt = sa.select(EvidenceAttachment)
    res = await db_session.execute(stmt)
    attachment = res.scalar_one()

    assert attachment.scan_status == EvidenceScanStatus.SCAN_FAILED

    quar_path = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{attachment.storage_key}.bin"
    app_path = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{attachment.storage_key}.bin"

    assert quar_path.is_file()
    assert not app_path.is_file()


# ============================================================================
# 5. RECONCILIATION & RECOVERY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_reconciliation_hash_verified_recovery(db_session):
    """Interrupted PROMOTING transition is safely recovered to CLEAN when SHA-256 matches."""
    # Create report
    report = Report(
        case_code_digest=derive_case_code_digest("wdc_testcasecode123"),
        category=ReportCategory.SECURITY,
        description="Test incident for reconciliation.",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    storage_key = uuid.uuid4()
    sha256_hash = hashlib.sha256(SAMPLE_PNG).hexdigest()

    attachment = EvidenceAttachment(
        report_id=report.id,
        storage_key=storage_key,
        detected_mime="image/png",
        file_size=len(SAMPLE_PNG),
        sha256_hash=sha256_hash,
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),  # Stale > 15m
    )
    db_session.add(attachment)
    await db_session.commit()

    # Place file in quarantine
    quar_file = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{storage_key}.bin"
    quar_file.write_bytes(SAMPLE_PNG)

    # Run reconciliation
    await evidence_service.run_reconciliation()

    # Verify status advanced to CLEAN and file moved to approved/
    await db_session.refresh(attachment)
    assert attachment.scan_status == EvidenceScanStatus.CLEAN

    app_file = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{storage_key}.bin"
    assert app_file.is_file()
    assert not quar_file.is_file()


@pytest.mark.asyncio
async def test_reconciliation_corrupted_hash_fails(db_session):
    """Interrupted recovery with corrupted file hash must fail to SCAN_FAILED, not CLEAN."""
    report = Report(
        case_code_digest=derive_case_code_digest("wdc_testcasecode456"),
        category=ReportCategory.SECURITY,
        description="Test incident for corrupt recovery.",
    )
    db_session.add(report)
    await db_session.commit()
    await db_session.refresh(report)

    storage_key = uuid.uuid4()
    correct_hash = hashlib.sha256(SAMPLE_PDF).hexdigest()

    attachment = EvidenceAttachment(
        report_id=report.id,
        storage_key=storage_key,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=correct_hash,
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(attachment)
    await db_session.commit()

    # Place corrupted file (same length but modified byte)
    corrupted_data = b"X" * len(SAMPLE_PDF)
    quar_file = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{storage_key}.bin"
    quar_file.write_bytes(corrupted_data)

    await evidence_service.run_reconciliation()

    await db_session.refresh(attachment)
    assert attachment.scan_status == EvidenceScanStatus.SCAN_FAILED


@pytest.mark.asyncio
async def test_reconciliation_stale_pending_scan(db_session):
    """PENDING_SCAN rows older than 24 hours are transitioned to SCAN_FAILED."""
    report = Report(
        case_code_digest=derive_case_code_digest("wdc_testcasecode789"),
        category=ReportCategory.SECURITY,
        description="Test incident for stale pending.",
    )
    db_session.add(report)
    await db_session.commit()

    attachment = EvidenceAttachment(
        report_id=report.id,
        storage_key=uuid.uuid4(),
        detected_mime="text/plain",
        file_size=len(SAMPLE_TXT),
        sha256_hash=hashlib.sha256(SAMPLE_TXT).hexdigest(),
        scan_status=EvidenceScanStatus.PENDING_SCAN,
        created_at=datetime.now(timezone.utc) - timedelta(hours=25),
    )
    db_session.add(attachment)
    await db_session.commit()

    await evidence_service.run_reconciliation()

    await db_session.refresh(attachment)
    assert attachment.scan_status == EvidenceScanStatus.SCAN_FAILED


@pytest.mark.asyncio
async def test_orphan_cleanup_removes_unreferenced_files():
    """Unreferenced files in quarantine older than grace period are deleted."""
    orphan_key = uuid.uuid4()
    orphan_file = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{orphan_key}.bin"
    orphan_file.write_bytes(b"orphaned content")

    # Set mtime to 30 minutes ago (older than 15-minute grace period)
    old_time = datetime.now().timestamp() - 1800
    os.utime(str(orphan_file), (old_time, old_time))

    await evidence_service.run_reconciliation()
    assert not orphan_file.is_file()


# ============================================================================
# 6. MODERATOR ACCESS & DOWNLOAD TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_moderator_list_and_download_evidence(client: TestClient, db_session):
    """Authorized moderator lists attachments with synthetic names and downloads clean file."""
    from app.core.security import create_access_token, hash_password

    # Create moderator
    mod = Moderator(
        username="mod_tester1",
        password_hash=hash_password("ValidModeratorPassword123!"),
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )
    db_session.add(mod)
    await db_session.commit()
    await db_session.refresh(mod)

    token = create_access_token(subject=str(mod.id))
    auth_header = {"Authorization": f"Bearer {token}"}

    # Create report and attach clean file
    case_code = create_report_helper(client)
    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[
                ("files", ("attacker_screenshot.png", SAMPLE_PNG, "image/png")),
                ("files", ("contract.pdf", SAMPLE_PDF, "application/pdf")),
            ],
        )

    # Get report ID via list
    rep_res = client.get("/api/v1/moderator/reports", headers=auth_header)
    assert rep_res.status_code == status.HTTP_200_OK
    report_id = rep_res.json()["items"][0]["id"]

    # 1. List evidence for report
    list_res = client.get(f"/api/v1/moderator/reports/{report_id}/evidence", headers=auth_header)
    assert list_res.status_code == status.HTTP_200_OK
    ev_data = list_res.json()
    assert ev_data["total"] == 2
    display_names = {item["display_name"] for item in ev_data["items"]}
    assert display_names in ({"evidence-1.png", "evidence-2.pdf"}, {"evidence-1.pdf", "evidence-2.png"})
    assert "attacker_screenshot" not in str(ev_data)
    assert "contract.pdf" not in str(ev_data)

    png_item = next(item for item in ev_data["items"] if item["detected_mime"] == "image/png")
    ev_id = png_item["id"]
    expected_filename = png_item["display_name"]

    # 2. Download clean evidence file
    dl_res = client.get(f"/api/v1/moderator/reports/{report_id}/evidence/{ev_id}", headers=auth_header)
    assert dl_res.status_code == status.HTTP_200_OK
    assert dl_res.headers["Content-Disposition"] == f'attachment; filename="{expected_filename}"'
    assert dl_res.headers["X-Content-Type-Options"] == "nosniff"
    assert dl_res.headers["Cache-Control"] == "private, no-cache, no-store, must-revalidate"
    assert dl_res.content == SAMPLE_PNG


@pytest.mark.asyncio
async def test_non_clean_evidence_download_rejected(client: TestClient, db_session):
    """Attempting to download evidence in non-CLEAN status returns 403 Forbidden."""
    from app.core.security import create_access_token, hash_password

    mod = Moderator(
        username="mod_tester2",
        password_hash=hash_password("ValidModeratorPassword123!"),
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )
    db_session.add(mod)
    await db_session.commit()
    token = create_access_token(subject=str(mod.id))
    auth_header = {"Authorization": f"Bearer {token}"}

    case_code = create_report_helper(client)
    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("ERROR", "Timeout")  # Status will be SCAN_FAILED
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("doc.pdf", SAMPLE_PDF, "application/pdf"))],
        )

    rep_res = client.get("/api/v1/moderator/reports", headers=auth_header)
    report_id = rep_res.json()["items"][0]["id"]

    list_res = client.get(f"/api/v1/moderator/reports/{report_id}/evidence", headers=auth_header)
    ev_id = list_res.json()["items"][0]["id"]

    dl_res = client.get(f"/api/v1/moderator/reports/{report_id}/evidence/{ev_id}", headers=auth_header)
    assert dl_res.status_code == status.HTTP_403_FORBIDDEN
    assert "Evidence attachment not available" in dl_res.json()["detail"]


@pytest.mark.asyncio
async def test_evidence_idor_protection(client: TestClient, db_session):
    """Requesting evidence with mismatched report ID returns 404."""
    from app.core.security import create_access_token, hash_password

    mod = Moderator(
        username="mod_tester3",
        password_hash=hash_password("ValidModeratorPassword123!"),
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )
    db_session.add(mod)
    await db_session.commit()
    token = create_access_token(subject=str(mod.id))
    auth_header = {"Authorization": f"Bearer {token}"}

    case_code1 = create_report_helper(client)
    case_code2 = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code1},
            files=[("files", ("doc1.pdf", SAMPLE_PDF, "application/pdf"))],
        )

    reps = client.get("/api/v1/moderator/reports", headers=auth_header).json()["items"]
    ev_res1 = client.get(f"/api/v1/moderator/reports/{reps[0]['id']}/evidence", headers=auth_header).json()["items"]
    if ev_res1:
        rep_with_ev = reps[0]["id"]
        rep_other = reps[1]["id"]
        ev_id = ev_res1[0]["id"]
    else:
        rep_with_ev = reps[1]["id"]
        rep_other = reps[0]["id"]
        ev_id = client.get(f"/api/v1/moderator/reports/{rep_with_ev}/evidence", headers=auth_header).json()["items"][0]["id"]

    # Request ev_id using rep_other (mismatch) -> 404
    dl_res = client.get(f"/api/v1/moderator/reports/{rep_other}/evidence/{ev_id}", headers=auth_header)
    assert dl_res.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
async def test_unauthenticated_moderator_access_rejected(client: TestClient):
    """Unauthenticated access to moderator evidence routes returns 401."""
    random_id = uuid.uuid4()
    assert client.get(f"/api/v1/moderator/reports/{random_id}/evidence").status_code == status.HTTP_401_UNAUTHORIZED
    assert client.get(f"/api/v1/moderator/reports/{random_id}/evidence/{random_id}").status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_duplicate_sha256_across_multiple_submissions_rejected(client: TestClient):
    """Submitting the same SHA-256 in separate requests to the same report returns 422."""
    case_code = create_report_helper(client)

    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)

        # 1. First upload succeeds
        res1 = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("invoice.pdf", SAMPLE_PDF, "application/pdf"))],
        )
        assert res1.status_code == status.HTTP_200_OK

        # 2. Second upload with the same content (same SHA-256) is rejected
        res2 = client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("duplicate_invoice.pdf", SAMPLE_PDF, "application/pdf"))],
        )
        assert res2.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "Duplicate attachment detected" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_crash_recovery_matrix_cases_a_through_i(client: TestClient, db_session):
    """Verify all 9 crash-recovery branches (A through I) in reconciliation.
    
    A. SCAN_CLEAN + quarantine exists + approved missing -> CLEAN
    B. SCAN_CLEAN + approved exists + quarantine missing -> CLEAN
    C. PROMOTING + quarantine exists + approved missing -> CLEAN
    D. PROMOTING + approved exists + quarantine missing -> CLEAN
    E. both quarantine AND approved exist -> CLEAN, quarantine unlinked
    F. neither file exists -> SCAN_FAILED
    G. approved exists but wrong size -> SCAN_FAILED, corrupted approved unlinked
    H. approved exists but wrong SHA-256 -> SCAN_FAILED, corrupted approved unlinked
    I. quarantine exists but wrong SHA-256 -> SCAN_FAILED, not promoted
    """
    case_code = create_report_helper(client)
    stmt = sa.select(Report).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    res = await db_session.execute(stmt)
    report = res.scalar_one()

    # Case A: SCAN_CLEAN + quarantine exists (valid) + approved missing
    s_key_a = uuid.uuid4()
    q_file_a = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{s_key_a}.bin"
    q_file_a.write_bytes(SAMPLE_PDF)
    att_a = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_a,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=hashlib.sha256(SAMPLE_PDF).hexdigest(),
        scan_status=EvidenceScanStatus.SCAN_CLEAN,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_a)

    # Case B: SCAN_CLEAN + approved exists (valid) + quarantine missing
    s_key_b = uuid.uuid4()
    app_file_b = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_b}.bin"
    app_file_b.write_bytes(SAMPLE_PNG)
    att_b = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_b,
        detected_mime="image/png",
        file_size=len(SAMPLE_PNG),
        sha256_hash=hashlib.sha256(SAMPLE_PNG).hexdigest(),
        scan_status=EvidenceScanStatus.SCAN_CLEAN,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_b)

    # Case C: PROMOTING + quarantine exists (valid) + approved missing
    s_key_c = uuid.uuid4()
    q_file_c = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{s_key_c}.bin"
    q_file_c.write_bytes(SAMPLE_JPEG)
    att_c = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_c,
        detected_mime="image/jpeg",
        file_size=len(SAMPLE_JPEG),
        sha256_hash=hashlib.sha256(SAMPLE_JPEG).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_c)

    # Case D: PROMOTING + approved exists (valid) + quarantine missing
    s_key_d = uuid.uuid4()
    app_file_d = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_d}.bin"
    app_file_d.write_bytes(SAMPLE_TXT)
    att_d = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_d,
        detected_mime="text/plain",
        file_size=len(SAMPLE_TXT),
        sha256_hash=hashlib.sha256(SAMPLE_TXT).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_d)

    # Case E: both quarantine AND approved exist (approved valid)
    s_key_e = uuid.uuid4()
    app_file_e = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_e}.bin"
    app_file_e.write_bytes(SAMPLE_CSV)
    q_file_e = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{s_key_e}.bin"
    q_file_e.write_bytes(SAMPLE_CSV)
    att_e = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_e,
        detected_mime="text/csv",
        file_size=len(SAMPLE_CSV),
        sha256_hash=hashlib.sha256(SAMPLE_CSV).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_e)

    # Case F: neither file exists
    s_key_f = uuid.uuid4()
    att_f = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_f,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=hashlib.sha256(SAMPLE_PDF).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_f)

    # Case G: approved exists but wrong size
    s_key_g = uuid.uuid4()
    app_file_g = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_g}.bin"
    app_file_g.write_bytes(SAMPLE_PDF[:10])  # truncated
    att_g = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_g,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=hashlib.sha256(SAMPLE_PDF).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_g)

    # Case H: approved exists but wrong SHA-256
    s_key_h = uuid.uuid4()
    app_file_h = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_h}.bin"
    app_file_h.write_bytes(b"%PDF-corrupted-content-here-with-correct-length!" + b" " * (len(SAMPLE_PDF) - 49))
    att_h = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_h,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=hashlib.sha256(SAMPLE_PDF).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_h)

    # Case I: quarantine exists but wrong SHA-256
    s_key_i = uuid.uuid4()
    q_file_i = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{s_key_i}.bin"
    q_file_i.write_bytes(b"%PDF-corrupted-quarantine-content-here-for-test!" + b" " * (len(SAMPLE_PDF) - 48))
    att_i = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key_i,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=hashlib.sha256(SAMPLE_PDF).hexdigest(),
        scan_status=EvidenceScanStatus.PROMOTING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=20),
    )
    db_session.add(att_i)

    await db_session.commit()

    # Run reconciliation pass
    await evidence_service.run_reconciliation()

    # Verify results
    await db_session.refresh(att_a)
    assert att_a.scan_status == EvidenceScanStatus.CLEAN
    assert (Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_a}.bin").is_file()

    await db_session.refresh(att_b)
    assert att_b.scan_status == EvidenceScanStatus.CLEAN

    await db_session.refresh(att_c)
    assert att_c.scan_status == EvidenceScanStatus.CLEAN
    assert (Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_c}.bin").is_file()

    await db_session.refresh(att_d)
    assert att_d.scan_status == EvidenceScanStatus.CLEAN

    await db_session.refresh(att_e)
    assert att_e.scan_status == EvidenceScanStatus.CLEAN
    assert not q_file_e.is_file(), "Leftover quarantine file must be unlinked in Case E"

    await db_session.refresh(att_f)
    assert att_f.scan_status == EvidenceScanStatus.SCAN_FAILED

    await db_session.refresh(att_g)
    assert att_g.scan_status == EvidenceScanStatus.SCAN_FAILED
    assert not app_file_g.is_file(), "Corrupted approved file must be unlinked in Case G"

    await db_session.refresh(att_h)
    assert att_h.scan_status == EvidenceScanStatus.SCAN_FAILED
    assert not app_file_h.is_file(), "Corrupted approved file must be unlinked in Case H"

    await db_session.refresh(att_i)
    assert att_i.scan_status == EvidenceScanStatus.SCAN_FAILED
    assert not (Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key_i}.bin").is_file()


@pytest.mark.asyncio
async def test_reconciliation_terminal_state_purged_after_72_hours(client: TestClient, db_session):
    """Files in SCAN_FAILED or INFECTED older than 72 hours are purged and marked DELETED."""
    case_code = create_report_helper(client)
    stmt = sa.select(Report).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    res = await db_session.execute(stmt)
    report = res.scalar_one()

    # Stale failed attachment
    s_key = uuid.uuid4()
    q_file = Path(settings.EVIDENCE_STORAGE_PATH) / "quarantine" / f"{s_key}.bin"
    q_file.write_bytes(b"old failed data")
    att = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key,
        detected_mime="application/pdf",
        file_size=15,
        sha256_hash="0" * 64,
        scan_status=EvidenceScanStatus.SCAN_FAILED,
        updated_at=datetime.now(timezone.utc) - timedelta(hours=73),
    )
    db_session.add(att)
    await db_session.commit()

    await evidence_service.run_reconciliation()

    await db_session.refresh(att)
    assert att.scan_status == EvidenceScanStatus.DELETED
    assert not q_file.is_file()


@pytest.mark.asyncio
async def test_reconciliation_corrupted_clean_attachment_transitions_to_failed(client: TestClient, db_session):
    """If an approved file for a CLEAN record is missing or corrupted, it transitions to SCAN_FAILED."""
    case_code = create_report_helper(client)
    stmt = sa.select(Report).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    res = await db_session.execute(stmt)
    report = res.scalar_one()

    s_key = uuid.uuid4()
    app_file = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{s_key}.bin"
    app_file.write_bytes(b"corrupted bytes!")
    att = EvidenceAttachment(
        report_id=report.id,
        storage_key=s_key,
        detected_mime="application/pdf",
        file_size=len(SAMPLE_PDF),
        sha256_hash=hashlib.sha256(SAMPLE_PDF).hexdigest(),
        scan_status=EvidenceScanStatus.CLEAN,
    )
    db_session.add(att)
    await db_session.commit()

    await evidence_service.run_reconciliation()

    await db_session.refresh(att)
    assert att.scan_status == EvidenceScanStatus.SCAN_FAILED
    assert not app_file.is_file()


@pytest.mark.asyncio
async def test_report_deletion_cleans_up_orphaned_evidence_files(client: TestClient, db_session):
    """When a report is deleted, its database rows cascade and physical files are swept by reconciliation."""
    case_code = create_report_helper(client)
    with patch.object(clamav_service, "scan_file", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ("OK", None)
        client.post(
            "/api/v1/reports/evidence",
            headers={"X-Case-Code": case_code},
            files=[("files", ("evidence.pdf", SAMPLE_PDF, "application/pdf"))],
        )

    stmt = sa.select(Report).where(
        Report.case_code_digest == derive_case_code_digest(case_code)
    )
    res = await db_session.execute(stmt)
    report = res.scalar_one()

    # Find the approved file
    att_stmt = sa.select(EvidenceAttachment).where(EvidenceAttachment.report_id == report.id)
    att_res = await db_session.execute(att_stmt)
    att = att_res.scalar_one()
    approved_file = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{att.storage_key}.bin"
    assert approved_file.is_file()

    # Delete parent report (simulating database cascade)
    await db_session.delete(report)
    await db_session.commit()

    # Verify evidence attachment row was cascaded
    att_check = await db_session.execute(att_stmt)
    assert att_check.scalar_one_or_none() is None

    # Set mtime on approved file to 20 minutes ago (older than 15-minute grace period)
    old_time = datetime.now().timestamp() - 1200
    os.utime(str(approved_file), (old_time, old_time))

    # Run reconciliation pass
    await evidence_service.run_reconciliation()

    # Verify physical file was unlinked by orphan cleanup
    assert not approved_file.is_file()


