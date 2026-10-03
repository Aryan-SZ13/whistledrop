import hashlib
import hmac
from unittest.mock import patch
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import derive_case_code_digest
from app.models.audit_log import AuditLog
from app.models.enums import ReportCategory, ReportStatus
from app.models.report import Report
from app.schemas.report import ReportCreate
from app.services.report_service import report_service


def test_submit_report_success(client: TestClient):
    """Verify successful report submission flow and response shape."""
    payload = {
        "category": "CORRUPTION",
        "description": "Observed fraudulent procurement contract approvals.",
        "evidence_url": "https://example.com/evidence/doc.pdf",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 201
    data = response.json()

    # Public response must expose only the minimum information
    assert "id" in data
    assert "case_code" in data
    assert data["case_code"].startswith("wdc_")
    assert len(data["case_code"]) >= 36
    assert data["status"] == "SUBMITTED"
    assert "created_at" in data

    # Verify sensitive and internal fields are completely excluded from public response
    assert "case_code_digest" not in data
    assert "description" not in data
    assert "evidence_url" not in data


def test_submit_report_without_evidence_url(client: TestClient):
    """Verify report submission works without optional evidence_url."""
    payload = {
        "category": "SECURITY",
        "description": "Unauthenticated remote code execution vulnerability found.",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "SUBMITTED"
    assert "case_code" in data


@pytest.mark.asyncio
async def test_plaintext_case_code_absent_from_database(
    client: TestClient,
    db_session: AsyncSession,
):
    """Regression test proving plaintext case code is never persisted in PostgreSQL."""
    payload = {
        "category": "HARASSMENT",
        "description": "Workplace harassment complaint submitted anonymously.",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 201
    data = response.json()
    report_id = data["id"]
    plaintext_case_code = data["case_code"]

    # 1. Fetch raw report from PostgreSQL
    res = await db_session.execute(sa.select(Report).where(Report.id == report_id))
    report = res.scalar_one_or_none()
    assert report is not None

    # 2. Verify plaintext case code does NOT exist anywhere in report columns
    assert report.case_code_digest != plaintext_case_code
    assert plaintext_case_code not in (report.description or "")
    assert plaintext_case_code not in (report.evidence_url or "")

    # 3. Verify digest matches HMAC-SHA256 of case code using CASE_CODE_SECRET
    expected_digest = derive_case_code_digest(plaintext_case_code)
    assert report.case_code_digest == expected_digest

    # 4. Check raw audit log row in PostgreSQL
    res_audit = await db_session.execute(
        sa.select(AuditLog).where(AuditLog.report_id == report_id)
    )
    audit = res_audit.scalar_one_or_none()
    assert audit is not None
    assert audit.action == "REPORT_SUBMITTED"
    assert audit.moderator_id is None

    # Plaintext case code must NEVER exist in audit log metadata or action
    audit_dump = str(audit.metadata_) + str(audit.action)
    assert plaintext_case_code not in audit_dump
    assert expected_digest not in audit_dump
    assert report.description not in audit_dump


def test_submit_report_forbids_extra_fields(client: TestClient):
    """Verify that identity and unexpected fields are rejected by validation."""
    payload = {
        "category": "TECHNICAL",
        "description": "Database deadlock issue in background processing.",
        "reporter_name": "Whistleblower Alice",
        "email": "alice@example.com",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 422
    errors = response.json()["detail"]
    error_fields = [e["loc"][-1] for e in errors]
    assert "reporter_name" in error_fields or "extra_forbidden" in str(errors)


def test_submit_report_invalid_category(client: TestClient):
    """Verify that invalid report categories are rejected."""
    payload = {
        "category": "NON_EXISTENT_CATEGORY",
        "description": "Testing invalid categorization.",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 422


def test_submit_report_description_too_short(client: TestClient):
    """Verify description length boundary validation (< 10 chars)."""
    payload = {
        "category": "OTHER",
        "description": "Too short",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 422


def test_submit_report_invalid_evidence_url(client: TestClient):
    """Verify invalid URL protocols (e.g. javascript:) are rejected."""
    payload = {
        "category": "SECURITY",
        "description": "Security report with suspicious evidence URL.",
        "evidence_url": "javascript:alert(1)",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_transaction_rollback_on_failure(db_session: AsyncSession):
    """Verify transactional atomicity and rollback if an error occurs during submission."""
    report_in = ReportCreate(
        category=ReportCategory.CORRUPTION,
        description="Corruption incident description that should roll back.",
    )

    # Simulate an error during audit log persistence
    with patch.object(db_session, "commit", side_effect=RuntimeError("Simulated database failure")):
        with pytest.raises(RuntimeError, match="Simulated database failure"):
            await report_service.create_report(db=db_session, report_in=report_in)

    # Verify no records were persisted
    res_reports = await db_session.execute(sa.select(Report))
    assert res_reports.fetchall() == []

    res_audits = await db_session.execute(sa.select(AuditLog))
    assert res_audits.fetchall() == []
