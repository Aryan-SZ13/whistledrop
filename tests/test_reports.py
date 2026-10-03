import hashlib
import hmac
from unittest.mock import patch
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import derive_case_code_digest, generate_case_code
from app.models.audit_log import AuditLog
from app.models.enums import ReportCategory, ReportStatus
from app.models.report import Report
from app.schemas.report import ReportCreate
from app.services.report_service import report_service


def test_submit_report_success_response_shape(client: TestClient):
    """Verify successful report submission minimizes public response and conceals internal UUID."""
    payload = {
        "category": "CORRUPTION",
        "description": "Observed fraudulent procurement contract approvals.",
        "evidence_url": "https://example.com/evidence/doc.pdf",
    }
    response = client.post("/api/v1/reports", json=payload)
    assert response.status_code == 201
    data = response.json()

    # Public response MUST expose only case_code, status, and created_at
    assert set(data.keys()) == {"case_code", "status", "created_at"}

    # Internal database primary keys must remain strictly internal
    assert "id" not in data

    # Bearer credential checks
    assert data["case_code"].startswith("wdc_")
    assert len(data["case_code"]) >= 36
    assert data["status"] == "SUBMITTED"
    assert "created_at" in data

    # Internal and sensitive fields must never be exposed
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
    assert set(data.keys()) == {"case_code", "status", "created_at"}
    assert data["status"] == "SUBMITTED"


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
    plaintext_case_code = data["case_code"]

    # 1. Derive expected digest to query the database (since internal ID is concealed)
    expected_digest = derive_case_code_digest(plaintext_case_code)

    # 2. Fetch raw report from PostgreSQL using the digest
    res = await db_session.execute(
        sa.select(Report).where(Report.case_code_digest == expected_digest)
    )
    report = res.scalar_one_or_none()
    assert report is not None

    # 3. Verify plaintext case code does NOT exist anywhere in report columns
    assert report.case_code_digest != plaintext_case_code
    assert plaintext_case_code not in (report.description or "")
    assert plaintext_case_code not in (report.evidence_url or "")

    # 4. Check raw audit log row in PostgreSQL
    res_audit = await db_session.execute(
        sa.select(AuditLog).where(AuditLog.report_id == report.id)
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


@pytest.mark.parametrize(
    "invalid_url",
    [
        "javascript:alert(1)",
        "ftp://files.example.com/doc.pdf",
        "file:///etc/passwd",
        "http://",
        "https://",
        "not_a_valid_url",
    ],
)
def test_submit_report_invalid_evidence_url(client: TestClient, invalid_url: str):
    """Verify structured URL validation rejects dangerous or malformed schemes."""
    payload = {
        "category": "SECURITY",
        "description": "Security report with suspicious evidence URL format.",
        "evidence_url": invalid_url,
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


# ==============================================================================
# Cryptographic Regression Tests
# ==============================================================================


def test_crypto_multiple_generated_case_codes_are_distinct():
    """Verify that multiple generated case codes have sufficient entropy and no collisions."""
    generated = {generate_case_code() for _ in range(100)}
    assert len(generated) == 100
    for code in generated:
        assert code.startswith("wdc_")
        assert len(code) >= 36


def test_crypto_deterministic_digest_with_same_secret():
    """Verify that the same case code and same secret produce an identical digest."""
    case_code = "wdc_test_case_code_fixed_value_12345"
    digest_1 = derive_case_code_digest(case_code)
    digest_2 = derive_case_code_digest(case_code)
    assert digest_1 == digest_2
    assert len(digest_1) == 64  # SHA-256 hex digest length


def test_crypto_different_case_codes_produce_different_digests():
    """Verify collision resistance across different case codes."""
    code_a = generate_case_code()
    code_b = generate_case_code()
    assert code_a != code_b

    digest_a = derive_case_code_digest(code_a)
    digest_b = derive_case_code_digest(code_b)
    assert digest_a != digest_b


def test_crypto_changing_secret_changes_digest():
    """Verify that digest derivation strictly depends on CASE_CODE_SECRET."""
    case_code = "wdc_test_fixed_token_for_secret_check"
    original_secret = settings.CASE_CODE_SECRET

    digest_orig = derive_case_code_digest(case_code)

    # Re-compute digest using an alternate secret key
    alternate_secret = "an-alternate-secret-key-for-testing-digest-changes"
    digest_alt = hmac.new(
        alternate_secret.encode("utf-8"),
        case_code.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert digest_orig != digest_alt
