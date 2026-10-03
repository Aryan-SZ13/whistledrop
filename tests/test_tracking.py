import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import derive_case_code_digest
from app.models.enums import ModeratorRole, ReportCategory, ReportStatus
from app.models.moderator import Moderator
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.services.report_service import report_service


def test_tracking_valid_case_code_empty_updates(client: TestClient):
    """Verify that a valid case code returns the expected public tracking response with empty updates."""
    # 1. Create a report via API
    payload = {
        "category": "CORRUPTION",
        "description": "Suspected procurement irregularity involving senior official.",
    }
    create_res = client.post("/api/v1/reports", json=payload)
    assert create_res.status_code == 201
    case_code = create_res.json()["case_code"]

    # 2. Track report via case code
    track_res = client.get(f"/api/v1/reports/{case_code}")
    assert track_res.status_code == 200
    data = track_res.json()

    # Public schema exactness
    assert set(data.keys()) == {"status", "updates"}
    assert data["status"] == "SUBMITTED"
    assert data["updates"] == []


@pytest.mark.asyncio
async def test_tracking_with_chronological_updates(
    client: TestClient,
    db_session: AsyncSession,
):
    """Verify updates are returned in chronological order and exclude moderator/internal info."""
    # 1. Create report and moderator directly in database
    case_code = "wdc_test_custom_tracking_code_12345"
    digest = derive_case_code_digest(case_code)

    mod = Moderator(
        username="lead_auditor",
        password_hash="secret_hash",
        role=ModeratorRole.MODERATOR,
    )
    report = Report(
        case_code_digest=digest,
        category=ReportCategory.SECURITY,
        description="Confidential internal vulnerability assessment.",
        status=ReportStatus.UNDER_REVIEW,
    )
    db_session.add_all([mod, report])
    await db_session.flush()

    # 2. Add two updates to the report with different timestamps
    now = datetime.now(timezone.utc)
    u1 = ReportUpdate(
        report_id=report.id,
        created_by=mod.id,
        message="Initial assessment opened by security team.",
        created_at=now - timedelta(minutes=5),
    )
    u2 = ReportUpdate(
        report_id=report.id,
        created_by=mod.id,
        message="Vulnerability patched and pending verification.",
        created_at=now,
    )
    db_session.add_all([u1, u2])
    await db_session.commit()

    # 3. Track report via API
    track_res = client.get(f"/api/v1/reports/{case_code}")
    assert track_res.status_code == 200
    data = track_res.json()

    assert data["status"] == "UNDER_REVIEW"
    assert len(data["updates"]) == 2

    # Check update fields and order
    assert data["updates"][0]["message"] == "Initial assessment opened by security team."
    assert data["updates"][1]["message"] == "Vulnerability patched and pending verification."

    # Verify each update contains strictly {"message", "created_at"}
    for update in data["updates"]:
        assert set(update.keys()) == {"message", "created_at"}
        # Moderator metadata and internal UUIDs must never leak into public updates
        assert "created_by" not in update
        assert "moderator" not in update
        assert "id" not in update
        assert "report_id" not in update


def test_tracking_invalid_case_code_not_found(client: TestClient):
    """Verify that a nonexistent case code returns a clean 404 response without leaking internals."""
    fake_code = "wdc_nonexistent_case_code_999999"
    response = client.get(f"/api/v1/reports/{fake_code}")
    assert response.status_code == 404
    data = response.json()
    assert data == {"detail": "Report not found"}


def test_tracking_malformed_case_code_rejected(client: TestClient):
    """Verify that a malformed (too short) case code is rejected with 422 Unprocessable Entity."""
    malformed_code = "short"
    response = client.get(f"/api/v1/reports/{malformed_code}")
    assert response.status_code == 422


def test_tracking_public_data_minimization_regression(client: TestClient):
    """Regression test: Proves that sensitive internal fields are strictly omitted from tracking response."""
    payload = {
        "category": "TECHNICAL",
        "description": "Critical infrastructure failover vulnerability.",
        "evidence_url": "https://example.com/sensitive_evidence.log",
    }
    create_res = client.post("/api/v1/reports", json=payload)
    case_code = create_res.json()["case_code"]

    track_res = client.get(f"/api/v1/reports/{case_code}")
    assert track_res.status_code == 200
    data = track_res.json()

    # Public schema must match EXACTLY {"status", "updates"}
    assert set(data.keys()) == {"status", "updates"}

    # Explicit assertions against internal leakage
    forbidden_keys = {
        "id",
        "report_id",
        "case_code",
        "case_code_digest",
        "digest",
        "description",
        "evidence_url",
        "category",
        "moderator",
        "moderator_id",
        "audit",
        "audit_logs",
    }
    leaked = forbidden_keys.intersection(data.keys())
    assert not leaked, f"Internal fields leaked into tracking response: {leaked}"


@pytest.mark.asyncio
async def test_tracking_case_codes_do_not_cross_access(
    client: TestClient,
    db_session: AsyncSession,
):
    """Verify distinct case codes only access their respective reports and cannot cross-access."""
    # Create two separate reports
    res1 = client.post(
        "/api/v1/reports",
        json={"category": "SECURITY", "description": "Report one details 12345"},
    )
    res2 = client.post(
        "/api/v1/reports",
        json={"category": "HARASSMENT", "description": "Report two details 67890"},
    )
    code1 = res1.json()["case_code"]
    code2 = res2.json()["case_code"]
    assert code1 != code2

    # Fetch report 1 and report 2 records directly from DB to attach distinguishable updates
    digest1 = derive_case_code_digest(code1)
    digest2 = derive_case_code_digest(code2)

    r1 = (await db_session.execute(sa.select(Report).where(Report.case_code_digest == digest1))).scalar_one()
    r2 = (await db_session.execute(sa.select(Report).where(Report.case_code_digest == digest2))).scalar_one()

    # Set distinct statuses
    r1.status = ReportStatus.UNDER_REVIEW
    r2.status = ReportStatus.RESOLVED

    # Attach distinct updates
    u1 = ReportUpdate(report_id=r1.id, message="Update for Report 1 only")
    u2 = ReportUpdate(report_id=r2.id, message="Update for Report 2 only")
    db_session.add_all([u1, u2])
    await db_session.commit()

    # Query using code1
    track1 = client.get(f"/api/v1/reports/{code1}").json()
    assert track1["status"] == "UNDER_REVIEW"
    assert len(track1["updates"]) == 1
    assert track1["updates"][0]["message"] == "Update for Report 1 only"

    # Query using code2
    track2 = client.get(f"/api/v1/reports/{code2}").json()
    assert track2["status"] == "RESOLVED"
    assert len(track2["updates"]) == 1
    assert track2["updates"][0]["message"] == "Update for Report 2 only"


def test_tracking_never_logs_case_code_or_digest(client: TestClient, caplog):
    """Verify that case code and its digest are NEVER written to application logs."""
    payload = {
        "category": "OTHER",
        "description": "Operational log hygiene verification report.",
    }
    create_res = client.post("/api/v1/reports", json=payload)
    case_code = create_res.json()["case_code"]
    digest = derive_case_code_digest(case_code)

    with caplog.at_level(logging.DEBUG):
        track_res = client.get(f"/api/v1/reports/{case_code}")
        assert track_res.status_code == 200

    # Inspect application log records specifically
    app_log_messages = [
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("app")
    ]
    app_log_text = "\n".join(app_log_messages)

    assert case_code not in app_log_text
    assert digest not in app_log_text


@pytest.mark.asyncio
async def test_tracking_database_error_safety(client: TestClient):
    """Verify that database errors during tracking produce a safe 500 API response without leaking internals."""
    with patch.object(
        report_service,
        "get_report_tracking",
        side_effect=RuntimeError("Simulated internal DB connection failure"),
    ):
        response = client.get("/api/v1/reports/wdc_valid_format_test_code_12345")
        assert response.status_code == 500
        data = response.json()
        assert data == {"detail": "An error occurred while tracking the report."}
        # Verify internal errors, SQL fragments, and stack traces are absent
        assert "Simulated internal DB connection failure" not in str(data)
        assert "SELECT" not in str(data)
