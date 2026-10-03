from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.models.enums import ModeratorRole, ReportCategory, ReportStatus
from app.models.report import Report
from app.schemas.report import ReportCreate
from app.services.auth_service import auth_service
from app.services.report_service import report_service


# ==============================================================================
# Helpers
# ==============================================================================

async def create_auth_headers(
    db_session: AsyncSession,
    role: ModeratorRole = ModeratorRole.MODERATOR,
    is_active: bool = True,
    username: str = "test_mod",
) -> dict:
    """Helper to provision a moderator and return Bearer authorization headers."""
    mod = await auth_service.create_moderator(
        db_session,
        username=username,
        password="TestPassword123!",
        role=role,
        is_active=is_active,
    )
    token = create_access_token(subject=str(mod.id))
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# Security & Authentication Boundary Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_moderator_endpoints_return_401(client):
    """Verify listing and detail endpoints reject unauthenticated requests with 401."""
    # 1. List endpoint without token
    res_list = client.get("/api/v1/moderator/reports")
    assert res_list.status_code == 401
    assert res_list.json()["detail"] == "Authentication credentials were not provided"

    # 2. Detail endpoint without token
    res_detail = client.get(f"/api/v1/moderator/reports/{uuid.uuid4()}")
    assert res_detail.status_code == 401
    assert res_detail.json()["detail"] == "Authentication credentials were not provided"


@pytest.mark.asyncio
async def test_invalid_jwt_returns_401(client):
    """Verify malformed or forged JWT returns 401."""
    headers = {"Authorization": "Bearer invalid.jwt.signature"}

    res_list = client.get("/api/v1/moderator/reports", headers=headers)
    assert res_list.status_code == 401
    assert res_list.json()["detail"] == "Could not validate credentials"

    res_detail = client.get(f"/api/v1/moderator/reports/{uuid.uuid4()}", headers=headers)
    assert res_detail.status_code == 401
    assert res_detail.json()["detail"] == "Could not validate credentials"


@pytest.mark.asyncio
async def test_inactive_moderator_returns_401(client, db_session: AsyncSession):
    """Verify deactivated moderator token cannot access moderator endpoints."""
    headers = await create_auth_headers(db_session, is_active=False, username="deactivated_mod")

    res_list = client.get("/api/v1/moderator/reports", headers=headers)
    assert res_list.status_code == 401
    assert res_list.json()["detail"] == "Could not validate credentials"

    res_detail = client.get(f"/api/v1/moderator/reports/{uuid.uuid4()}", headers=headers)
    assert res_detail.status_code == 401
    assert res_detail.json()["detail"] == "Could not validate credentials"


# ==============================================================================
# Role-Based Access & Inspection Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_moderator_can_list_and_inspect_reports(client, db_session: AsyncSession):
    """Verify standard MODERATOR role can list and inspect reports."""
    headers = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="mod_user")

    # Seed report via public report service
    report_in = ReportCreate(
        category=ReportCategory.SECURITY,
        description="A serious security vulnerability in authentication layer.",
        evidence_url="https://example.com/vuln-proof.pdf",
    )
    report, _ = await report_service.create_report(db_session, report_in)

    # 1. List reports
    res_list = client.get("/api/v1/moderator/reports", headers=headers)
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] == 1
    assert len(list_data["items"]) == 1
    assert list_data["items"][0]["id"] == str(report.id)
    assert list_data["items"][0]["category"] == "SECURITY"
    assert list_data["items"][0]["description"] == "A serious security vulnerability in authentication layer."

    # 2. Inspect single report
    res_detail = client.get(f"/api/v1/moderator/reports/{report.id}", headers=headers)
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["id"] == str(report.id)
    assert detail_data["category"] == "SECURITY"
    assert detail_data["status"] == "SUBMITTED"
    assert detail_data["evidence_url"] == "https://example.com/vuln-proof.pdf"


@pytest.mark.asyncio
async def test_admin_can_list_and_inspect_reports(client, db_session: AsyncSession):
    """Verify ADMIN role can also list and inspect reports."""
    headers = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="admin_user")

    report_in = ReportCreate(
        category=ReportCategory.HARASSMENT,
        description="Harassment incident observed on team chat.",
    )
    report, _ = await report_service.create_report(db_session, report_in)

    res_list = client.get("/api/v1/moderator/reports", headers=headers)
    assert res_list.status_code == 200
    assert res_list.json()["total"] == 1

    res_detail = client.get(f"/api/v1/moderator/reports/{report.id}", headers=headers)
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == str(report.id)


@pytest.mark.asyncio
async def test_unknown_report_id_returns_404(client, db_session: AsyncSession):
    """Verify querying an unknown report UUID returns uniform 404."""
    headers = await create_auth_headers(db_session)
    nonexistent_id = uuid.uuid4()

    response = client.get(f"/api/v1/moderator/reports/{nonexistent_id}", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Report not found"


@pytest.mark.asyncio
async def test_malformed_report_id_returns_422(client, db_session: AsyncSession):
    """Verify malformed report ID produces safe 422 without leaking database exception."""
    headers = await create_auth_headers(db_session)

    response = client.get("/api/v1/moderator/reports/not-a-valid-uuid", headers=headers)
    assert response.status_code == 422
    assert "detail" in response.json()
    # Confirm no SQL error or internal trace leaked
    assert "psycopg" not in response.text.lower()
    assert "sqlalchemy" not in response.text.lower()
    assert "traceback" not in response.text.lower()


# ==============================================================================
# Filtering, Pagination & Ordering Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_status_and_category_filtering(client, db_session: AsyncSession):
    """Verify filtering by status and category in list endpoint."""
    headers = await create_auth_headers(db_session)

    # Seed reports with different categories and statuses
    r1, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Sec report 1"),
    )
    r2, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Corruption report 2"),
    )
    r3, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Sec report 3"),
    )

    # Modify r3 status directly to UNDER_REVIEW
    r3.status = ReportStatus.UNDER_REVIEW
    await db_session.commit()

    # 1. Filter by category=SECURITY
    res_cat = client.get("/api/v1/moderator/reports?category=SECURITY", headers=headers)
    assert res_cat.status_code == 200
    data_cat = res_cat.json()
    assert data_cat["total"] == 2
    assert all(item["category"] == "SECURITY" for item in data_cat["items"])

    # 2. Filter by status=UNDER_REVIEW
    res_stat = client.get("/api/v1/moderator/reports?status=UNDER_REVIEW", headers=headers)
    assert res_stat.status_code == 200
    data_stat = res_stat.json()
    assert data_stat["total"] == 1
    assert data_stat["items"][0]["id"] == str(r3.id)

    # 3. Filter by category=SECURITY and status=SUBMITTED
    res_both = client.get("/api/v1/moderator/reports?category=SECURITY&status=SUBMITTED", headers=headers)
    assert res_both.status_code == 200
    data_both = res_both.json()
    assert data_both["total"] == 1
    assert data_both["items"][0]["id"] == str(r1.id)


@pytest.mark.asyncio
async def test_pagination_and_deterministic_ordering(client, db_session: AsyncSession):
    """Verify pagination limit/offset and deterministic newest-first ordering."""
    headers = await create_auth_headers(db_session)

    # Create 5 reports
    created_ids = []
    for i in range(5):
        r, _ = await report_service.create_report(
            db_session,
            ReportCreate(category=ReportCategory.TECHNICAL, description=f"Technical incident {i}"),
        )
        created_ids.append(str(r.id))

    # Page 1: limit 2, offset 0
    res_p1 = client.get("/api/v1/moderator/reports?limit=2&offset=0", headers=headers)
    assert res_p1.status_code == 200
    data_p1 = res_p1.json()
    assert data_p1["total"] == 5
    assert len(data_p1["items"]) == 2
    assert data_p1["limit"] == 2
    assert data_p1["offset"] == 0

    # Page 2: limit 2, offset 2
    res_p2 = client.get("/api/v1/moderator/reports?limit=2&offset=2", headers=headers)
    assert res_p2.status_code == 200
    data_p2 = res_p2.json()
    assert len(data_p2["items"]) == 2
    assert data_p2["offset"] == 2

    # Verify no overlap between Page 1 and Page 2
    ids_p1 = {item["id"] for item in data_p1["items"]}
    ids_p2 = {item["id"] for item in data_p2["items"]}
    assert ids_p1.isdisjoint(ids_p2)

    # Page 3: limit 2, offset 4
    res_p3 = client.get("/api/v1/moderator/reports?limit=2&offset=4", headers=headers)
    assert res_p3.status_code == 200
    data_p3 = res_p3.json()
    assert len(data_p3["items"]) == 1

    # Verify deterministic ordering: newest created_at is first
    all_res = client.get("/api/v1/moderator/reports?limit=10&offset=0", headers=headers)
    items = all_res.json()["items"]
    timestamps = [datetime.fromisoformat(item["created_at"]) for item in items]
    assert timestamps == sorted(timestamps, reverse=True)


@pytest.mark.asyncio
async def test_pagination_validation_enforced(client, db_session: AsyncSession):
    """Verify invalid pagination inputs (limit > 100, limit < 1, offset < 0) return 422."""
    headers = await create_auth_headers(db_session)

    # limit > 100
    res_high = client.get("/api/v1/moderator/reports?limit=101", headers=headers)
    assert res_high.status_code == 422

    # limit < 1 (zero)
    res_zero = client.get("/api/v1/moderator/reports?limit=0", headers=headers)
    assert res_zero.status_code == 422

    # limit < 1 (negative)
    res_neg_limit = client.get("/api/v1/moderator/reports?limit=-5", headers=headers)
    assert res_neg_limit.status_code == 422

    # offset < 0
    res_neg_offset = client.get("/api/v1/moderator/reports?offset=-1", headers=headers)
    assert res_neg_offset.status_code == 422


# ==============================================================================
# Privacy & Secret Leakage Prevention Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_case_code_and_digest_never_exposed_in_moderator_api(client, db_session: AsyncSession):
    """Verify case_code and case_code_digest are absent from moderator list & detail responses."""
    headers = await create_auth_headers(db_session)

    report, case_code = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description="Confidential incident report"),
    )

    # 1. Check List response
    res_list = client.get("/api/v1/moderator/reports", headers=headers)
    list_item = res_list.json()["items"][0]

    assert case_code not in res_list.text
    assert report.case_code_digest not in res_list.text
    assert "case_code" not in list_item
    assert "case_code_digest" not in list_item
    assert "password_hash" not in list_item
    assert "reporter" not in list_item

    # 2. Check Detail response
    res_detail = client.get(f"/api/v1/moderator/reports/{report.id}", headers=headers)
    detail_data = res_detail.json()

    assert case_code not in res_detail.text
    assert report.case_code_digest not in res_detail.text
    assert "case_code" not in detail_data
    assert "case_code_digest" not in detail_data
    assert "password_hash" not in detail_data
    assert "reporter" not in detail_data


@pytest.mark.asyncio
async def test_public_anonymous_api_remains_unchanged(client):
    """Verify public anonymous submission and tracking endpoints remain completely functional."""
    # 1. Anonymous submission
    sub_res = client.post(
        "/api/v1/reports",
        json={"category": "SECURITY", "description": "Anonymous submission through public API."},
    )
    assert sub_res.status_code == 201
    sub_data = sub_res.json()
    assert "case_code" in sub_data
    assert "status" in sub_data
    assert "id" not in sub_data  # Public API still conceals internal UUID

    case_code = sub_data["case_code"]

    # 2. Anonymous tracking
    track_res = client.get(f"/api/v1/reports/{case_code}")
    assert track_res.status_code == 200
    track_data = track_res.json()
    assert track_data["status"] == "SUBMITTED"
    assert "updates" in track_data
    assert "id" not in track_data
    assert "description" not in track_data


@pytest.mark.asyncio
async def test_moderator_query_column_least_privilege(db_session: AsyncSession):
    """Verify moderator service executes queries that select only the 7 intended columns."""
    from app.services.moderator_service import moderator_service

    # Create a report with a distinct description
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Financial audit irregularity"),
    )

    # Track executed statements and their selected column names
    executed_statements = []

    original_execute = db_session.execute

    async def tracking_execute(statement, *args, **kwargs):
        executed_statements.append(statement)
        return await original_execute(statement, *args, **kwargs)

    db_session.execute = tracking_execute
    try:
        # 1. Test list_reports query columns
        items, total = await moderator_service.list_reports(db_session, limit=10, offset=0)
        assert len(items) >= 1
        assert total >= 1

        # Check statement columns
        # The second statement executed in list_reports is the items query
        items_stmt = executed_statements[1]
        selected_columns = [col.name for col in items_stmt.selected_columns]
        expected_columns = [
            "id",
            "category",
            "description",
            "evidence_url",
            "status",
            "created_at",
            "updated_at",
        ]
        assert selected_columns == expected_columns
        assert "case_code_digest" not in selected_columns

        # 2. Test get_report_by_id query columns
        executed_statements.clear()
        detail_item = await moderator_service.get_report_by_id(db_session, r.id)
        assert detail_item is not None
        assert detail_item.id == r.id

        detail_stmt = executed_statements[0]
        detail_columns = [col.name for col in detail_stmt.selected_columns]
        assert detail_columns == expected_columns
        assert "case_code_digest" not in detail_columns
    finally:
        db_session.execute = original_execute


@pytest.mark.asyncio
async def test_moderator_service_defensive_bounds_validation(db_session: AsyncSession):
    """Verify moderator_service raises ValueError if called with invalid limit or offset directly."""
    from app.services.moderator_service import moderator_service

    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        await moderator_service.list_reports(db_session, limit=0)

    with pytest.raises(ValueError, match="limit must be between 1 and 100"):
        await moderator_service.list_reports(db_session, limit=101)

    with pytest.raises(ValueError, match="offset must be non-negative"):
        await moderator_service.list_reports(db_session, offset=-1)

