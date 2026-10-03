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


# ==============================================================================
# Phase 6: Lifecycle State Machine, Updates, Auditing & Atomicity Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_state_machine_valid_transitions(client, db_session: AsyncSession):
    """Verify valid transitions: SUBMITTED -> UNDER_REVIEW -> RESOLVED / DISMISSED."""
    headers = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="lifecycle_mod")

    # 1. SUBMITTED -> UNDER_REVIEW -> RESOLVED
    r1, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Report 1 for lifecycle test"),
    )
    res1 = client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "UNDER_REVIEW"

    res1_resolved = client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "RESOLVED"},
    )
    assert res1_resolved.status_code == 200
    assert res1_resolved.json()["status"] == "RESOLVED"

    # 2. SUBMITTED -> UNDER_REVIEW -> DISMISSED
    r2, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Report 2 for lifecycle test"),
    )
    res2 = client.patch(
        f"/api/v1/moderator/reports/{r2.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res2.status_code == 200

    res2_dismissed = client.patch(
        f"/api/v1/moderator/reports/{r2.id}/status",
        headers=headers,
        json={"status": "DISMISSED"},
    )
    assert res2_dismissed.status_code == 200
    assert res2_dismissed.json()["status"] == "DISMISSED"


@pytest.mark.asyncio
async def test_state_machine_invalid_transitions_rejected_with_409(client, db_session: AsyncSession):
    """Verify illegal transitions are rejected with 409 Conflict."""
    headers = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="invalid_trans_mod")

    # A. SUBMITTED -> RESOLVED (Illegal)
    r1, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Direct resolve attempt"),
    )
    res_direct_res = client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "RESOLVED"},
    )
    assert res_direct_res.status_code == 409
    assert "Invalid report lifecycle transition" in res_direct_res.json()["detail"]

    # B. SUBMITTED -> DISMISSED (Illegal)
    res_direct_dism = client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "DISMISSED"},
    )
    assert res_direct_dism.status_code == 409

    # C. UNDER_REVIEW -> SUBMITTED (Illegal backwards transition)
    client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    res_back = client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "SUBMITTED"},
    )
    assert res_back.status_code == 409

    # D. RESOLVED -> anything (Terminal state)
    client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "RESOLVED"},
    )
    res_after_resolved = client.patch(
        f"/api/v1/moderator/reports/{r1.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res_after_resolved.status_code == 409

    # E. DISMISSED -> anything (Terminal state)
    r2, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description="Dismissed terminal check"),
    )
    client.patch(
        f"/api/v1/moderator/reports/{r2.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    client.patch(
        f"/api/v1/moderator/reports/{r2.id}/status",
        headers=headers,
        json={"status": "DISMISSED"},
    )
    res_after_dismissed = client.patch(
        f"/api/v1/moderator/reports/{r2.id}/status",
        headers=headers,
        json={"status": "RESOLVED"},
    )
    assert res_after_dismissed.status_code == 409


@pytest.mark.asyncio
async def test_status_mutation_auth_boundaries(client, db_session: AsyncSession):
    """Verify status mutation requires active authenticated moderator or admin."""
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Auth check report"),
    )

    # 1. Unauthenticated -> 401
    res_unauth = client.patch(f"/api/v1/moderator/reports/{r.id}/status", json={"status": "UNDER_REVIEW"})
    assert res_unauth.status_code == 401

    # 2. Invalid JWT -> 401
    res_bad_jwt = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers={"Authorization": "Bearer bad.token"},
        json={"status": "UNDER_REVIEW"},
    )
    assert res_bad_jwt.status_code == 401

    # 3. Inactive moderator -> 401
    inactive_headers = await create_auth_headers(db_session, is_active=False, username="inactive_mod_status")
    res_inactive = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=inactive_headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res_inactive.status_code == 401

    # 4. Admin can mutate -> 200
    admin_headers = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="admin_mod_status")
    res_admin = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["status"] == "UNDER_REVIEW"


@pytest.mark.asyncio
async def test_status_mutation_creates_audit_log(client, db_session: AsyncSession):
    """Verify each status transition generates an AuditLog row with structured safe metadata."""
    import sqlalchemy as sa
    from app.models.audit_log import AuditLog

    headers = await create_auth_headers(db_session, username="audit_tester_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.TECHNICAL, description="Audit log verification report"),
    )

    # Trigger transition
    res = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res.status_code == 200

    # Query audit logs for this report
    stmt = sa.select(AuditLog).where(
        AuditLog.report_id == r.id,
        AuditLog.action == "REPORT_STATUS_CHANGED",
    )
    res_audit = await db_session.execute(stmt)
    logs = res_audit.scalars().all()
    assert len(logs) == 1

    log = logs[0]
    assert log.report_id == r.id
    assert log.moderator_id is not None
    assert log.metadata_ == {"from_status": "SUBMITTED", "to_status": "UNDER_REVIEW"}
    assert log.created_at is not None


@pytest.mark.asyncio
async def test_failed_status_transition_creates_no_audit_log(client, db_session: AsyncSession):
    """Verify atomic rollback: invalid transition produces no new AuditLog rows."""
    import sqlalchemy as sa
    from app.models.audit_log import AuditLog

    headers = await create_auth_headers(db_session, username="atomic_fail_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description="Rollback audit test"),
    )

    # Count audit logs before
    count_before = (
        await db_session.execute(
            sa.select(sa.func.count(AuditLog.id)).where(AuditLog.report_id == r.id)
        )
    ).scalar()

    # Attempt illegal transition
    res = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=headers,
        json={"status": "RESOLVED"},
    )
    assert res.status_code == 409

    # Count audit logs after
    count_after = (
        await db_session.execute(
            sa.select(sa.func.count(AuditLog.id)).where(AuditLog.report_id == r.id)
        )
    ).scalar()

    assert count_after == count_before


@pytest.mark.asyncio
async def test_public_update_vs_internal_note_visibility(client, db_session: AsyncSession):
    """Verify PUBLIC_UPDATE appears in tracking, while INTERNAL_NOTE is strictly concealed."""
    headers = await create_auth_headers(db_session, username="note_visibility_mod")

    # 1. Anonymous submission
    sub_res = client.post(
        "/api/v1/reports",
        json={"category": "SECURITY", "description": "Tracking note visibility check incident."},
    )
    assert sub_res.status_code == 201
    case_code = sub_res.json()["case_code"]

    # Retrieve internal report id via moderator list
    list_res = client.get("/api/v1/moderator/reports", headers=headers)
    report_id = list_res.json()["items"][0]["id"]

    # 2. Moderator posts a PUBLIC_UPDATE
    pub_res = client.post(
        f"/api/v1/moderator/reports/{report_id}/updates",
        headers=headers,
        json={
            "message": "We have received and verified your submission.",
            "type": "PUBLIC_UPDATE",
        },
    )
    assert pub_res.status_code == 201
    assert pub_res.json()["type"] == "PUBLIC_UPDATE"

    # 3. Moderator posts an INTERNAL_NOTE
    note_res = client.post(
        f"/api/v1/moderator/reports/{report_id}/updates",
        headers=headers,
        json={
            "message": "Internal note: assigned senior analyst Jane Doe for forensic triage.",
            "type": "INTERNAL_NOTE",
        },
    )
    assert note_res.status_code == 201
    assert note_res.json()["type"] == "INTERNAL_NOTE"

    # 4. Anonymous tracking GET /api/v1/reports/{case_code}
    track_res = client.get(f"/api/v1/reports/{case_code}")
    assert track_res.status_code == 200
    track_data = track_res.json()

    # Must contain ONLY the public update
    assert len(track_data["updates"]) == 1
    assert track_data["updates"][0]["message"] == "We have received and verified your submission."
    # Internal note must NEVER appear in public response text
    assert "Internal note" not in track_res.text
    assert "Jane Doe" not in track_res.text
    assert "INTERNAL_NOTE" not in track_res.text

    # 5. Moderator detail view GET /api/v1/moderator/reports/{report_id}
    mod_detail_res = client.get(f"/api/v1/moderator/reports/{report_id}", headers=headers)
    assert mod_detail_res.status_code == 200
    mod_detail = mod_detail_res.json()

    # Moderator sees BOTH updates in chronological order
    assert len(mod_detail["updates"]) == 2
    types = [u["type"] for u in mod_detail["updates"]]
    assert types == ["PUBLIC_UPDATE", "INTERNAL_NOTE"]
    assert "Jane Doe" in mod_detail_res.text


@pytest.mark.asyncio
async def test_update_creation_creates_audit_log(client, db_session: AsyncSession):
    """Verify creating a report update generates an AuditLog entry without duplicating text."""
    import sqlalchemy as sa
    from app.models.audit_log import AuditLog

    headers = await create_auth_headers(db_session, username="update_audit_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Update audit log report"),
    )

    res = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Safe update message content", "type": "PUBLIC_UPDATE"},
    )
    assert res.status_code == 201

    # Query audit logs
    stmt = sa.select(AuditLog).where(
        AuditLog.report_id == r.id,
        AuditLog.action == "REPORT_UPDATE_CREATED",
    )
    res_audit = await db_session.execute(stmt)
    logs = res_audit.scalars().all()
    assert len(logs) == 1

    log = logs[0]
    assert log.report_id == r.id
    assert log.moderator_id is not None
    assert log.metadata_["update_type"] == "PUBLIC_UPDATE"
    # Ensure message content itself is NOT duplicated into audit log metadata
    assert "Safe update message content" not in str(log.metadata_)


@pytest.mark.asyncio
async def test_moderator_update_validation(client, db_session: AsyncSession):
    """Verify input validation on update creation: empty, oversized, extra fields."""
    headers = await create_auth_headers(db_session, username="val_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description="Validation test incident"),
    )

    # 1. Empty message -> 422
    res_empty = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "", "type": "PUBLIC_UPDATE"},
    )
    assert res_empty.status_code == 422

    # 2. Oversized message (> 5000 chars) -> 422
    res_oversized = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "A" * 5001, "type": "PUBLIC_UPDATE"},
    )
    assert res_oversized.status_code == 422

    # 3. Extra fields forbidden -> 422
    res_extra = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Valid update", "type": "PUBLIC_UPDATE", "moderator_id": str(uuid.uuid4())},
    )
    assert res_extra.status_code == 422

    # 4. Unknown report ID -> 404
    res_unknown = client.post(
        f"/api/v1/moderator/reports/{uuid.uuid4()}/updates",
        headers=headers,
        json={"message": "Valid update", "type": "PUBLIC_UPDATE"},
    )
    assert res_unknown.status_code == 404
    assert res_unknown.json()["detail"] == "Report not found"


