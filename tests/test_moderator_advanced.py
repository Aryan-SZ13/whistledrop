from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.models.enums import ModeratorRole, ReportCategory, ReportPriority, ReportStatus, ReportUpdateType
from app.models.moderator import Moderator
from app.models.report import Report
from app.schemas.report import ReportCreate
from app.services.auth_service import auth_service
from app.services.moderator_service import moderator_service
from app.services.report_service import report_service


async def create_auth_headers(
    db_session: AsyncSession,
    role: ModeratorRole = ModeratorRole.MODERATOR,
    username: str = "adv_mod",
    is_active: bool = True,
) -> tuple[dict, Moderator]:
    mod = await auth_service.create_moderator(
        db_session,
        username=username,
        password="TestPassword123!",
        role=role,
        is_active=is_active,
    )
    token = create_access_token(subject=str(mod.id))
    return {"Authorization": f"Bearer {token}"}, mod


# ==============================================================================
# Mandatory OCC on All 5 Mutating Endpoints
# ==============================================================================

@pytest.mark.asyncio
async def test_occ_mandatory_on_status_endpoint(client, db_session: AsyncSession):
    """Verify status update requires expected_version, rejects stale with 409, bumps on success."""
    headers, _ = await create_auth_headers(db_session, username="occ_status_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="OCC status incident"),
    )
    assert r.version_id == 1

    # 1. Missing expected_version -> 422
    res_missing = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW"},
    )
    assert res_missing.status_code == 422

    # 2. Stale expected_version (e.g. 99) -> 409 Conflict with current_version
    res_stale = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW", "expected_version": 99},
    )
    assert res_stale.status_code == 409
    body_stale = res_stale.json()
    assert "Conflict" in body_stale["detail"]
    assert body_stale["current_version"] == 1

    # 3. Matching expected_version -> 200, version becomes 2
    res_ok = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=headers,
        json={"status": "UNDER_REVIEW", "expected_version": 1},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["version_id"] == 2


@pytest.mark.asyncio
async def test_occ_mandatory_on_priority_endpoint(client, db_session: AsyncSession):
    """Verify priority update requires expected_version and detects conflicts."""
    headers, _ = await create_auth_headers(db_session, username="occ_prio_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="OCC prio incident"),
    )

    # 1. Missing expected_version -> 422
    res_missing = client.patch(
        f"/api/v1/moderator/reports/{r.id}/priority",
        headers=headers,
        json={"priority": "HIGH"},
    )
    assert res_missing.status_code == 422

    # 2. Stale expected_version -> 409
    res_stale = client.patch(
        f"/api/v1/moderator/reports/{r.id}/priority",
        headers=headers,
        json={"priority": "HIGH", "expected_version": 5},
    )
    assert res_stale.status_code == 409
    assert res_stale.json()["current_version"] == 1

    # 3. Matching expected_version -> 200
    res_ok = client.patch(
        f"/api/v1/moderator/reports/{r.id}/priority",
        headers=headers,
        json={"priority": "HIGH", "expected_version": 1},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["priority"] == "HIGH"
    assert res_ok.json()["version_id"] == 2


@pytest.mark.asyncio
async def test_occ_mandatory_on_assignment_endpoint(client, db_session: AsyncSession):
    """Verify assignment requires expected_version and detects conflicts."""
    headers, mod = await create_auth_headers(db_session, username="occ_assign_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.TECHNICAL, description="OCC assign incident"),
    )

    # 1. Missing expected_version -> 422
    res_missing = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=headers,
        json={"moderator_id": str(mod.id)},
    )
    assert res_missing.status_code == 422

    # 2. Stale expected_version -> 409
    res_stale = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=headers,
        json={"moderator_id": str(mod.id), "expected_version": 2},
    )
    assert res_stale.status_code == 409
    assert res_stale.json()["current_version"] == 1

    # 3. Matching expected_version -> 200
    res_ok = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=headers,
        json={"moderator_id": str(mod.id), "expected_version": 1},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["assigned_to"] == str(mod.id)
    assert res_ok.json()["version_id"] == 2


@pytest.mark.asyncio
async def test_occ_mandatory_on_updates_endpoints(client, db_session: AsyncSession):
    """Verify both PUBLIC_UPDATE and INTERNAL_NOTE require expected_version and detect conflicts."""
    headers, _ = await create_auth_headers(db_session, username="occ_notes_mod")
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description="OCC notes incident"),
    )

    # 1. Public update missing expected_version -> 422
    res_pub_missing = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Public update", "type": "PUBLIC_UPDATE"},
    )
    assert res_pub_missing.status_code == 422

    # 2. Public update stale -> 409
    res_pub_stale = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Public update", "type": "PUBLIC_UPDATE", "expected_version": 2},
    )
    assert res_pub_stale.status_code == 409

    # 3. Public update matching -> 201 (bumps report version to 2)
    res_pub_ok = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Public update", "type": "PUBLIC_UPDATE", "expected_version": 1},
    )
    assert res_pub_ok.status_code == 201

    # 4. Internal note missing expected_version -> 422
    res_note_missing = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Internal review note", "type": "INTERNAL_NOTE"},
    )
    assert res_note_missing.status_code == 422

    # 5. Internal note with old version 1 -> 409 (since version is now 2)
    res_note_stale = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Internal review note", "type": "INTERNAL_NOTE", "expected_version": 1},
    )
    assert res_note_stale.status_code == 409
    assert res_note_stale.json()["current_version"] == 2

    # 6. Internal note with version 2 -> 201 (bumps version to 3)
    res_note_ok = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=headers,
        json={"message": "Internal review note", "type": "INTERNAL_NOTE", "expected_version": 2},
    )
    assert res_note_ok.status_code == 201


# ==============================================================================
# Role Matrix & Reopening Closed Reports
# ==============================================================================

@pytest.mark.asyncio
async def test_reopen_closed_report_requires_admin_and_reason(client, db_session: AsyncSession):
    """Verify reopening closed reports requires ADMIN role and >= 10 char reason."""
    mod_headers, _ = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="std_mod_reopen")
    admin_headers, _ = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="admin_mod_reopen")

    # Create report and resolve it
    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Closed case to reopen"),
    )
    # Transition: 1 -> UNDER_REVIEW -> 2 -> RESOLVED -> 3
    client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=mod_headers,
        json={"status": "UNDER_REVIEW", "expected_version": 1},
    )
    client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=mod_headers,
        json={"status": "RESOLVED", "expected_version": 2},
    )

    # 1. Standard moderator attempts to reopen -> 403 Forbidden
    res_std = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=mod_headers,
        json={"status": "UNDER_REVIEW", "expected_version": 3, "reopen_reason": "New whistleblower evidence submitted"},
    )
    assert res_std.status_code == 403
    assert "Admin privileges required" in res_std.json()["detail"]

    # 2. Admin attempts reopen without reason -> 422
    res_no_reason = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={"status": "UNDER_REVIEW", "expected_version": 3},
    )
    assert res_no_reason.status_code == 422

    # 3. Admin attempts reopen with short reason (< 10 chars) -> 422
    res_short = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={"status": "UNDER_REVIEW", "expected_version": 3, "reopen_reason": "Too short"},
    )
    assert res_short.status_code == 422

    # 4. Admin successfully reopens with valid reason -> 200, status UNDER_REVIEW
    res_reopen = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={
            "status": "UNDER_REVIEW",
            "expected_version": 3,
            "reopen_reason": "Reopening case due to new critical corroborating documents.",
        },
    )
    assert res_reopen.status_code == 200
    assert res_reopen.json()["status"] == "UNDER_REVIEW"
    assert res_reopen.json()["version_id"] == 4


# ==============================================================================
# Assignment Matrix & Deactivation Semantics
# ==============================================================================

@pytest.mark.asyncio
async def test_assignment_matrix_and_inactive_rejection(client, db_session: AsyncSession):
    """Verify assignment rules, stealing prevention, and rejection of inactive moderators."""
    mod1_headers, mod1 = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="assign_mod1")
    mod2_headers, mod2 = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="assign_mod2")
    admin_headers, _ = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="assign_admin")
    _, inactive_mod = await create_auth_headers(db_session, is_active=False, username="inactive_assignee")

    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.TECHNICAL, description="Assignment matrix test case"),
    )

    # 1. Mod1 self-assigns unassigned case -> 200
    res_claim = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=mod1_headers,
        json={"moderator_id": str(mod1.id), "expected_version": 1},
    )
    assert res_claim.status_code == 200
    assert res_claim.json()["assigned_to"] == str(mod1.id)

    # 2. Mod2 attempts to steal case from Mod1 -> 403 Forbidden
    res_steal = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=mod2_headers,
        json={"moderator_id": str(mod2.id), "expected_version": 2},
    )
    assert res_steal.status_code == 403

    # 3. Attempt to assign to inactive moderator -> 422 Unprocessable
    res_inactive = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=admin_headers,
        json={"moderator_id": str(inactive_mod.id), "expected_version": 2},
    )
    assert res_inactive.status_code == 422
    assert "inactive moderator" in res_inactive.json()["detail"].lower()

    # 4. Mod1 hands off case to Mod2 -> 200
    res_handoff = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=mod1_headers,
        json={"moderator_id": str(mod2.id), "expected_version": 2},
    )
    assert res_handoff.status_code == 200
    assert res_handoff.json()["assigned_to"] == str(mod2.id)

    # 5. Admin can reassign back to Mod1 -> 200
    res_admin = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=admin_headers,
        json={"moderator_id": str(mod1.id), "expected_version": 3},
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["assigned_to"] == str(mod1.id)

    # 6. Admin unassigns report -> 200
    res_unassign = client.patch(
        f"/api/v1/moderator/reports/{r.id}/assignment",
        headers=admin_headers,
        json={"moderator_id": None, "expected_version": 4},
    )
    assert res_unassign.status_code == 200
    assert res_unassign.json()["assigned_to"] is None


# ==============================================================================
# Cursor-Paginated Unified Case Activity Timeline
# ==============================================================================

@pytest.mark.asyncio
async def test_cursor_paginated_timeline(client, db_session: AsyncSession):
    """Verify cursor pagination, deterministic ordering, and invalid cursor rejection."""
    headers, mod = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="timeline_mod")

    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Timeline pagination report"),
    )

    # Generate 5 timeline events:
    # 1: Under review
    client.patch(f"/api/v1/moderator/reports/{r.id}/status", headers=headers, json={"status": "UNDER_REVIEW", "expected_version": 1})
    # 2: Priority high
    client.patch(f"/api/v1/moderator/reports/{r.id}/priority", headers=headers, json={"priority": "HIGH", "expected_version": 2})
    # 3: Assign to self
    client.patch(f"/api/v1/moderator/reports/{r.id}/assignment", headers=headers, json={"moderator_id": str(mod.id), "expected_version": 3})
    # 4: Note 1
    client.post(f"/api/v1/moderator/reports/{r.id}/updates", headers=headers, json={"message": "Note 1", "type": "INTERNAL_NOTE", "expected_version": 4})
    # 5: Public update
    client.post(f"/api/v1/moderator/reports/{r.id}/updates", headers=headers, json={"message": "Public 1", "type": "PUBLIC_UPDATE", "expected_version": 5})

    # Page 1: limit 2
    res_p1 = client.get(f"/api/v1/moderator/reports/{r.id}/timeline?limit=2", headers=headers)
    assert res_p1.status_code == 200
    p1_data = res_p1.json()
    assert len(p1_data["items"]) == 2
    assert p1_data["total"] >= 5
    assert p1_data["next_cursor"] is not None

    # Page 2 using next_cursor
    res_p2 = client.get(f"/api/v1/moderator/reports/{r.id}/timeline?limit=2&cursor={p1_data['next_cursor']}", headers=headers)
    assert res_p2.status_code == 200
    p2_data = res_p2.json()
    assert len(p2_data["items"]) == 2

    # Verify no item duplication between pages
    ids_p1 = {item["id"] for item in p1_data["items"]}
    ids_p2 = {item["id"] for item in p2_data["items"]}
    assert ids_p1.isdisjoint(ids_p2)

    # Page 3
    res_p3 = client.get(f"/api/v1/moderator/reports/{r.id}/timeline?limit=2&cursor={p2_data['next_cursor']}", headers=headers)
    assert res_p3.status_code == 200
    p3_data = res_p3.json()
    assert len(p3_data["items"]) >= 1

    # Malformed cursor returns 422
    res_bad_cursor = client.get(f"/api/v1/moderator/reports/{r.id}/timeline?cursor=invalid_base64_cursor", headers=headers)
    assert res_bad_cursor.status_code == 422
    assert "Invalid pagination cursor" in res_bad_cursor.json()["detail"]


# ==============================================================================
# Dashboard Stats & Advanced Filtering / Search
# ==============================================================================

@pytest.mark.asyncio
async def test_dashboard_stats_and_filtering(client, db_session: AsyncSession):
    """Verify consolidated dashboard statistics and multi-field search and filters."""
    headers, mod = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="stats_mod")

    # Seed diverse reports
    r1, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Bribery inside procurement office"),
    )
    r2, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Firewall exploit in data center"),
    )

    # Mutate r1 to HIGH priority and assign to current mod
    client.patch(f"/api/v1/moderator/reports/{r1.id}/priority", headers=headers, json={"priority": "HIGH", "expected_version": 1})
    client.patch(f"/api/v1/moderator/reports/{r1.id}/assignment", headers=headers, json={"moderator_id": str(mod.id), "expected_version": 2})

    # Fetch stats
    res_stats = client.get("/api/v1/moderator/dashboard/stats", headers=headers)
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["priority_high"] >= 1
    assert stats["my_active_cases"] >= 1
    assert stats["unassigned_active"] >= 1

    # Search by text with wildcards
    res_search = client.get("/api/v1/moderator/reports?search=procurement", headers=headers)
    assert res_search.status_code == 200
    assert any("procurement" in item["description"] for item in res_search.json()["items"])

    # Search with SQL wildcard character should match literal
    res_wildcard = client.get("/api/v1/moderator/reports?search=procure%ment", headers=headers)
    assert res_wildcard.status_code == 200

    # Filter by priority HIGH
    res_prio = client.get("/api/v1/moderator/reports?priority=HIGH", headers=headers)
    assert res_prio.status_code == 200
    assert all(item["priority"] == "HIGH" for item in res_prio.json()["items"])

    # Filter by unassigned=true
    res_unassigned = client.get("/api/v1/moderator/reports?unassigned=true", headers=headers)
    assert res_unassigned.status_code == 200
    assert all(item["assigned_to"] is None for item in res_unassigned.json()["items"])

    # Test since > 90 days returns 422
    old_date = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
    res_old_since = client.get(f"/api/v1/moderator/dashboard/stats?since={old_date}", headers=headers)
    assert res_old_since.status_code == 422


# ==============================================================================
# SQL Wildcard Escaping & Free-Form Bounds Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_search_sql_wildcard_escaping(client, db_session: AsyncSession):
    """Verify that %, _, and \\ characters in search query are treated as literals."""
    headers, _ = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="wildcard_mod")

    # Seed reports with special characters
    r_percent, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Offering 50% discount on kickbacks"),
    )
    r_other_num, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.CORRUPTION, description="Offering 500 discount on kickbacks"),
    )
    r_underscore, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Audit of file_name_test123 source"),
    )
    r_other_char, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Audit of fileXnameXtest123 source"),
    )
    r_backslash, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description=r"Detected leak in C:\Windows\System32 directory"),
    )
    r_mixed, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.OTHER, description=r"Special pattern 100%_safe\guarantee found"),
    )

    # 1. Search literal %: "50%" should match r_percent but NOT r_other_num
    res_pct = client.get("/api/v1/moderator/reports?search=50%", headers=headers)
    assert res_pct.status_code == 200
    pct_ids = {item["id"] for item in res_pct.json()["items"]}
    assert str(r_percent.id) in pct_ids
    assert str(r_other_num.id) not in pct_ids

    # 2. Search literal _: "file_name" should match r_underscore but NOT r_other_char
    res_us = client.get("/api/v1/moderator/reports?search=file_name", headers=headers)
    assert res_us.status_code == 200
    us_ids = {item["id"] for item in res_us.json()["items"]}
    assert str(r_underscore.id) in us_ids
    assert str(r_other_char.id) not in us_ids

    # 3. Search literal \: r"C:\Windows" should match r_backslash
    res_bs = client.get("/api/v1/moderator/reports?search=C:\\Windows", headers=headers)
    assert res_bs.status_code == 200
    bs_ids = {item["id"] for item in res_bs.json()["items"]}
    assert str(r_backslash.id) in bs_ids

    # 4. Search mixed combination: "100%_safe\guarantee"
    res_mix = client.get("/api/v1/moderator/reports?search=100%25_safe%5Cguarantee", headers=headers)
    assert res_mix.status_code == 200
    mix_ids = {item["id"] for item in res_mix.json()["items"]}
    assert str(r_mixed.id) in mix_ids


@pytest.mark.asyncio
async def test_free_form_input_bounds_enforced(client, db_session: AsyncSession):
    """Verify minimum and maximum length bounds on free-form inputs."""
    admin_headers, _ = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="bounds_admin")

    r, _ = await report_service.create_report(
        db_session,
        ReportCreate(category=ReportCategory.SECURITY, description="Free-form input boundary test"),
    )

    # 1. Search parameter > 200 chars -> 422
    long_search = "a" * 201
    res_search = client.get(f"/api/v1/moderator/reports?search={long_search}", headers=admin_headers)
    assert res_search.status_code == 422

    # 2. Update message > 5000 chars -> 422
    long_msg = "a" * 5001
    res_msg = client.post(
        f"/api/v1/moderator/reports/{r.id}/updates",
        headers=admin_headers,
        json={"message": long_msg, "type": "INTERNAL_NOTE", "expected_version": 1},
    )
    assert res_msg.status_code == 422

    # 3. Reopen reason > 1000 chars -> 422
    client.patch(f"/api/v1/moderator/reports/{r.id}/status", headers=admin_headers, json={"status": "UNDER_REVIEW", "expected_version": 1})
    client.patch(f"/api/v1/moderator/reports/{r.id}/status", headers=admin_headers, json={"status": "RESOLVED", "expected_version": 2})

    long_reason = "a" * 1001
    res_reopen = client.patch(
        f"/api/v1/moderator/reports/{r.id}/status",
        headers=admin_headers,
        json={"status": "UNDER_REVIEW", "expected_version": 3, "reopen_reason": long_reason},
    )
    assert res_reopen.status_code == 422

    # 4. Timeline cursor > 512 chars -> 422
    long_cursor = "c" * 513
    res_cursor = client.get(f"/api/v1/moderator/reports/{r.id}/timeline?cursor={long_cursor}", headers=admin_headers)
    assert res_cursor.status_code == 422
