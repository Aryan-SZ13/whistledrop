import uuid
from datetime import datetime, timezone
import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import Base
from app.models.enums import ModeratorRole, ReportCategory, ReportStatus
from app.models.moderator import Moderator
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.models.audit_log import AuditLog


def test_model_metadata_loads_correctly():
    """Verify that all domain models are registered with Base.metadata."""
    table_names = set(Base.metadata.tables.keys())
    expected_tables = {"moderators", "reports", "report_updates", "audit_logs"}
    assert expected_tables.issubset(table_names), f"Missing tables in metadata: {expected_tables - table_names}"


@pytest.mark.asyncio
async def test_database_connection(db_session: AsyncSession):
    """Verify active database connectivity and execution."""
    result = await db_session.execute(sa.text("SELECT 1"))
    assert result.scalar() == 1


@pytest.mark.asyncio
async def test_required_tables_exist(db_session: AsyncSession):
    """Verify that Alembic migrations created all required tables in PostgreSQL."""
    query = sa.text("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
    """)
    result = await db_session.execute(query)
    tables = {row[0] for row in result.fetchall()}
    assert "moderators" in tables
    assert "reports" in tables
    assert "report_updates" in tables
    assert "audit_logs" in tables
    assert "alembic_version" in tables


def test_no_reporter_identity_columns_in_reports():
    """Verify that the reports model contains NO reporter identity or network metadata columns."""
    report_columns = {col.name.lower() for col in Report.__table__.columns}
    forbidden_terms = {
        "name", "reporter", "reporter_name", "email", "reporter_email",
        "phone", "user_id", "account_id", "ip", "ip_address",
        "user_agent", "useragent"
    }
    present_forbidden = report_columns.intersection(forbidden_terms)
    assert not present_forbidden, f"Critical privacy violation: forbidden columns found: {present_forbidden}"


@pytest.mark.asyncio
async def test_unique_constraint_moderator_username(db_session: AsyncSession):
    """Verify database enforces unique usernames for moderators."""
    u1 = Moderator(
        username="lead_moderator",
        password_hash="hashed_pw_1",
        role=ModeratorRole.ADMIN,
    )
    db_session.add(u1)
    await db_session.flush()

    u2 = Moderator(
        username="lead_moderator",
        password_hash="hashed_pw_2",
        role=ModeratorRole.MODERATOR,
    )
    db_session.add(u2)
    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.asyncio
async def test_unique_constraint_case_code_digest(db_session: AsyncSession):
    """Verify database enforces unique case_code_digest values for reports."""
    digest = "unique_sha256_digest_token_12345"
    r1 = Report(
        case_code_digest=digest,
        category=ReportCategory.CORRUPTION,
        description="First incident report",
    )
    db_session.add(r1)
    await db_session.flush()

    r2 = Report(
        case_code_digest=digest,
        category=ReportCategory.SECURITY,
        description="Duplicate digest incident report",
    )
    db_session.add(r2)
    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.asyncio
async def test_enum_values_storage_and_retrieval(db_session: AsyncSession):
    """Verify enum fields store and retrieve correct typed values."""
    report = Report(
        case_code_digest=f"digest_{uuid.uuid4().hex}",
        category=ReportCategory.SECURITY,
        description="Security vulnerability detected",
        status=ReportStatus.UNDER_REVIEW,
    )
    db_session.add(report)
    await db_session.flush()
    await db_session.refresh(report)

    assert report.category == ReportCategory.SECURITY
    assert report.status == ReportStatus.UNDER_REVIEW
    assert isinstance(report.id, uuid.UUID)


@pytest.mark.asyncio
async def test_foreign_keys_and_cascades(db_session: AsyncSession):
    """Verify foreign key constraints, cascading deletes, and nullification."""
    # 1. Create moderator and report
    mod = Moderator(
        username=f"mod_{uuid.uuid4().hex[:8]}",
        password_hash="hashed_pw",
        role=ModeratorRole.MODERATOR,
    )
    report = Report(
        case_code_digest=f"digest_{uuid.uuid4().hex}",
        category=ReportCategory.TECHNICAL,
        description="Technical defect report",
    )
    db_session.add_all([mod, report])
    await db_session.flush()

    # 2. Create update and audit log
    update = ReportUpdate(
        report_id=report.id,
        created_by=mod.id,
        message="Status updated to under review",
    )
    audit = AuditLog(
        report_id=report.id,
        moderator_id=mod.id,
        action="UPDATE_STATUS",
        metadata_={"new_status": "UNDER_REVIEW"},
    )
    db_session.add_all([update, audit])
    await db_session.flush()

    # 3. Verify relationships
    assert update.report_id == report.id
    assert audit.moderator_id == mod.id

    # 4. Verify cascade on report deletion: report_update is deleted, audit_log report_id becomes NULL
    await db_session.delete(report)
    await db_session.flush()

    # Query report update -> should be deleted by CASCADE
    res_update = await db_session.execute(
        sa.select(ReportUpdate).where(ReportUpdate.id == update.id)
    )
    assert res_update.scalar_one_or_none() is None

    # Query audit log -> report_id should be SET NULL
    await db_session.refresh(audit)
    assert audit.report_id is None
    assert audit.moderator_id == mod.id


@pytest.mark.asyncio
async def test_timezone_aware_timestamps(db_session: AsyncSession):
    """Verify database timestamps are timezone-aware."""
    report = Report(
        case_code_digest=f"digest_{uuid.uuid4().hex}",
        category=ReportCategory.HARASSMENT,
        description="Harassment incident details",
    )
    db_session.add(report)
    await db_session.flush()
    await db_session.refresh(report)

    assert report.created_at is not None
    assert report.created_at.tzinfo is not None
