from typing import AsyncGenerator
import pytest
import pytest_asyncio
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.db.session import get_db
from app.main import app

# Test engine with NullPool to prevent event-loop cross-contamination between test cases
test_engine = create_async_engine(
    settings.async_database_url,
    poolclass=NullPool,
)

TestAsyncSession = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(autouse=True)
async def clean_database():
    """Ensure complete database table isolation before and after every test."""
    import app.db.session as session_module
    session_module.async_engine = test_engine
    session_module.async_session_maker = TestAsyncSession
    session_module.async_session_factory = TestAsyncSession
    import app.api.v1.endpoints.health as health_module
    health_module.async_engine = test_engine
    from app.services.evidence_service import evidence_service
    evidence_service.db_engine = test_engine
    async with test_engine.begin() as conn:
        await conn.execute(
            sa.text(
                "TRUNCATE reports, moderators, report_updates, audit_logs, evidence_attachments, "
                "case_messages, case_message_moderator_read_state, moderator_sessions, webhook_endpoints, "
                "outbox_events, webhook_deliveries, quorum_requests CASCADE"
            )
        )
    yield
    async with test_engine.begin() as conn:
        await conn.execute(
            sa.text(
                "TRUNCATE reports, moderators, report_updates, audit_logs, evidence_attachments, "
                "case_messages, case_message_moderator_read_state, moderator_sessions, webhook_endpoints, "
                "outbox_events, webhook_deliveries, quorum_requests CASCADE"
            )
        )


@pytest_asyncio.fixture(autouse=True)
async def clean_redis():
    """Ensure complete Redis key isolation between tests."""
    from app.db.redis import get_redis
    try:
        r = get_redis()
        await r.flushdb()
    except Exception:
        pass
    yield
    try:
        r = get_redis()
        await r.flushdb()
    except Exception:
        pass



@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provides an isolated database session that supports explicit commits."""
    async with TestAsyncSession() as session:
        try:
            yield session
        finally:
            await session.close()


@pytest.fixture
def client() -> TestClient:
    """TestClient configured with dependency overrides for database sessions."""
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with TestAsyncSession() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
