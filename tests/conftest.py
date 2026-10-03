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
    async with test_engine.begin() as conn:
        await conn.execute(
            sa.text("TRUNCATE reports, moderators, report_updates, audit_logs CASCADE")
        )
    yield
    async with test_engine.begin() as conn:
        await conn.execute(
            sa.text("TRUNCATE reports, moderators, report_updates, audit_logs CASCADE")
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
