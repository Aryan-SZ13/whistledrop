import asyncio
from datetime import datetime, timezone
import hashlib
from unittest.mock import AsyncMock, patch
import uuid
import pytest
import redis.exceptions as redis_exceptions
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from tests.conftest import TestAsyncSession
from app.models.enums import ReportCategory
from app.models.report import Report
from app.models.transparency import MerkleLeaf, MerkleTreeState
from app.models.webhook import OutboxEvent
from app.schemas.report import ReportCreate
from app.services.report_service import report_service
from app.services.transparency_service import transparency_service
from app.services.webhook_dispatcher_service import webhook_dispatcher_service
from app.services.rate_limiter import RateLimitPolicy, RateLimitUnavailableError, rate_limiter


@pytest.mark.asyncio
async def test_concurrent_merkle_leaf_commitments(clean_database):
    """
    Concurrency Invariant: Contiguous leaf indices under heavy parallel transactions.
    Asserts zero sequence gaps, zero duplicates, and exact tree_size alignment.
    """
    total_concurrent = 15

    async def commit_worker(i: int):
        async with TestAsyncSession() as session:
            digest = hashlib.sha256(f"concurrent_payload_{i}_{uuid.uuid4()}".encode("utf-8")).digest()
            leaf, size = await transparency_service.commit_merkle_leaf(
                db=session,
                event_type="test.concurrent",
                opaque_reference=f"ref_{i}",
                payload_digest=digest,
            )
            await session.commit()
            return leaf.leaf_index, size

    results = await asyncio.gather(*(commit_worker(i) for i in range(total_concurrent)))

    indices = [r[0] for r in results]
    sizes = [r[1] for r in results]

    # Zero duplicate indices
    assert len(set(indices)) == total_concurrent

    # Continuous sequential indices without any gaps
    sorted_indices = sorted(indices)
    for idx, expected in enumerate(range(sorted_indices[0], sorted_indices[0] + total_concurrent)):
        assert sorted_indices[idx] == expected

    # Verify database state
    async with TestAsyncSession() as session:
        state_stmt = sa.select(MerkleTreeState).where(MerkleTreeState.id == 1)
        state = (await session.execute(state_stmt)).scalar_one()
        count_stmt = sa.select(sa.func.count(MerkleLeaf.leaf_index))
        actual_count = (await session.execute(count_stmt)).scalar()

        assert state.tree_size == actual_count
        assert state.next_leaf_index == actual_count


@pytest.mark.asyncio
async def test_concurrent_outbox_batch_claiming(clean_database):
    """
    Concurrency Invariant: Transactional lease exclusivity with SELECT FOR UPDATE SKIP LOCKED.
    Multiple workers claiming batches concurrently claim mutually disjoint event sets.
    """
    total_events = 24
    num_workers = 4

    # Seed pending events
    async with TestAsyncSession() as session:
        for i in range(total_events):
            event = OutboxEvent(
                opaque_event_id=f"evt_conc_{i}_{uuid.uuid4().hex[:8]}",
                event_type="case.updated",
                payload={"index": i},
                status="PENDING",
            )
            session.add(event)
        await session.commit()

    # Concurrent workers claiming batches
    async def worker_task(worker_id: str):
        async with TestAsyncSession() as session:
            claimed = await webhook_dispatcher_service.claim_batch(
                db=session,
                worker_id=worker_id,
                limit=10,
            )
            return worker_id, [e.opaque_event_id for e in claimed]

    worker_results = await asyncio.gather(
        *(worker_task(f"worker_{w}") for w in range(num_workers))
    )

    all_claimed_ids = []
    for worker_id, claimed_ids in worker_results:
        all_claimed_ids.extend(claimed_ids)

    # Invariant: Disjoint sets — no event claimed by more than one worker
    assert len(all_claimed_ids) == len(set(all_claimed_ids))
    assert len(all_claimed_ids) <= total_events


@pytest.mark.asyncio
async def test_concurrent_report_creations(clean_database):
    """
    Concurrency Invariant: High-volume concurrent report submissions atomically allocate
    distinct high-entropy case codes, envelope DEKs, and Merkle leaves.
    """
    num_reports = 8

    async def submit_task(idx: int):
        async with TestAsyncSession() as session:
            report_in = ReportCreate(
                category=ReportCategory.CORRUPTION,
                description=f"Concurrent submission report {idx} payload.",
            )
            report, case_code = await report_service.create_report(
                db=session,
                report_in=report_in,
            )
            await session.commit()
            return report.id, case_code

    results = await asyncio.gather(*(submit_task(i) for i in range(num_reports)))

    report_ids = [r[0] for r in results]
    case_codes = [r[1] for r in results]

    assert len(set(report_ids)) == num_reports
    assert len(set(case_codes)) == num_reports

    # Confirm all have description encrypted and plaintext description is NULL
    async with TestAsyncSession() as session:
        for r_id in report_ids:
            rep = await session.get(Report, r_id)
            assert rep is not None
            assert rep.description is None
            assert rep.description_encrypted is not None


@pytest.mark.asyncio
async def test_redis_degradation_handling():
    """
    Failure Injection: Simulates Redis failure and asserts rate limiter raises
    RateLimitUnavailableError for fail-closed graceful degradation.
    """
    policy = RateLimitPolicy(key_prefix="fail_test", max_requests=5, window_seconds=60)
    mock_redis = AsyncMock()
    mock_redis.evalsha.side_effect = redis_exceptions.ConnectionError("Redis connection refused")
    mock_redis.script_load.side_effect = redis_exceptions.ConnectionError("Redis connection refused")

    with patch("app.services.rate_limiter.get_redis", return_value=mock_redis):
        with pytest.raises(RateLimitUnavailableError):
            await rate_limiter.check_rate_limit(policy, "192.0.2.1")
