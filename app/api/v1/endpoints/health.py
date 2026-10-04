import asyncio
import logging
from typing import Dict

from fastapi import APIRouter, Depends, Response, status
import sqlalchemy as sa

from app import __version__
from app.api.deps import require_admin
from app.core.config import settings
from app.core.metrics import (
    dependency_healthy,
    generate_metrics_response,
)
from app.db.redis import get_redis
from app.db.session import async_engine
from app.models.moderator import Moderator
from app.services.clamav_service import clamav_service
from app.services.evidence_service import reconciliation_worker_status

logger = logging.getLogger("app.health")
router = APIRouter()


@router.get("/health", summary="Liveness Probe")
async def health_check():
    """Liveness probe validating process is alive and event loop responds. Zero external dependencies."""
    return {
        "status": "ok",
        "app": settings.PROJECT_NAME,
        "version": __version__,
    }


@router.get("/ready", summary="Readiness Probe")
async def readiness_check():
    """Readiness probe checking PostgreSQL, Redis, ClamAV, and Worker status.

    Returns HTTP 200 {"status": "ready"} if all systems ready.
    Returns HTTP 503 {"status": "not_ready"} if any check fails.
    Zero internal dependency names, hostnames, ports, or error messages are returned in HTTP body.
    """
    checks: Dict[str, bool] = {
        "postgres": False,
        "redis": False,
        "clamav": False,
        "worker": False,
    }

    # 1. PostgreSQL check (SELECT 1 with timeout)
    try:
        async with asyncio.timeout(2.0):
            async with async_engine.connect() as conn:
                await conn.execute(sa.text("SELECT 1"))
        checks["postgres"] = True
    except Exception as e:
        logger.error(
            "Readiness probe PostgreSQL check failed: %s",
            type(e).__name__,
            extra={"context": {"dependency": "postgres", "error": type(e).__name__}},
        )

    # 2. Redis check (ping with timeout)
    try:
        async with asyncio.timeout(2.0):
            r = get_redis()
            checks["redis"] = await r.ping()
    except Exception as e:
        logger.error(
            "Readiness probe Redis check failed: %s",
            type(e).__name__,
            extra={"context": {"dependency": "redis", "error": type(e).__name__}},
        )

    # 3. ClamAV check (ping with timeout)
    try:
        async with asyncio.timeout(2.0):
            checks["clamav"] = await clamav_service.ping()
    except Exception as e:
        logger.error(
            "Readiness probe ClamAV check failed: %s",
            type(e).__name__,
            extra={"context": {"dependency": "clamav", "error": type(e).__name__}},
        )

    # 4. Background reconciliation worker check
    try:
        checks["worker"] = reconciliation_worker_status.is_healthy()
    except Exception as e:
        logger.error(
            "Readiness probe worker check failed: %s",
            type(e).__name__,
            extra={"context": {"dependency": "worker", "error": type(e).__name__}},
        )

    # Update Prometheus dependency gauges
    for dep, is_up in checks.items():
        dependency_healthy.labels(dependency=dep).set(1 if is_up else 0)

    # Determine readiness
    all_ready = all(checks.values())
    if not all_ready:
        failed = [dep for dep, ok in checks.items() if not ok]
        logger.error("Readiness probe failed. Components unready: %s", failed)
        return Response(
            content='{"status":"not_ready"}',
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )

    return {"status": "ready"}


@router.get("/metrics", summary="Prometheus Metrics")
async def get_metrics(
    admin_user: Moderator = Depends(require_admin),
):
    """Scrape endpoint for Prometheus OpenMetrics telemetry.

    Secured via database-verified ADMIN authorization.
    """
    body, content_type = generate_metrics_response()
    return Response(content=body, media_type=content_type)
