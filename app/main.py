import asyncio
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.api import api_router
from app.api.v1.endpoints.health import get_metrics, health_check, readiness_check
from app.core.config import settings
from app.core.logging import setup_logging
from app.core.metrics import setup_multiprocess_dir
from app.core.middleware import (
    AllowlistAccessLoggingMiddleware,
    PrometheusMetricsMiddleware,
    RequestIDMiddleware,
)
from app.db.redis import close_redis, init_redis
from app.services.evidence_service import evidence_service

# Initialize structured logging early
setup_logging(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle resources (e.g., Redis connection pool and reconciliation)."""
    setup_multiprocess_dir(cleanup_stale=True)
    await init_redis()

    # Startup reconciliation sweep
    try:
        await evidence_service.run_reconciliation()
    except Exception as e:
        logger.error("Startup evidence reconciliation failed: %s", str(e))

    # Periodic background reconciliation worker
    async def reconciliation_worker():
        while True:
            try:
                await asyncio.sleep(settings.RECONCILIATION_INTERVAL_MINUTES * 60)
                await evidence_service.run_reconciliation()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Scheduled evidence reconciliation error: %s", str(e))

    reconciliation_task = asyncio.create_task(reconciliation_worker())

    yield

    # Clean shutdown
    reconciliation_task.cancel()
    try:
        await reconciliation_task
    except asyncio.CancelledError:
        pass
    except Exception:
        pass

    await close_redis()

    # Multiprocess worker metric cleanup
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        try:
            from prometheus_client import multiprocess
            multiprocess.mark_process_dead(os.getpid())
        except Exception:
            pass


# Initialize FastAPI application
# In production or when DEBUG is False, interactive documentation endpoints are disabled.
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=__version__,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# Execution flow: RequestIDMiddleware -> AllowlistAccessLoggingMiddleware -> PrometheusMetricsMiddleware -> Route handlers
# In FastAPI, add_middleware wraps bottom-up, so Prometheus is added first, then Logging, then RequestID (which runs outermost).
app.add_middleware(PrometheusMetricsMiddleware)
app.add_middleware(AllowlistAccessLoggingMiddleware)
app.add_middleware(RequestIDMiddleware)

# Configurable CORS Middleware
# Only register middleware if allowed origins are explicitly defined.
# allow_credentials=False is enforced because authentication uses Bearer JWT headers,
# eliminating the need for browser-managed credential exposure.
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept", "X-Case-Code", "X-Request-ID", "Idempotency-Key"],
    )

# Top-level operational endpoints for root probes / orchestrators
app.add_api_route(
    "/health",
    health_check,
    methods=["GET"],
    tags=["Health"],
    summary="Root Liveness Probe",
)
app.add_api_route(
    "/ready",
    readiness_check,
    methods=["GET"],
    tags=["Health"],
    summary="Root Readiness Probe",
)
app.add_api_route(
    "/metrics",
    get_metrics,
    methods=["GET"],
    tags=["Health"],
    summary="Root Prometheus Metrics Scrape",
)

# Include Versioned API Routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"], summary="Root status")
async def root():
    response = {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "health": "/health",
        "version": __version__,
    }
    if settings.DEBUG:
        response["docs"] = "/docs"
    return response
