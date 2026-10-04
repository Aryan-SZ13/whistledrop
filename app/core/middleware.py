import logging
import re
import time
import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.logging import current_request_id
from app.core.metrics import http_request_duration_seconds, http_requests_total

logger = logging.getLogger("app.middleware.access")

# Strict canonical UUIDv4 regex pattern
UUIDV4_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Enforce canonical UUIDv4 correlation IDs on incoming and outgoing HTTP requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        header_val = request.headers.get("X-Request-ID")
        # Validate strict canonical format and length
        if header_val and len(header_val) == 36 and UUIDV4_REGEX.match(header_val):
            req_id = header_val.lower()
        else:
            req_id = str(uuid.uuid4())

        token = current_request_id.set(req_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            current_request_id.reset(token)


def resolve_path_template(request: Request) -> str:
    """Resolve low-cardinality, sanitized route path template for metrics and logs."""
    template = None
    route = request.scope.get("route")
    if route and hasattr(route, "path"):
        template = route.path
    elif hasattr(request, "app") and getattr(request.app, "routes", None):
        from starlette.routing import Match
        for r in request.app.routes:
            match, _ = r.matches(request.scope)
            if match == Match.FULL and hasattr(r, "path"):
                template = r.path
                break

    if template is not None:
        if request.url.path.startswith(settings.API_V1_PREFIX) and not template.startswith(settings.API_V1_PREFIX):
            template = f"{settings.API_V1_PREFIX}{template}"
        return template

    # Fallback defense-in-depth sanitization:
    path = request.url.path
    # 1. Normalize case code parameter anywhere in path: wdc_... -> {case_code}
    path = re.sub(r"wdc_[A-Za-z0-9_-]+", "{case_code}", path)
    # 2. Normalize UUID parameters anywhere in path: UUID -> {id}
    path = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{id}", path)
    return path




class AllowlistAccessLoggingMiddleware(BaseHTTPMiddleware):
    """Structured allowlist-first access logging omitting client IP, raw headers, and bodies."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        req_id = current_request_id.get() or str(uuid.uuid4())

        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            path_template = resolve_path_template(request)
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            # Do NOT log client IP, IP hash, user agent, case codes, or authorization headers
            logger.info(
                "HTTP request completed",
                extra={
                    "context": {
                        "http_method": request.method,
                        "path_template": path_template,
                        "status_code": status_code,
                        "latency_ms": latency_ms,
                    }
                },
            )


class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """Record Prometheus request count and latency metrics with low-cardinality route templates."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()

        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            path_template = resolve_path_template(request)
            duration = time.perf_counter() - start_time
            # Increment request counter with normalized route template
            http_requests_total.labels(
                method=request.method,
                path=path_template,
                status=str(status_code),
            ).inc()

            # Record duration histogram
            http_request_duration_seconds.labels(
                method=request.method,
                path=path_template,
            ).observe(duration)
