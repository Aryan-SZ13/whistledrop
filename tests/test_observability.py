import json
import logging
import uuid
import pytest
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import StructuredJsonFormatter, current_request_id, setup_logging
from app.core.metrics import (
    dependency_healthy,
    evidence_scans_total,
    generate_metrics_response,
    http_request_duration_seconds,
    http_requests_total,
    moderator_actions_total,
    reconciliation_runs_total,
)
from app.models.enums import ModeratorRole
from app.services.auth_service import auth_service
from app.core.security import create_access_token


async def create_auth_headers(
    db_session: AsyncSession,
    role: ModeratorRole = ModeratorRole.MODERATOR,
    username: str = "obs_mod",
) -> dict:
    mod = await auth_service.create_moderator(
        db_session,
        username=username,
        password="TestPassword123!",
        role=role,
        is_active=True,
    )
    token = create_access_token(subject=str(mod.id))
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# Phase 9: Request ID & Middleware Tests
# ==============================================================================

def test_request_id_generated_when_missing(client):
    """Verify that requests without X-Request-ID receive a newly generated canonical UUIDv4."""
    response = client.get("/health")
    assert response.status_code == 200
    rid = response.headers.get("X-Request-ID")
    assert rid is not None
    # Validate canonical UUID format
    parsed = uuid.UUID(rid)
    assert parsed.version == 4


def test_valid_request_id_propagated(client):
    """Verify that incoming valid canonical UUIDv4 is preserved and propagated."""
    in_rid = str(uuid.uuid4())
    response = client.get("/health", headers={"X-Request-ID": in_rid})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == in_rid.lower()


def test_malformed_request_id_regenerated(client):
    """Verify that malformed, non-canonical, or malicious X-Request-ID headers are discarded."""
    malformed_headers = [
        "not-a-uuid",
        "12345",
        "../../etc/passwd",
        "<script>alert(1)</script>",
        "00000000-0000-0000-0000-000000000000",  # nil UUID (version != 4)
        str(uuid.uuid1()),  # UUIDv1 (version != 4)
        " " * 36,
    ]
    for bad_id in malformed_headers:
        response = client.get("/health", headers={"X-Request-ID": bad_id})
        assert response.status_code == 200
        out_rid = response.headers.get("X-Request-ID")
        assert out_rid != bad_id
        # Must be valid UUIDv4
        parsed = uuid.UUID(out_rid)
        assert parsed.version == 4


# ==============================================================================
# Phase 9: Privacy-First Zero-IP Logging Tests
# ==============================================================================

def test_structured_logging_formatter_omits_ip():
    """Verify StructuredJsonFormatter creates allowlisted JSON and contains zero IP fields."""
    formatter = StructuredJsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test event occurred",
        args=(),
        exc_info=None,
    )
    record.request_id = str(uuid.uuid4())
    record.context = {"http_method": "GET", "status_code": 200}

    formatted = formatter.format(record)
    data = json.loads(formatted)

    assert data["message"] == "Test event occurred"
    assert data["request_id"] == record.request_id
    assert data["context"]["http_method"] == "GET"
    assert "client_ip" not in data
    assert "client_ip_hash" not in data
    assert "client_ip" not in data["context"]


def test_regex_redaction_filter():
    """Verify defense-in-depth filter redacts case codes and bearer tokens."""
    from app.core.logging import RegexRedactionFilter

    rf = RegexRedactionFilter()
    rec = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=1,
        msg="Case wdc_AbCdEf1234567890abcdef and Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig leaked",
        args=(),
        exc_info=None,
    )
    rf.filter(rec)
    assert "wdc_AbCdEf1234567890abcdef" not in rec.msg
    assert "[REDACTED_CASE_CODE]" in rec.msg
    assert "Bearer [REDACTED_TOKEN]" in rec.msg


# ==============================================================================
# Phase 9: Health & Readiness Probes
# ==============================================================================

def test_liveness_probe_returns_200(client):
    """Verify /health and /api/v1/health liveness probes return 200 without dependencies."""
    for path in ("/health", "/api/v1/health"):
        res = client.get(path)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "WhistleDrop" in data["app"]


@pytest.mark.asyncio
async def test_readiness_probe_all_healthy(client):
    """Verify /ready and /api/v1/ready return 200 when all dependencies are ready."""
    for path in ("/ready", "/api/v1/ready"):
        res = client.get(path)
        assert res.status_code == 200
        assert res.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_readiness_probe_fails_closed_on_db_outage(client):
    """Verify /ready returns 503 with zero internal details when DB check fails."""
    with patch("app.api.v1.endpoints.health.async_engine") as mock_engine:
        mock_engine.connect.side_effect = Exception("Database connection refused: 5432")
        res = client.get("/ready")
        assert res.status_code == 503
        assert res.json() == {"status": "not_ready"}
        # Verify NO hostnames, ports, or error strings are in response
        assert "5432" not in res.text
        assert "refused" not in res.text
        assert "postgres" not in res.text


@pytest.mark.asyncio
async def test_readiness_probe_fails_closed_on_redis_outage(client):
    """Verify /ready returns 503 when Redis is unavailable."""
    with patch("app.api.v1.endpoints.health.get_redis") as mock_get_redis:
        mock_r = AsyncMock()
        mock_r.ping.side_effect = Exception("Redis connection timeout: 6379")
        mock_get_redis.return_value = mock_r

        res = client.get("/ready")
        assert res.status_code == 503
        assert res.json() == {"status": "not_ready"}
        assert "6379" not in res.text
        assert "redis" not in res.text


@pytest.mark.asyncio
async def test_readiness_probe_fails_closed_on_clamav_outage(client):
    """Verify /ready returns 503 when ClamAV daemon is unreachable."""
    with patch("app.api.v1.endpoints.health.clamav_service.ping") as mock_clam_ping:
        mock_clam_ping.return_value = False

        res = client.get("/ready")
        assert res.status_code == 503
        assert res.json() == {"status": "not_ready"}
        assert "clamav" not in res.text


@pytest.mark.asyncio
async def test_readiness_probe_fails_closed_on_stalled_worker(client):
    """Verify /ready returns 503 when background reconciliation worker is stalled or unhealthy."""
    with patch("app.api.v1.endpoints.health.reconciliation_worker_status.is_healthy") as mock_worker:
        mock_worker.return_value = False

        res = client.get("/ready")
        assert res.status_code == 503
        assert res.json() == {"status": "not_ready"}


# ==============================================================================
# Phase 9: Secure /metrics Authorization & Telemetry Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_metrics_endpoint_unauthenticated_returns_401(client):
    """Verify unauthenticated requests to /metrics and /api/v1/metrics receive 401."""
    for path in ("/metrics", "/api/v1/metrics"):
        res = client.get(path)
        assert res.status_code == 401
        assert res.json()["detail"] == "Authentication credentials were not provided"


@pytest.mark.asyncio
async def test_metrics_endpoint_standard_moderator_forbidden_403(client, db_session: AsyncSession):
    """Verify standard MODERATOR role cannot access /metrics (requires ADMIN)."""
    headers = await create_auth_headers(db_session, role=ModeratorRole.MODERATOR, username="metrics_mod")
    for path in ("/metrics", "/api/v1/metrics"):
        res = client.get(path, headers=headers)
        assert res.status_code == 403
        assert res.json()["detail"] == "Admin privileges required"


@pytest.mark.asyncio
async def test_metrics_endpoint_admin_authorized_returns_openmetrics(client, db_session: AsyncSession):
    """Verify ADMIN role receives Prometheus metrics response in text format."""
    headers = await create_auth_headers(db_session, role=ModeratorRole.ADMIN, username="metrics_admin")
    for path in ("/metrics", "/api/v1/metrics"):
        res = client.get(path, headers=headers)
        assert res.status_code == 200
        content = res.text
        assert "http_requests_total" in content
        assert "http_request_duration_seconds" in content
        assert "dependency_healthy" in content
        # Ensure zero sensitive tokens or plaintext case codes
        assert "wdc_" not in content
        assert "password" not in content
        assert "secret" not in content


# ==============================================================================
# Phase 9: Access Log Path Privacy & Multiprocess Lifecycle Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_access_log_path_template_privacy_with_real_case_code(client, caplog):
    """Verify access logs record path_template and NEVER record raw path with case codes."""
    real_case_code = "wdc_SecurityAuditRealCaseCode123456789"

    with caplog.at_level(logging.INFO, logger="app.middleware.access"):
        caplog.clear()
        res = client.get(f"/api/v1/reports/{real_case_code}")
        # Could be 404 (not in DB) or 200, but request enters middleware
        assert res.status_code in (200, 404)

        access_records = [r for r in caplog.records if r.name == "app.middleware.access"]
        assert len(access_records) >= 1

        target_record = access_records[-1]
        assert hasattr(target_record, "context")
        context = target_record.context

        # Must record normalized route template
        assert context.get("path_template") == "/api/v1/reports/{case_code}"
        # Must NEVER record raw path
        assert "path" not in context

        # Format as JSON string using our StructuredJsonFormatter
        formatter = StructuredJsonFormatter()
        json_output = formatter.format(target_record)
        parsed = json.loads(json_output)

        assert parsed["context"]["path_template"] == "/api/v1/reports/{case_code}"
        assert "path" not in parsed["context"]
        assert real_case_code not in json_output
        assert "wdc_" not in json_output


def test_multiprocess_pid_aware_cleanup_preserves_live_workers(tmp_path):
    """Verify multiprocess file cleanup retains files of live PIDs and removes dead PIDs."""
    import os
    from app.core.metrics import cleanup_stale_multiprocess_files

    dir_path = str(tmp_path)
    current_pid = os.getpid()
    # Extremely large dead PID that cannot exist
    dead_pid = 99999999

    live_file = tmp_path / f"counter_{current_pid}.db"
    live_file.write_text("live worker data")

    dead_file = tmp_path / f"counter_{dead_pid}.db"
    dead_file.write_text("dead worker data")

    # Execute cleanup
    cleanup_stale_multiprocess_files(dir_path)

    # Live file must STILL EXIST
    assert live_file.exists()
    # Dead file must HAVE BEEN REMOVED
    assert not dead_file.exists()


def test_multiprocess_metrics_aggregation_without_duplicate_registration(tmp_path, monkeypatch):
    """Verify multiprocess mode scrape creates fresh registry without duplicate errors."""
    monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
    data, content_type = generate_metrics_response()
    assert isinstance(data, bytes)
    assert "text/plain" in content_type
