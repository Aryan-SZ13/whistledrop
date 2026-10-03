import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import time
from unittest.mock import AsyncMock, patch
import pytest
import pytest_asyncio
import redis.asyncio as aioredis
import redis.exceptions as redis_exceptions
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
import sqlalchemy as sa

from app.core.client_ip import canonicalize_ip, parse_trusted_cidrs, resolve_client_ip
from app.core.config import settings
from app.db.redis import get_redis
from app.models.enums import ModeratorRole, ReportCategory
from app.models.moderator import Moderator
from app.models.report import Report
from app.services.auth_service import auth_service
from app.services.rate_limiter import (
    RateLimitPolicy,
    RateLimitResult,
    RateLimitUnavailableError,
    RateLimiterService,
    rate_limiter,
)


# ==============================================================================
# 1. Redis / Limiter Core Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_limiter_first_request_allowed():
    """Verify first request to a fresh key is allowed."""
    policy = RateLimitPolicy(key_prefix="test_first", max_requests=3, window_seconds=60)
    res = await rate_limiter.check_rate_limit(policy, "192.168.1.100")
    assert res.allowed is True
    assert res.retry_after == 0


@pytest.mark.asyncio
async def test_limiter_requests_within_limit_allowed():
    """Verify multiple requests within configured limit are all allowed."""
    policy = RateLimitPolicy(key_prefix="test_multi", max_requests=3, window_seconds=60)
    ip = "192.168.1.101"
    for _ in range(3):
        res = await rate_limiter.check_rate_limit(policy, ip)
        assert res.allowed is True
        assert res.retry_after == 0


@pytest.mark.asyncio
async def test_limiter_limit_exceeded_rejected_with_retry_after():
    """Verify exceeding the rate limit rejects the request and returns Retry-After >= 1."""
    policy = RateLimitPolicy(key_prefix="test_burst", max_requests=2, window_seconds=30)
    ip = "192.168.1.102"
    # Consume quota
    res1 = await rate_limiter.check_rate_limit(policy, ip)
    assert res1.allowed is True
    res2 = await rate_limiter.check_rate_limit(policy, ip)
    assert res2.allowed is True

    # Exceed limit
    res3 = await rate_limiter.check_rate_limit(policy, ip)
    assert res3.allowed is False
    assert res3.retry_after >= 1
    assert res3.retry_after <= 30


@pytest.mark.asyncio
async def test_limiter_rejected_requests_do_not_consume_quota():
    """Verify rejected requests are not inserted and do not artificially extend the window."""
    policy = RateLimitPolicy(key_prefix="test_no_consume", max_requests=2, window_seconds=10)
    ip = "192.168.1.103"
    await rate_limiter.check_rate_limit(policy, ip)
    await rate_limiter.check_rate_limit(policy, ip)

    # Hammer the limiter with 10 rejected requests
    for _ in range(10):
        res = await rate_limiter.check_rate_limit(policy, ip)
        assert res.allowed is False

    # Check the actual cardinality in Redis
    r = get_redis()
    bucket = rate_limiter.derive_client_bucket(ip)
    key = rate_limiter.build_key(policy.key_prefix, bucket)
    cardinality = await r.zcard(key)
    assert cardinality == 2


@pytest.mark.asyncio
async def test_limiter_window_expiry_restores_quota():
    """Verify quota is restored after the window elapses."""
    policy = RateLimitPolicy(key_prefix="test_expiry", max_requests=1, window_seconds=1)
    ip = "192.168.1.104"
    res1 = await rate_limiter.check_rate_limit(policy, ip)
    assert res1.allowed is True

    # Immediate next request rejected
    res2 = await rate_limiter.check_rate_limit(policy, ip)
    assert res2.allowed is False

    # Wait for the short window to elapse
    await asyncio.sleep(1.2)

    # Request allowed again
    res3 = await rate_limiter.check_rate_limit(policy, ip)
    assert res3.allowed is True


@pytest.mark.asyncio
async def test_limiter_independent_policies_isolated():
    """Verify different endpoint policies use separate counters and don't interfere."""
    policy_a = RateLimitPolicy(key_prefix="endpoint_a", max_requests=1, window_seconds=60)
    policy_b = RateLimitPolicy(key_prefix="endpoint_b", max_requests=1, window_seconds=60)
    ip = "192.168.1.105"

    res_a1 = await rate_limiter.check_rate_limit(policy_a, ip)
    assert res_a1.allowed is True

    # Exhausted policy_a
    res_a2 = await rate_limiter.check_rate_limit(policy_a, ip)
    assert res_a2.allowed is False

    # policy_b must still be allowed for the same IP
    res_b1 = await rate_limiter.check_rate_limit(policy_b, ip)
    assert res_b1.allowed is True


@pytest.mark.asyncio
async def test_limiter_policy_versioned_key_format():
    """Verify Redis keys use policy-versioned format rl:v1:<prefix>:<bucket>."""
    policy = RateLimitPolicy(key_prefix="submit", max_requests=5, window_seconds=60)
    ip = "203.0.113.42"
    await rate_limiter.check_rate_limit(policy, ip)

    r = get_redis()
    keys = await r.keys("rl:v1:submit:*")
    assert len(keys) == 1
    key_str = keys[0].decode("utf-8")
    assert key_str.startswith("rl:v1:submit:")

    bucket = key_str.split(":")[-1]
    # Bucket must be full 64-hexadecimal character HMAC-SHA256 digest
    assert len(bucket) == 64
    assert all(c in "0123456789abcdef" for c in bucket)
    expected_digest = hmac.new(
        settings.RATE_LIMIT_KEY_SECRET.encode("utf-8"),
        ip.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert bucket == expected_digest
    # Plaintext IP must NEVER be in key
    assert ip not in key_str


@pytest.mark.asyncio
async def test_limiter_atomic_concurrency_protection():
    """Verify concurrent requests cannot bypass the configured rate limit."""
    policy = RateLimitPolicy(key_prefix="test_concurrent", max_requests=5, window_seconds=60)
    ip = "198.51.100.99"

    # Launch 20 concurrent requests
    tasks = [rate_limiter.check_rate_limit(policy, ip) for _ in range(20)]
    results = await asyncio.gather(*tasks)

    allowed_count = sum(1 for r in results if r.allowed)
    rejected_count = sum(1 for r in results if not r.allowed)

    assert allowed_count == 5
    assert rejected_count == 15


# ==============================================================================
# 2. Submission Endpoint Integration Tests
# ==============================================================================

def test_submission_rate_limiting(client: TestClient):
    """Verify POST /api/v1/reports enforces submission rate limit."""
    payload = {
        "category": "CORRUPTION",
        "description": "Evidence of procurement malfeasance in city hall contracts.",
    }

    # settings.SUBMISSION_RATE_LIMIT is 5
    for _ in range(settings.SUBMISSION_RATE_LIMIT):
        res = client.post("/api/v1/reports", json=payload)
        assert res.status_code == 201

    # 6th request must be rejected with 429
    res_exceeded = client.post("/api/v1/reports", json=payload)
    assert res_exceeded.status_code == 429
    assert res_exceeded.json() == {"detail": "Too many requests"}
    assert "retry-after" in res_exceeded.headers
    assert int(res_exceeded.headers["retry-after"]) >= 1


def test_submission_under_limit_succeeds(client: TestClient):
    """Verify a valid submission under the limit functions normally."""
    payload = {
        "category": "SECURITY",
        "description": "Unauthorized administrative credential sharing on shared drive.",
    }
    res = client.post("/api/v1/reports", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "case_code" in data
    assert data["status"] == "SUBMITTED"


# ==============================================================================
# 3. Lookup Endpoint Integration Tests (Multi-Policy Protection)
# ==============================================================================

def test_lookup_rate_limiting(client: TestClient):
    """Verify GET /api/v1/reports/{case_code} enforces lookup rate limit."""
    # Create a real report
    create_res = client.post(
        "/api/v1/reports",
        json={"category": "OTHER", "description": "Test report for lookup limit verification."},
    )
    assert create_res.status_code == 201
    case_code = create_res.json()["case_code"]

    # settings.LOOKUP_RATE_LIMIT is 10
    for _ in range(settings.LOOKUP_RATE_LIMIT):
        res = client.get(f"/api/v1/reports/{case_code}")
        assert res.status_code == 200

    # 11th request must receive 429
    res_exceeded = client.get(f"/api/v1/reports/{case_code}")
    assert res_exceeded.status_code == 429
    assert res_exceeded.json() == {"detail": "Too many requests"}
    assert "retry-after" in res_exceeded.headers
    assert int(res_exceeded.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_lookup_never_creates_case_code_derived_redis_keys(client: TestClient):
    """Verify probing with various case codes does NOT create keys named after case codes."""
    fake_codes = [
        "wdc_attacker_guess_number_000000000001",
        "wdc_attacker_guess_number_000000000002",
        "wdc_attacker_guess_number_000000000003",
    ]
    for code in fake_codes:
        res = client.get(f"/api/v1/reports/{code}")
        assert res.status_code == 404

    r = get_redis()
    all_keys = await r.keys("rl:*")
    key_strings = [k.decode("utf-8") for k in all_keys]

    # No case code, substring, or guess must appear in any Redis key
    for code in fake_codes:
        for k in key_strings:
            assert code not in k
            assert "guess" not in k

    # Keys must only be client-bucket and global keys
    assert any(k.startswith("rl:v1:lookup:") for k in key_strings)
    assert any(k == "rl:v1:lookup_global:all" for k in key_strings)


def test_lookup_valid_and_invalid_probes_share_same_counter(client: TestClient):
    """Verify valid and invalid probes share the exact same client rate limit budget."""
    create_res = client.post(
        "/api/v1/reports",
        json={"category": "HARASSMENT", "description": "Hostile workplace environment report."},
    )
    valid_code = create_res.json()["case_code"]
    invalid_code = "wdc_totally_invalid_case_code_guess_01"

    # Interleave 5 invalid and 5 valid lookups = 10 total (reaches limit)
    for _ in range(5):
        assert client.get(f"/api/v1/reports/{invalid_code}").status_code == 404
        assert client.get(f"/api/v1/reports/{valid_code}").status_code == 200

    # 11th probe (whether valid or invalid) is rate-limited with 429
    assert client.get(f"/api/v1/reports/{valid_code}").status_code == 429
    assert client.get(f"/api/v1/reports/{invalid_code}").status_code == 429


@pytest.mark.asyncio
async def test_lookup_global_safeguard_triggers_under_distributed_probing():
    """Verify global lookup limiter triggers when total system traffic exceeds global limit."""
    client_policy = RateLimitPolicy("lookup", max_requests=10, window_seconds=60)
    global_policy = RateLimitPolicy("lookup_global", max_requests=5, window_seconds=60)

    # 5 requests from 5 distinct simulated IP addresses
    for i in range(5):
        simulated_ip = f"10.0.0.{i+1}"
        res = await rate_limiter.check_multi_rate_limit(client_policy, global_policy, simulated_ip)
        assert res.allowed is True

    # 6th request from a brand new IP address must be rejected by global safeguard
    res_global_reject = await rate_limiter.check_multi_rate_limit(
        client_policy, global_policy, "10.0.0.99"
    )
    assert res_global_reject.allowed is False
    assert res_global_reject.retry_after >= 1


# ==============================================================================
# 4. Login Endpoint Integration Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_login_rate_limiting(client: TestClient, db_session: AsyncSession):
    """Verify POST /api/v1/auth/login enforces login rate limit."""
    # Create a real moderator
    await auth_service.create_moderator(
        db_session,
        username="rate_limited_mod",
        password="ValidPassword123!",
    )

    bad_payload = {"username": "rate_limited_mod", "password": "WrongPassword!"}

    # settings.LOGIN_RATE_LIMIT is 5
    for _ in range(settings.LOGIN_RATE_LIMIT):
        res = client.post("/api/v1/auth/login", json=bad_payload)
        assert res.status_code == 401

    # 6th attempt must be rejected with 429 (not 401)
    res_exceeded = client.post("/api/v1/auth/login", json=bad_payload)
    assert res_exceeded.status_code == 429
    assert res_exceeded.json() == {"detail": "Too many requests"}
    assert "retry-after" in res_exceeded.headers


@pytest.mark.asyncio
async def test_login_success_permitted_under_threshold(client: TestClient, db_session: AsyncSession):
    """Verify legitimate moderator can authenticate successfully when under threshold."""
    await auth_service.create_moderator(
        db_session,
        username="legit_mod_user",
        password="SuperSecretPassword!",
    )

    good_payload = {"username": "legit_mod_user", "password": "SuperSecretPassword!"}
    res = client.post("/api/v1/auth/login", json=good_payload)
    assert res.status_code == 200
    assert "access_token" in res.json()


# ==============================================================================
# 5. Privacy Boundary Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_privacy_no_identity_stored_in_postgres(client: TestClient, db_session: AsyncSession):
    """Verify no IP, User-Agent, or requester identity is stored in PostgreSQL tables."""
    # Submit report with distinct client header
    client.post(
        "/api/v1/reports",
        json={"category": "TECHNICAL", "description": "System database configuration audit."},
        headers={"User-Agent": "WhistleblowerBrowser/1.0", "X-Forwarded-For": "198.51.100.77"},
    )

    # Inspect Report table columns
    report_columns = [c.name for c in Report.__table__.columns]
    forbidden_terms = ["ip", "ip_address", "client_ip", "user_agent", "fingerprint", "requester"]
    for term in forbidden_terms:
        assert term not in report_columns

    # Check raw SQL query to ensure no leaks in report record
    res = await db_session.execute(sa.text("SELECT * FROM reports LIMIT 1"))
    row = res.mappings().first()
    assert row is not None
    row_text = str(dict(row))
    assert "198.51.100.77" not in row_text
    assert "WhistleblowerBrowser" not in row_text


@pytest.mark.asyncio
async def test_privacy_plaintext_case_code_absent_from_redis(client: TestClient):
    """Verify plaintext case codes never appear in Redis keys or values."""
    res = client.post(
        "/api/v1/reports",
        json={"category": "CORRUPTION", "description": "Procurement oversight finding."},
    )
    case_code = res.json()["case_code"]

    # Perform lookup
    client.get(f"/api/v1/reports/{case_code}")

    r = get_redis()
    keys = await r.keys("rl:*")
    for k in keys:
        k_str = k.decode("utf-8")
        assert case_code not in k_str
        # Inspect members
        members = await r.zrange(k, 0, -1)
        for m in members:
            assert case_code not in m.decode("utf-8")


# ==============================================================================
# 6. Redis Failure Mode (Fail-Closed) Tests
# ==============================================================================

def test_redis_outage_fails_closed_on_submission(client: TestClient):
    """Verify Redis outage returns 503 without leaking exceptions on report submission."""
    with patch.object(
        rate_limiter,
        "_execute_single_script",
        side_effect=RateLimitUnavailableError("Rate limiting service unavailable"),
    ):
        res = client.post(
            "/api/v1/reports",
            json={"category": "CORRUPTION", "description": "Urgent whistleblower submission."},
        )
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        # Verify no Redis exception details or connection strings leak
        assert "redis" not in res.text.lower()
        assert "connection" not in res.text.lower()


def test_redis_outage_fails_closed_on_lookup(client: TestClient):
    """Verify Redis outage returns 503 on case tracking."""
    with patch.object(
        rate_limiter,
        "_execute_multi_script",
        side_effect=RateLimitUnavailableError("Rate limiting service unavailable"),
    ):
        res = client.get("/api/v1/reports/wdc_some_sample_case_code_12345")
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()


def test_redis_outage_fails_closed_on_login(client: TestClient):
    """Verify Redis outage returns 503 on moderator login."""
    with patch.object(
        rate_limiter,
        "_execute_single_script",
        side_effect=RateLimitUnavailableError("Rate limiting service unavailable"),
    ):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AnyPassword123!"},
        )
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()


# ==============================================================================
# 7. Client IP & Proxy Trust Boundary Tests
# ==============================================================================

def test_proxy_trust_default_ignores_forwarded_for():
    """Verify by default (TRUSTED_PROXY_COUNT=0, TRUSTED_PROXY_CIDRS=""), X-Forwarded-For is ignored."""
    class FakeRequest:
        client = type("Client", (), {"host": "198.51.100.25"})()
        headers = {"x-forwarded-for": "10.0.0.1, 10.0.0.2"}

    resolved = resolve_client_ip(FakeRequest())
    assert resolved == "198.51.100.25"


def test_proxy_trust_untrusted_peer_ignores_forwarded_for():
    """Verify socket peer outside TRUSTED_PROXY_CIDRS cannot spoof client address."""
    with patch.object(settings, "TRUSTED_PROXY_CIDRS", "10.0.0.0/8"):
        with patch.object(settings, "TRUSTED_PROXY_COUNT", 1):
            class FakeRequest:
                # Socket peer is NOT in 10.0.0.0/8
                client = type("Client", (), {"host": "198.51.100.50"})()
                headers = {"x-forwarded-for": "203.0.113.99, 10.0.0.1"}

            resolved = resolve_client_ip(FakeRequest())
            # Must fall back to socket peer, ignoring spoofed header
            assert resolved == "198.51.100.50"


def test_proxy_trust_trusted_peer_extracts_client_ip():
    """Verify trusted socket peer with TRUSTED_PROXY_COUNT extracts correct client IP."""
    with patch.object(settings, "TRUSTED_PROXY_CIDRS", "127.0.0.1/32,10.0.0.0/8"):
        with patch.object(settings, "TRUSTED_PROXY_COUNT", 1):
            class FakeRequest:
                # Socket peer is a trusted proxy
                client = type("Client", (), {"host": "10.0.0.1"})()
                # Client IP is 203.0.113.88, followed by 1 proxy hop
                headers = {"x-forwarded-for": "203.0.113.88, 10.0.0.2"}

            resolved = resolve_client_ip(FakeRequest())
            assert resolved == "203.0.113.88"


def test_ip_canonicalization():
    """Verify IPv4 and IPv6 addresses are canonicalized consistently."""
    # IPv4 normalization (leading zeros stripped)
    assert canonicalize_ip("010.000.001.001") == "10.0.1.1"
    assert canonicalize_ip("127.0.0.1") == "127.0.0.1"

    # IPv6 normalization (compressed representation)
    assert canonicalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert canonicalize_ip("::1") == "::1"


# ==============================================================================
# 8. Redis NoScript Recovery Fail-Closed Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_noscript_recovery_script_load_failure_direct_service():
    """Verify NoScriptError recovery fails closed if script_load raises RedisError."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = redis_exceptions.NoScriptError("NOSCRIPT No matching script")
    fake_redis.script_load.side_effect = redis_exceptions.ConnectionError("Redis connection lost")

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        # Reset cached SHAs to trigger recovery path
        rate_limiter._single_script_sha = "stale_sha"
        policy = RateLimitPolicy(key_prefix="test_noscript", max_requests=5, window_seconds=60)
        with pytest.raises(RateLimitUnavailableError) as exc_info:
            await rate_limiter.check_rate_limit(policy, "192.168.1.200")
        assert "Rate limiting service unavailable" in str(exc_info.value)


@pytest.mark.asyncio
async def test_noscript_recovery_second_evalsha_failure_direct_service():
    """Verify NoScriptError recovery fails closed if second evalsha raises RedisError."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = [
        redis_exceptions.NoScriptError("NOSCRIPT No matching script"),
        redis_exceptions.TimeoutError("Redis timeout on reload"),
    ]
    fake_redis.script_load.return_value = "new_valid_sha"

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        rate_limiter._single_script_sha = "stale_sha"
        policy = RateLimitPolicy(key_prefix="test_noscript", max_requests=5, window_seconds=60)
        with pytest.raises(RateLimitUnavailableError) as exc_info:
            await rate_limiter.check_rate_limit(policy, "192.168.1.201")
        assert "Rate limiting service unavailable" in str(exc_info.value)


def test_noscript_recovery_script_load_failure_fails_closed_single_policy(client: TestClient):
    """Verify endpoint returns HTTP 503 without error leakage when script_load fails during NoScript recovery."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = redis_exceptions.NoScriptError("NOSCRIPT")
    fake_redis.script_load.side_effect = redis_exceptions.ConnectionError("Redis connection dropped")

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        rate_limiter._single_script_sha = "stale_sha"
        res = client.post(
            "/api/v1/reports",
            json={"category": "CORRUPTION", "description": "Recovery path test description."},
        )
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()
        assert "connection" not in res.text.lower()


def test_noscript_recovery_second_evalsha_failure_fails_closed_single_policy(client: TestClient):
    """Verify endpoint returns HTTP 503 when second evalsha fails during NoScript recovery."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = [
        redis_exceptions.NoScriptError("NOSCRIPT"),
        redis_exceptions.TimeoutError("Timed out executing reloaded script"),
    ]
    fake_redis.script_load.return_value = "new_valid_sha"

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        rate_limiter._single_script_sha = "stale_sha"
        res = client.post(
            "/api/v1/reports",
            json={"category": "CORRUPTION", "description": "Recovery path test description."},
        )
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()
        assert "timed out" not in res.text.lower()


def test_noscript_recovery_script_load_failure_fails_closed_multi_policy(client: TestClient):
    """Verify lookup endpoint returns HTTP 503 when script_load fails during multi-policy NoScript recovery."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = redis_exceptions.NoScriptError("NOSCRIPT")
    fake_redis.script_load.side_effect = redis_exceptions.ConnectionError("Redis connection dropped")

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        rate_limiter._multi_script_sha = "stale_multi_sha"
        res = client.get("/api/v1/reports/wdc_sample_case_code_for_noscript_123")
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()
        assert "connection" not in res.text.lower()


def test_noscript_recovery_second_evalsha_failure_fails_closed_multi_policy(client: TestClient):
    """Verify lookup endpoint returns HTTP 503 when second evalsha fails during multi-policy NoScript recovery."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = [
        redis_exceptions.NoScriptError("NOSCRIPT"),
        redis_exceptions.TimeoutError("Timed out executing reloaded script"),
    ]
    fake_redis.script_load.return_value = "new_valid_multi_sha"

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        rate_limiter._multi_script_sha = "stale_multi_sha"
        res = client.get("/api/v1/reports/wdc_sample_case_code_for_noscript_123")
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()
        assert "timed out" not in res.text.lower()


def test_noscript_recovery_failure_fails_closed_on_login(client: TestClient):
    """Verify login endpoint returns HTTP 503 when Redis fails during NoScript recovery."""
    fake_redis = AsyncMock()
    fake_redis.evalsha.side_effect = redis_exceptions.NoScriptError("NOSCRIPT")
    fake_redis.script_load.side_effect = redis_exceptions.ConnectionError("Redis connection dropped")

    with patch("app.services.rate_limiter.get_redis", return_value=fake_redis):
        rate_limiter._single_script_sha = "stale_sha"
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "AnyPassword123!"},
        )
        assert res.status_code == 503
        assert res.json() == {"detail": "Rate limiting service unavailable"}
        assert "redis" not in res.text.lower()
        assert "connection" not in res.text.lower()

