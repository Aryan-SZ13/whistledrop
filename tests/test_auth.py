from datetime import datetime, timedelta, timezone
import logging
import uuid
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
import jwt
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_moderator, require_admin, require_moderator
from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    normalize_username,
    verify_password,
)
from app.models.enums import ModeratorRole
from app.models.moderator import Moderator
from app.services.auth_service import auth_service


# ==============================================================================
# Unit Tests: Security Core Functions & Password Hashing
# ==============================================================================

def test_password_hashing_and_verification():
    """Verify Argon2id password hashing produces secure hashes and verifies properly."""
    plain_password = "CorrectHorseBatteryStaple123!"
    hashed = hash_password(plain_password)

    # Hash should use Argon2id format
    assert hashed.startswith("$argon2id$")
    assert verify_password(plain_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(plain_password, "") is False
    assert verify_password(plain_password, "invalid_hash_format") is False


def test_username_normalization():
    """Verify username normalization strips whitespace and converts to lowercase.

    Username canonicalization prevents casing and surrounding-whitespace ambiguity.
    It is not a Unicode confusable/homograph defense.
    """
    assert normalize_username("Admin") == "admin"
    assert normalize_username("  Moderator_1  ") == "moderator_1"
    assert normalize_username("USER@EXAMPLE.COM") == "user@example.com"

    with pytest.raises(ValueError):
        normalize_username("")
    with pytest.raises(ValueError):
        normalize_username("   ")


# ==============================================================================
# Unit Tests: Context-Bound JWT & Claims Structure
# ==============================================================================

def test_jwt_contains_only_intended_claims():
    """Verify JWT strictly contains intended claims: sub, iat, exp, iss, aud.

    Specifically asserts role, password, report data, case codes, and PII are omitted.
    """
    subject_id = str(uuid.uuid4())
    token = create_access_token(subject=subject_id)
    decoded = decode_access_token(token)

    # Required claims strictly match expected specification
    expected_claims = {"sub", "iat", "exp", "iss", "aud"}
    assert set(decoded.keys()) == expected_claims

    assert decoded["sub"] == subject_id
    assert decoded["iss"] == settings.JWT_ISSUER
    assert decoded["aud"] == settings.JWT_AUDIENCE
    assert decoded["exp"] > decoded["iat"]

    # Prohibited claims verification
    assert "role" not in decoded
    assert "password" not in decoded
    assert "password_hash" not in decoded
    assert "case_code" not in decoded
    assert "report_id" not in decoded


def test_jwt_token_expiration_rejection():
    """Verify expired JWT tokens raise ExpiredSignatureError upon decoding."""
    subject_id = str(uuid.uuid4())
    token = create_access_token(
        subject=subject_id,
        expires_delta=timedelta(seconds=-10),
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_jwt_issuer_validation():
    """Verify valid issuer succeeds and invalid or missing issuer is rejected."""
    subject_id = str(uuid.uuid4())
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Valid issuer succeeds
    valid_token = create_access_token(subject=subject_id)
    decoded = decode_access_token(valid_token)
    assert decoded["iss"] == settings.JWT_ISSUER

    # 2. Invalid issuer rejected
    bad_iss_payload = {
        "sub": subject_id,
        "iat": now,
        "exp": now + 1800,
        "iss": "untrusted-issuer",
        "aud": settings.JWT_AUDIENCE,
    }
    bad_iss_token = jwt.encode(bad_iss_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.InvalidIssuerError):
        decode_access_token(bad_iss_token)

    # 3. Missing issuer rejected
    no_iss_payload = {
        "sub": subject_id,
        "iat": now,
        "exp": now + 1800,
        "aud": settings.JWT_AUDIENCE,
    }
    no_iss_token = jwt.encode(no_iss_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(no_iss_token)


def test_jwt_audience_validation():
    """Verify valid audience succeeds and invalid or missing audience is rejected."""
    subject_id = str(uuid.uuid4())
    now = int(datetime.now(timezone.utc).timestamp())

    # 1. Valid audience succeeds
    valid_token = create_access_token(subject=subject_id)
    decoded = decode_access_token(valid_token)
    assert decoded["aud"] == settings.JWT_AUDIENCE

    # 2. Invalid audience rejected
    bad_aud_payload = {
        "sub": subject_id,
        "iat": now,
        "exp": now + 1800,
        "iss": settings.JWT_ISSUER,
        "aud": "wrong-audience",
    }
    bad_aud_token = jwt.encode(bad_aud_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.InvalidAudienceError):
        decode_access_token(bad_aud_token)

    # 3. Missing audience rejected
    no_aud_payload = {
        "sub": subject_id,
        "iat": now,
        "exp": now + 1800,
        "iss": settings.JWT_ISSUER,
    }
    no_aud_token = jwt.encode(no_aud_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(no_aud_token)


def test_jwt_token_wrong_secret_rejection():
    """Verify tokens signed with CASE_CODE_SECRET are rejected by JWT_SECRET."""
    subject_id = str(uuid.uuid4())
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "sub": subject_id,
        "iat": now,
        "exp": now + 1800,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    bogus_token = jwt.encode(payload, settings.CASE_CODE_SECRET, algorithm="HS256")

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(bogus_token)


def test_jwt_token_wrong_algorithm_rejection():
    """Verify tokens signed with an unauthorized algorithm (e.g. HS384) are rejected."""
    subject_id = str(uuid.uuid4())
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "sub": subject_id,
        "iat": now,
        "exp": now + 1800,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    token_hs384 = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS384")

    with pytest.raises(jwt.InvalidAlgorithmError):
        decode_access_token(token_hs384)


# ==============================================================================
# Integration Tests: Login Endpoint (POST /api/v1/auth/login)
# ==============================================================================

@pytest.mark.asyncio
async def test_login_active_moderator_accepted(client, db_session: AsyncSession):
    """Verify active moderator can successfully log in and receive short-lived token."""
    username = "active_mod"
    password = "SuperSecretPassword123!"

    await auth_service.create_moderator(
        db_session,
        username=username,
        password=password,
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Verify absence of sensitive data
    assert "password" not in data
    assert "password_hash" not in data
    assert "role" not in data

    # Verify decoded token does NOT have role
    decoded = decode_access_token(data["access_token"])
    assert "role" not in decoded


@pytest.mark.asyncio
async def test_login_disabled_moderator_rejected(client, db_session: AsyncSession):
    """Verify inactive/disabled moderator cannot log in and receives uniform 401."""
    username = "disabled_mod"
    password = "SuperSecretPassword123!"

    await auth_service.create_moderator(
        db_session,
        username=username,
        password=password,
        role=ModeratorRole.MODERATOR,
        is_active=False,
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_login_username_case_and_whitespace_insensitivity(client, db_session: AsyncSession):
    """Verify canonical username matching handles casing and surrounding whitespace."""
    await auth_service.create_moderator(
        db_session,
        username="CaseUser",
        password="MyPassword123!",
        role=ModeratorRole.MODERATOR,
    )

    for variant in ["caseuser", "CASEUSER", "  CaseUser  ", "  CASEUSER  "]:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": variant, "password": "MyPassword123!"},
        )
        assert response.status_code == 200, f"Failed for variant: {variant}"


@pytest.mark.asyncio
async def test_login_invalid_password(client, db_session: AsyncSession):
    """Verify invalid password returns generic 401 Unauthorized without disclosing error reason."""
    await auth_service.create_moderator(
        db_session,
        username="valid_user",
        password="CorrectPassword123!",
        role=ModeratorRole.MODERATOR,
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "valid_user", "password": "WrongPassword123!"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_login_nonexistent_user(client):
    """Verify non-existent user returns identical generic 401 Unauthorized."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_user", "password": "AnyPassword123!"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


@pytest.mark.asyncio
async def test_login_missing_or_blank_fields(client):
    """Verify request validation rejects missing or blank username/password."""
    res1 = client.post("/api/v1/auth/login", json={"username": "   ", "password": "foo"})
    assert res1.status_code == 422

    res2 = client.post("/api/v1/auth/login", json={"username": "alice", "password": ""})
    assert res2.status_code == 422


@pytest.mark.asyncio
async def test_login_logs_safely(client, db_session: AsyncSession, caplog):
    """Verify login logging does NOT record passwords, hashes, tokens, or case codes."""
    username = "audit_user"
    password = "SensitivePassword999!"

    await auth_service.create_moderator(
        db_session,
        username=username,
        password=password,
        role=ModeratorRole.MODERATOR,
    )

    with caplog.at_level(logging.INFO):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        assert response.status_code == 200
        token = response.json()["access_token"]

        for record in caplog.records:
            assert password not in record.message
            assert token not in record.message
            assert "$argon2id$" not in record.message
            assert "wdc_" not in record.message


# ==============================================================================
# Integration Tests: Auth Lifecycle & RBAC Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_disabled_moderator_with_valid_jwt_rejected(db_session: AsyncSession):
    """Verify a valid JWT issued before deactivation cannot access protected dependencies."""
    mod = await auth_service.create_moderator(
        db_session,
        username="soon_disabled",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )
    # Issue valid token
    valid_token = create_access_token(subject=str(mod.id))

    # Deactivate account without deleting
    await auth_service.deactivate_moderator(db_session, mod.id)

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=valid_token)
    with pytest.raises(HTTPException) as exc:
        await get_current_moderator(auth_credentials=creds, db=db_session)

    assert exc.value.status_code == 401
    assert exc.value.detail == "Could not validate credentials"


@pytest.mark.asyncio
async def test_active_moderator_accepted_by_dependency(db_session: AsyncSession):
    """Verify active moderator with valid token is accepted by get_current_moderator."""
    mod = await auth_service.create_moderator(
        db_session,
        username="active_user_dep",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
        is_active=True,
    )
    token = create_access_token(subject=str(mod.id))
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    current_mod = await get_current_moderator(auth_credentials=creds, db=db_session)
    assert current_mod.id == mod.id
    assert current_mod.username == "active_user_dep"
    assert current_mod.role == ModeratorRole.MODERATOR


@pytest.mark.asyncio
async def test_jwt_cannot_escalate_db_role(db_session: AsyncSession):
    """Verify crafted JWT attempting to forge 'role': 'ADMIN' cannot escalate database role."""
    # User is only MODERATOR in the database
    mod = await auth_service.create_moderator(
        db_session,
        username="regular_mod_escalate",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
    )

    # Attacker crafts token claiming role="ADMIN"
    now = int(datetime.now(timezone.utc).timestamp())
    forged_payload = {
        "sub": str(mod.id),
        "role": "ADMIN",  # Attempted escalation in token
        "iat": now,
        "exp": now + 1800,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
    }
    forged_token = jwt.encode(forged_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=forged_token)

    # get_current_moderator reads role strictly from DB
    loaded_mod = await get_current_moderator(auth_credentials=creds, db=db_session)
    assert loaded_mod.role == ModeratorRole.MODERATOR

    # require_admin checks loaded_mod.role and rejects
    with pytest.raises(HTTPException) as exc:
        await require_admin(current_moderator=loaded_mod)

    assert exc.value.status_code == 403
    assert exc.value.detail == "Admin privileges required"


@pytest.mark.asyncio
async def test_rbac_moderator_and_admin_permissions(db_session: AsyncSession):
    """Verify require_moderator and require_admin role permissions."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_rbac",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
    )
    admin = await auth_service.create_moderator(
        db_session,
        username="admin_rbac",
        password="Password123!",
        role=ModeratorRole.ADMIN,
    )

    # 1. MODERATOR can access require_moderator
    res1 = await require_moderator(current_moderator=mod)
    assert res1.id == mod.id

    # 2. MODERATOR cannot access require_admin
    with pytest.raises(HTTPException) as exc1:
        await require_admin(current_moderator=mod)
    assert exc1.value.status_code == 403

    # 3. ADMIN can access require_moderator
    res2 = await require_moderator(current_moderator=admin)
    assert res2.id == admin.id

    # 4. ADMIN can access require_admin
    res3 = await require_admin(current_moderator=admin)
    assert res3.id == admin.id


@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(client):
    """Verify get_current_moderator rejects request when no credentials provided."""
    with pytest.raises(HTTPException) as exc:
        await get_current_moderator(auth_credentials=None)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Authentication credentials were not provided"


@pytest.mark.asyncio
async def test_deleted_user_token_rejected(db_session: AsyncSession):
    """Verify token for nonexistent or deleted user ID is rejected."""
    token = create_access_token(subject=str(uuid.uuid4()))
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(HTTPException) as exc:
        await get_current_moderator(auth_credentials=creds, db=db_session)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Could not validate credentials"


@pytest.mark.asyncio
async def test_reporter_data_never_appears_in_auth_objects_or_tokens(client, db_session: AsyncSession):
    """Verify reporter data, case codes, and digests never appear in moderator auth objects or tokens."""
    mod = await auth_service.create_moderator(
        db_session,
        username="clean_mod",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
    )
    token_resp = auth_service.issue_token(mod)
    token = token_resp.access_token

    # Check TokenResponse attributes
    assert hasattr(token_resp, "access_token")
    assert not hasattr(token_resp, "case_code")
    assert not hasattr(token_resp, "report_id")

    # Check decoded JWT payload
    payload = decode_access_token(token)
    prohibited_keys = {"case_code", "case_code_digest", "category", "description", "evidence_url", "report_id"}
    assert not set(payload.keys()).intersection(prohibited_keys)

    # Check Moderator model attributes
    mod_attrs = {c.name for c in Moderator.__table__.columns}
    assert not mod_attrs.intersection(prohibited_keys)


# ==============================================================================
# Integration Tests: Removed Development Test Endpoints
# ==============================================================================

def test_removed_test_moderator_endpoint_returns_404(client):
    """Verify temporary dev endpoint /api/v1/auth/test-moderator is removed and returns 404."""
    response = client.get("/api/v1/auth/test-moderator")
    assert response.status_code == 404


def test_removed_test_admin_endpoint_returns_404(client):
    """Verify temporary dev endpoint /api/v1/auth/test-admin is removed and returns 404."""
    response = client.get("/api/v1/auth/test-admin")
    assert response.status_code == 404
