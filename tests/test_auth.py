from datetime import timedelta, timezone, datetime
import logging
import uuid
import pytest
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

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
# Unit Tests: Core Security Functions
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
    """Verify username normalization strips whitespace and converts to lowercase."""
    assert normalize_username("Admin") == "admin"
    assert normalize_username("  Moderator_1  ") == "moderator_1"
    assert normalize_username("USER@EXAMPLE.COM") == "user@example.com"

    with pytest.raises(ValueError):
        normalize_username("")
    with pytest.raises(ValueError):
        normalize_username("   ")


def test_jwt_token_creation_and_decoding():
    """Verify short-lived JWT token creation, standard claims, and signature decoding."""
    subject_id = str(uuid.uuid4())
    role = ModeratorRole.MODERATOR.value

    token = create_access_token(subject=subject_id, role=role)
    decoded = decode_access_token(token)

    assert decoded["sub"] == subject_id
    assert decoded["role"] == role
    assert "iat" in decoded
    assert "exp" in decoded
    assert decoded["exp"] > decoded["iat"]


def test_jwt_token_expiration_rejection():
    """Verify expired JWT tokens raise ExpiredSignatureError upon decoding."""
    subject_id = str(uuid.uuid4())
    token = create_access_token(
        subject=subject_id,
        role=ModeratorRole.MODERATOR.value,
        expires_delta=timedelta(seconds=-10),
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_jwt_token_wrong_secret_rejection():
    """Verify tokens signed with CASE_CODE_SECRET are rejected by JWT_SECRET."""
    subject_id = str(uuid.uuid4())
    # Sign token with CASE_CODE_SECRET instead of JWT_SECRET
    payload = {
        "sub": subject_id,
        "role": ModeratorRole.MODERATOR.value,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
    }
    bogus_token = jwt.encode(payload, settings.CASE_CODE_SECRET, algorithm="HS256")

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(bogus_token)


def test_jwt_token_wrong_algorithm_rejection():
    """Verify tokens signed with an unauthorized algorithm (e.g. HS384) are rejected."""
    subject_id = str(uuid.uuid4())
    payload = {
        "sub": subject_id,
        "role": ModeratorRole.MODERATOR.value,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
    }
    # Sign token with HS384 while settings.JWT_ALGORITHM is HS256
    token_hs384 = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS384")

    with pytest.raises(jwt.InvalidAlgorithmError):
        decode_access_token(token_hs384)


# ==============================================================================
# Integration Tests: Login Endpoint (POST /api/v1/auth/login)
# ==============================================================================

@pytest.mark.asyncio
async def test_login_success(client, db_session: AsyncSession):
    """Verify successful login returns short-lived JWT with expected schema."""
    username = "alice_moderator"
    password = "SuperSecretPassword123!"

    # Create moderator account
    await auth_service.create_moderator(
        db_session,
        username=username,
        password=password,
        role=ModeratorRole.MODERATOR,
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

    # Verify no sensitive hash or plaintext password leaked in response
    assert "password" not in data
    assert "password_hash" not in data

    # Verify decoded token payload
    decoded = decode_access_token(data["access_token"])
    assert decoded["role"] == "MODERATOR"
    assert "password" not in decoded
    assert "password_hash" not in decoded


@pytest.mark.asyncio
async def test_login_username_case_and_whitespace_insensitivity(client, db_session: AsyncSession):
    """Verify username matching works across casing and leading/trailing whitespace."""
    await auth_service.create_moderator(
        db_session,
        username="CaseUser",
        password="MyPassword123!",
        role=ModeratorRole.MODERATOR,
    )

    # Login with mixed case and extra whitespace
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
    # Blank username
    res1 = client.post("/api/v1/auth/login", json={"username": "   ", "password": "foo"})
    assert res1.status_code == 422

    # Empty password
    res2 = client.post("/api/v1/auth/login", json={"username": "alice", "password": ""})
    assert res2.status_code == 422


@pytest.mark.asyncio
async def test_login_logs_safely(client, db_session: AsyncSession, caplog):
    """Verify login logging does NOT record passwords, hashes, or tokens."""
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

        # Check all logged text
        for record in caplog.records:
            assert password not in record.message
            assert token not in record.message
            assert "$argon2id$" not in record.message


# ==============================================================================
# Integration Tests: Auth Dependencies & RBAC
# ==============================================================================

@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(client):
    """Verify protected endpoints reject requests without Authorization header."""
    res1 = client.get("/api/v1/auth/test-moderator")
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Authentication credentials were not provided"

    res2 = client.get("/api/v1/auth/test-admin")
    assert res2.status_code == 401


@pytest.mark.asyncio
async def test_malformed_token_rejected(client):
    """Verify malformed bearer token returns 401."""
    response = client.get(
        "/api/v1/auth/test-moderator",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


@pytest.mark.asyncio
async def test_expired_token_rejected_at_endpoint(client, db_session: AsyncSession):
    """Verify expired token returns 401 Token has expired."""
    mod = await auth_service.create_moderator(
        db_session,
        username="mod_exp",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
    )
    expired_token = create_access_token(
        subject=str(mod.id),
        role=mod.role.value,
        expires_delta=timedelta(seconds=-1),
    )

    response = client.get(
        "/api/v1/auth/test-moderator",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has expired"


@pytest.mark.asyncio
async def test_token_with_deleted_user_rejected(client, db_session: AsyncSession):
    """Verify valid token for a nonexistent/deleted user ID returns 401."""
    random_user_id = str(uuid.uuid4())
    token = create_access_token(
        subject=random_user_id,
        role=ModeratorRole.MODERATOR.value,
    )

    response = client.get(
        "/api/v1/auth/test-moderator",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "User not found"


@pytest.mark.asyncio
async def test_moderator_role_authorization(client, db_session: AsyncSession):
    """Verify MODERATOR can access moderator endpoints but is forbidden from ADMIN endpoints."""
    mod = await auth_service.create_moderator(
        db_session,
        username="regular_mod",
        password="Password123!",
        role=ModeratorRole.MODERATOR,
    )
    token = create_access_token(subject=str(mod.id), role=mod.role.value)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Allowed on moderator endpoint
    res_mod = client.get("/api/v1/auth/test-moderator", headers=headers)
    assert res_mod.status_code == 200
    assert res_mod.json()["role"] == "MODERATOR"

    # 2. Forbidden on admin endpoint
    res_admin = client.get("/api/v1/auth/test-admin", headers=headers)
    assert res_admin.status_code == 403
    assert res_admin.json()["detail"] == "Admin privileges required"


@pytest.mark.asyncio
async def test_admin_role_authorization(client, db_session: AsyncSession):
    """Verify ADMIN can access both moderator and admin endpoints."""
    admin = await auth_service.create_moderator(
        db_session,
        username="super_admin",
        password="Password123!",
        role=ModeratorRole.ADMIN,
    )
    token = create_access_token(subject=str(admin.id), role=admin.role.value)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Allowed on moderator endpoint
    res_mod = client.get("/api/v1/auth/test-moderator", headers=headers)
    assert res_mod.status_code == 200
    assert res_mod.json()["role"] == "ADMIN"

    # 2. Allowed on admin endpoint
    res_admin = client.get("/api/v1/auth/test-admin", headers=headers)
    assert res_admin.status_code == 200
    assert res_admin.json()["role"] == "ADMIN"


@pytest.mark.asyncio
async def test_token_missing_claims_rejected(client):
    """Verify tokens missing required claims (such as 'sub' or 'role') are rejected."""
    # Token missing 'sub'
    payload_no_sub = {
        "role": ModeratorRole.MODERATOR.value,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
    }
    token_no_sub = jwt.encode(payload_no_sub, settings.JWT_SECRET, algorithm="HS256")
    res1 = client.get(
        "/api/v1/auth/test-moderator",
        headers={"Authorization": f"Bearer {token_no_sub}"},
    )
    assert res1.status_code == 401

    # Token with invalid non-UUID subject
    payload_bad_uuid = {
        "sub": "not-a-valid-uuid",
        "role": ModeratorRole.MODERATOR.value,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
    }
    token_bad_uuid = jwt.encode(payload_bad_uuid, settings.JWT_SECRET, algorithm="HS256")
    res2 = client.get(
        "/api/v1/auth/test-moderator",
        headers={"Authorization": f"Bearer {token_bad_uuid}"},
    )
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Could not validate credentials"
