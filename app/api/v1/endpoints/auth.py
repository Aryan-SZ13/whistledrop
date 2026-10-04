import logging
from typing import Any, Dict, Optional
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_moderator, require_admin, require_moderator, security_scheme
from app.core.client_ip import resolve_client_ip
from app.core.config import settings
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.moderator import Moderator
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.mfa_session import (
    LogoutResponse,
    MfaChallengeRequest,
    MfaChallengeResponse,
    MfaSetupResponse,
    MfaSetupTokenRequest,
    MfaSetupTokenResponse,
    MfaVerifySetupRequest,
    MfaVerifySetupResponse,
    RevokeAllSessionsResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
)
from app.services.auth_service import auth_service
from app.services.mfa_service import mfa_service
from app.services.rate_limiter import (
    RateLimitPolicy,
    RateLimitUnavailableError,
    rate_limiter,
)
from app.services.session_service import session_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Moderator login",
    description=(
        "Authenticate moderator with canonical username and password. "
        "Returns short-lived JWT and refresh token, or MFA challenge ticket if MFA is enabled."
    ),
)
async def login(
    request: Request,
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate moderator and return access token or MFA challenge ticket."""
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="login",
            max_requests=settings.LOGIN_RATE_LIMIT,
            window_seconds=settings.LOGIN_RATE_WINDOW_SECONDS,
        )
        limit_result = await rate_limiter.check_rate_limit(policy, client_ip)
    except RateLimitUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service unavailable",
        )

    if not limit_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(limit_result.retry_after)},
        )

    moderator = await auth_service.authenticate_moderator(
        db,
        username=credentials.username,
        password=credentials.password,
    )
    if moderator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not moderator.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If MFA is enabled, issue challenge ticket and do NOT issue session yet
    if moderator.is_totp_enabled:
        challenge_ticket = await mfa_service.issue_challenge_ticket(moderator.id)
        logger.info(
            "AUDIT: Moderator password verified; MFA challenge required: moderator_id=%s",
            moderator.id,
        )
        return TokenResponse(
            access_token="",
            token_type="",
            expires_in=0,
            refresh_token=None,
            mfa_required=True,
            mfa_ticket=challenge_ticket,
        )

    # Single-factor session creation
    session, access_token, refresh_token = await session_service.create_session(
        db=db,
        moderator=moderator,
        user_agent=request.headers.get("user-agent"),
        auth_level="pwd",
    )
    await db.commit()

    logger.info(
        "AUDIT: Moderator authentication successful: moderator_id=%s, role=%s, session_id=%s",
        moderator.id,
        moderator.role.value,
        session.id,
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token,
        mfa_required=False,
        mfa_ticket=None,
    )


@router.post(
    "/mfa/setup-token",
    response_model=MfaSetupTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Re-authenticate and obtain MFA setup ticket",
)
async def get_mfa_setup_token(
    request: Request,
    body: MfaSetupTokenRequest,
    current_moderator: Moderator = Depends(require_moderator),
) -> MfaSetupTokenResponse:
    """Re-authenticates current account password and issues single-use setup ticket."""
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="mfa_setup_token",
            max_requests=5,
            window_seconds=300,
        )
        limit_result = await rate_limiter.check_rate_limit(policy, f"{current_moderator.id}:{client_ip}")
        if not limit_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many setup token requests. Please wait.",
            )
    except RateLimitUnavailableError:
        pass

    ticket = await mfa_service.issue_setup_ticket(current_moderator, body.password)
    return MfaSetupTokenResponse(setup_ticket=ticket, expires_in=settings.MFA_SETUP_TICKET_EXPIRE_SECONDS)


@router.post(
    "/mfa/setup",
    response_model=MfaSetupResponse,
    status_code=status.HTTP_200_OK,
    summary="Begin MFA enrollment using single-use setup ticket",
)
async def begin_mfa_setup(
    request: Request,
    ticket: Optional[str] = Query(default=None),
    x_mfa_setup_ticket: Optional[str] = Header(default=None, alias="X-MFA-Setup-Ticket"),
    current_moderator: Moderator = Depends(require_moderator),
) -> MfaSetupResponse:
    """Consumes single-use setup ticket and generates unconfirmed TOTP secret with otpauth URI."""
    setup_ticket = ticket or x_mfa_setup_ticket
    if not setup_ticket:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup ticket is required via query param or X-MFA-Setup-Ticket header",
        )

    is_valid = await mfa_service.verify_and_consume_setup_ticket(current_moderator.id, setup_ticket)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or already consumed MFA setup ticket",
        )

    setup_data = await mfa_service.begin_mfa_enrollment(current_moderator.id, current_moderator.username)
    return MfaSetupResponse(**setup_data)


@router.post(
    "/mfa/verify-setup",
    response_model=MfaVerifySetupResponse,
    status_code=status.HTTP_200_OK,
    summary="Finalize MFA enrollment",
)
async def verify_mfa_setup(
    body: MfaVerifySetupRequest,
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> MfaVerifySetupResponse:
    """Verifies initial 6-digit TOTP code and activates MFA on the account, returning recovery codes."""
    enrolled_at, backup_codes = await mfa_service.finalize_mfa_enrollment(db, current_moderator, body.code)
    return MfaVerifySetupResponse(
        status="mfa_enabled",
        enrolled_at=enrolled_at,
        backup_codes=backup_codes,
    )


@router.post(
    "/mfa/challenge",
    response_model=MfaChallengeResponse,
    status_code=status.HTTP_200_OK,
    summary="Fulfill MFA challenge during login",
)
async def fulfill_mfa_challenge(
    request: Request,
    body: MfaChallengeRequest,
    ticket: Optional[str] = Query(default=None),
    x_mfa_challenge_ticket: Optional[str] = Header(default=None, alias="X-MFA-Challenge-Ticket"),
    db: AsyncSession = Depends(get_db),
) -> MfaChallengeResponse:
    """Consumes MFA challenge ticket and validates TOTP or recovery code to issue authenticated session."""
    challenge_ticket = ticket or x_mfa_challenge_ticket
    if not challenge_ticket:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge ticket is required via query param or X-MFA-Challenge-Ticket header",
        )

    moderator_id = await mfa_service.consume_challenge_ticket(challenge_ticket)
    if not moderator_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or previously consumed MFA challenge ticket",
        )

    moderator = await auth_service.get_moderator_by_id(db, moderator_id)
    if not moderator or not moderator.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is invalid or inactive",
        )

    is_valid = await mfa_service.verify_totp_or_recovery_code(db, moderator, body.code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication code",
        )

    session, access_token, raw_refresh = await session_service.create_session(
        db=db,
        moderator=moderator,
        user_agent=request.headers.get("user-agent"),
        auth_level="mfa",
    )
    await db.commit()

    logger.info(
        "AUDIT: MFA challenge fulfilled: moderator_id=%s, session_id=%s",
        moderator.id,
        session.id,
    )
    return MfaChallengeResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate refresh token and issue new access token",
)
async def refresh_token(
    request: Request,
    body: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenRefreshResponse:
    """Rotates refresh token. Detecting replay of a consumed token revokes the entire family."""
    client_ip = resolve_client_ip(request)
    try:
        policy = RateLimitPolicy(
            key_prefix="refresh",
            max_requests=20,
            window_seconds=60,
        )
        limit_result = await rate_limiter.check_rate_limit(policy, client_ip)
        if not limit_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many refresh requests",
            )
    except RateLimitUnavailableError:
        pass

    session, access_token, new_refresh = await session_service.rotate_refresh_token(
        db=db,
        raw_refresh_token=body.refresh_token,
        user_agent=request.headers.get("user-agent"),
    )
    return TokenRefreshResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout current session",
)
async def logout(
    auth_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> LogoutResponse:
    """Revokes the current session and fast-path Redis token cache."""
    if auth_credentials:
        try:
            payload = decode_access_token(auth_credentials.credentials)
            sid = payload.get("sid")
            jti = payload.get("jti")
            if sid:
                await session_service.revoke_session(db, uuid.UUID(str(sid)), jti=jti)
        except Exception as e:
            logger.warning(f"Error during session logout extraction: {e}")

    return LogoutResponse(status="logged_out")


@router.post(
    "/sessions/revoke-all",
    response_model=RevokeAllSessionsResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke all active sessions for current moderator",
)
async def revoke_all_sessions(
    current_moderator: Moderator = Depends(require_moderator),
    db: AsyncSession = Depends(get_db),
) -> RevokeAllSessionsResponse:
    """Revokes all active sessions and increments token_version to invalidate all existing JWTs."""
    count = await session_service.revoke_all_for_moderator(db, current_moderator)
    logger.info(
        "AUDIT: All sessions revoked: moderator_id=%s, count=%s",
        current_moderator.id,
        count,
    )
    return RevokeAllSessionsResponse(revoked_sessions_count=count)
