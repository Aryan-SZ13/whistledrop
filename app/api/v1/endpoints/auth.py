import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_moderator
from app.core.client_ip import resolve_client_ip
from app.core.config import settings
from app.db.session import get_db
from app.models.moderator import Moderator
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import auth_service
from app.services.rate_limiter import (
    RateLimitPolicy,
    RateLimitUnavailableError,
    rate_limiter,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Moderator login",
    description=(
        "Authenticate moderator with canonical username and password. "
        "Returns a short-lived JWT access token for authorized operations."
    ),
)
async def login(
    request: Request,
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate moderator and return short-lived JWT access token."""
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
        # Uniform 401 response without disclosing whether username or password was incorrect
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Operational audit-oriented logging: records moderator UUID and role for accountability.
    # NEVER log passwords, password hashes, JWT tokens, case codes, or report data.
    logger.info(
        "AUDIT: Moderator authentication successful: moderator_id=%s, role=%s",
        moderator.id,
        moderator.role.value,
    )
    return auth_service.issue_token(moderator)

