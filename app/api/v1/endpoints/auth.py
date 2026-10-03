import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_moderator
from app.db.session import get_db
from app.models.moderator import Moderator
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import auth_service

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
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate moderator and return short-lived JWT access token."""
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

