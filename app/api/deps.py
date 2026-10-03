import logging
import uuid
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.enums import ModeratorRole
from app.models.moderator import Moderator
from app.services.auth_service import auth_service

logger = logging.getLogger(__name__)

# Security scheme for Bearer token extraction
security_scheme = HTTPBearer(auto_error=False)


async def get_current_moderator(
    auth_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> Moderator:
    """Validate JWT access token and return the authenticated moderator.

    Raises:
        HTTPException(401): If token is missing, expired, invalid, or user does not exist.
    """
    if auth_credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_credentials.credentials
    try:
        payload = decode_access_token(token)
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        moderator_id = uuid.UUID(str(sub))
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    moderator = await auth_service.get_moderator_by_id(db, moderator_id)
    if moderator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not moderator.is_active:
        logger.warning("Access attempted with valid token for inactive moderator: id=%s", moderator_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return moderator



async def require_moderator(
    current_moderator: Moderator = Depends(get_current_moderator),
) -> Moderator:
    """Authorization dependency requiring at least MODERATOR role (MODERATOR or ADMIN)."""
    if current_moderator.role not in (ModeratorRole.MODERATOR, ModeratorRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    return current_moderator


async def require_admin(
    current_moderator: Moderator = Depends(get_current_moderator),
) -> Moderator:
    """Authorization dependency requiring ADMIN role."""
    if current_moderator.role != ModeratorRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_moderator
