import logging
import uuid
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.core.config import settings
from app.models.enums import ModeratorRole
from app.models.moderator import Moderator
from app.schemas.auth import TokenResponse

logger = logging.getLogger(__name__)



class AuthService:
    """Service layer for moderator authentication, token generation, and account lookup."""

    async def authenticate_moderator(
        self,
        db: AsyncSession,
        username: str,
        password: str,
    ) -> Optional[Moderator]:
        """Authenticate a moderator by canonical username and password.

        Flow:
        1. Normalize input username to lowercase trimmed form.
        2. Query database for matching moderator.
        3. If moderator does not exist, execute dummy Argon2id verification with DUMMY_ARGON2_HASH
           to maintain comparable response times and mitigate username-enumeration timing attacks.
        4. If moderator exists, verify password against stored Argon2id hash.
        5. Verify that account is active.
        6. Return authenticated Moderator or None.

        Never raises granular user existence or password errors to protect against
        enumeration attacks.
        """
        if not username or not password:
            return None

        try:
            canonical_username = security.normalize_username(username)
        except ValueError:
            return None

        stmt = sa.select(Moderator).where(Moderator.username == canonical_username)
        result = await db.execute(stmt)
        moderator = result.scalar_one_or_none()

        if moderator is None:
            # Perform dummy Argon2id password verification using process-level dummy hash
            # to equalize computational work and mitigate username-enumeration timing side channels.
            security.verify_password(password, security.DUMMY_ARGON2_HASH)
            return None

        # Verify password against stored Argon2id hash
        password_valid = security.verify_password(password, moderator.password_hash)
        if not password_valid:
            return None

        # Disabled accounts cannot authenticate
        if not moderator.is_active:
            logger.warning("Authentication attempted for inactive moderator: username=%s", canonical_username)
            return None

        return moderator

    async def get_moderator_by_id(
        self,
        db: AsyncSession,
        moderator_id: uuid.UUID,
    ) -> Optional[Moderator]:
        """Retrieve a moderator by primary key UUID."""
        stmt = sa.select(Moderator).where(Moderator.id == moderator_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def create_moderator(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        role: ModeratorRole = ModeratorRole.MODERATOR,
        is_active: bool = True,
    ) -> Moderator:
        """Create a new moderator with normalized username and Argon2id hashed password.

        Atomic database transaction.
        """
        canonical_username = security.normalize_username(username)
        pwd_hash = security.hash_password(password)

        moderator = Moderator(
            username=canonical_username,
            password_hash=pwd_hash,
            role=role,
            is_active=is_active,
        )
        db.add(moderator)
        await db.commit()
        await db.refresh(moderator)
        return moderator

    async def deactivate_moderator(
        self,
        db: AsyncSession,
        moderator_id: uuid.UUID,
    ) -> Optional[Moderator]:
        """Deactivate a moderator account without deleting historical records."""
        moderator = await self.get_moderator_by_id(db, moderator_id)
        if moderator is None:
            return None
        moderator.is_active = False
        await db.commit()
        await db.refresh(moderator)
        return moderator

    def issue_token(self, moderator: Moderator) -> TokenResponse:
        """Issue a signed JWT access token for an authenticated moderator.

        Database Moderator.role remains the authoritative source of truth.
        Role is not embedded in the token payload.
        """
        access_token = security.create_access_token(
            subject=str(moderator.id),
        )
        expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
        )




auth_service = AuthService()
