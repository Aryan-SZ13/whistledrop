from datetime import datetime, timedelta, timezone
import logging
import secrets
from typing import Optional, Tuple
import uuid

from fastapi import HTTPException, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    create_access_token,
    hash_refresh_token,
)
from app.db.redis import get_redis
from app.models.moderator import Moderator
from app.models.moderator_session import ModeratorSession

logger = logging.getLogger(__name__)


class SessionService:
    def __init__(self) -> None:
        pass

    async def create_session(
        self,
        db: AsyncSession,
        moderator: Moderator,
        user_agent: Optional[str] = None,
        family_id: Optional[uuid.UUID] = None,
        auth_level: str = "pwd",
    ) -> Tuple[ModeratorSession, str, str]:
        """Creates a persistent session and returns (session, access_token, raw_refresh_token)."""
        session_family = family_id or uuid.uuid4()
        raw_refresh_token = f"rt_{secrets.token_urlsafe(32)}"
        token_hash = hash_refresh_token(raw_refresh_token)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        ua_hash = None
        if user_agent:
            import hashlib
            ua_hash = hashlib.sha256(user_agent.encode("utf-8")).hexdigest()

        session = ModeratorSession(
            moderator_id=moderator.id,
            session_family=session_family,
            refresh_token_hash=token_hash,
            user_agent_hash=ua_hash,
            expires_at=expires_at,
            is_revoked=False,
        )
        db.add(session)
        await db.flush()

        access_token = create_access_token(
            subject=str(moderator.id),
            sid=str(session.id),
            jti=str(uuid.uuid4()),
            token_version=moderator.token_version,
            auth_level=auth_level,
        )
        return session, access_token, raw_refresh_token

    async def rotate_refresh_token(
        self,
        db: AsyncSession,
        raw_refresh_token: str,
        user_agent: Optional[str] = None,
    ) -> Tuple[ModeratorSession, str, str]:
        """Atomically rotates a refresh token. Replay of a consumed token revokes the entire family."""
        token_hash = hash_refresh_token(raw_refresh_token)
        now = datetime.now(timezone.utc)

        # 1. Query session under exclusive row lock
        stmt = (
            sa.select(ModeratorSession)
            .where(ModeratorSession.refresh_token_hash == token_hash)
            .with_for_update()
        )
        session = (await db.execute(stmt)).scalar_one_or_none()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        # 2. Check if already revoked -> REPLAY THEFT DETECTED
        if session.is_revoked:
            logger.warning(
                f"Refresh token reuse detected for session {session.id}! "
                f"Revoking entire session family {session.session_family}."
            )
            # Revoke all sessions in the same family
            await db.execute(
                sa.update(ModeratorSession)
                .where(ModeratorSession.session_family == session.session_family)
                .values(is_revoked=True, revoked_at=now)
            )
            # Bump moderator token_version to invalidate all active JWTs
            mod_stmt = (
                sa.select(Moderator)
                .where(Moderator.id == session.moderator_id)
                .with_for_update()
            )
            moderator = (await db.execute(mod_stmt)).scalar_one()
            moderator.token_version += 1
            await db.commit()

            # Accelerate revocation in Redis
            try:
                redis = get_redis()
                await redis.set(f"revocation:session:{session.id}", "1", ex=86400)
                await redis.set(f"moderator:token_version:{moderator.id}", str(moderator.token_version), ex=86400)
            except Exception as e:
                logger.error(f"Redis cache sync error during family revocation: {e}")

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session revoked due to invalid token reuse",
            )

        # 3. Check expiration
        if session.expires_at <= now:
            session.is_revoked = True
            session.revoked_at = now
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired",
            )

        # 4. Load moderator to check active state and token_version
        mod_stmt = (
            sa.select(Moderator)
            .where(Moderator.id == session.moderator_id)
            .with_for_update()
        )
        moderator = (await db.execute(mod_stmt)).scalar_one()
        if not moderator.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Moderator account is inactive",
            )

        # 5. Create new session under same family
        new_session, new_access_token, new_raw_refresh = await self.create_session(
            db=db,
            moderator=moderator,
            user_agent=user_agent,
            family_id=session.session_family,
            auth_level="mfa" if moderator.is_totp_enabled else "pwd",
        )

        # 6. Mark old session as replaced and revoked
        session.is_revoked = True
        session.revoked_at = now
        session.replaced_by_session_id = new_session.id
        await db.commit()

        return new_session, new_access_token, new_raw_refresh

    async def revoke_session(
        self,
        db: AsyncSession,
        session_id: uuid.UUID,
        jti: Optional[str] = None,
    ) -> None:
        """Revokes a specific session in PostgreSQL and fast-path Redis."""
        now = datetime.now(timezone.utc)
        await db.execute(
            sa.update(ModeratorSession)
            .where(ModeratorSession.id == session_id)
            .values(is_revoked=True, revoked_at=now)
        )
        await db.commit()

        # Fast-path Redis revocation
        try:
            redis = get_redis()
            await redis.set(f"revocation:session:{session_id}", "1", ex=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
            if jti:
                await redis.set(f"revocation:jti:{jti}", "1", ex=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        except Exception as e:
            logger.error(f"Redis cache sync error during session revocation: {e}")

    async def revoke_all_for_moderator(
        self,
        db: AsyncSession,
        moderator: Moderator,
    ) -> int:
        """Revokes all active sessions for a moderator and increments token_version."""
        now = datetime.now(timezone.utc)
        res = await db.execute(
            sa.update(ModeratorSession)
            .where(
                ModeratorSession.moderator_id == moderator.id,
                ModeratorSession.is_revoked == False,
            )
            .values(is_revoked=True, revoked_at=now)
        )
        revoked_count = res.rowcount
        moderator.token_version += 1
        await db.commit()

        try:
            redis = get_redis()
            await redis.set(
                f"moderator:token_version:{moderator.id}",
                str(moderator.token_version),
                ex=86400 * 30,
            )
        except Exception as e:
            logger.error(f"Redis cache sync error during revoke-all: {e}")

        return revoked_count


session_service = SessionService()
