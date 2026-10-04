import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    generate_recovery_codes,
    generate_totp_secret,
    get_totp_code,
    hash_recovery_code,
    verify_password,
    verify_recovery_code,
    verify_totp_code,
)
from app.db.redis import get_redis
from app.models.moderator import Moderator

logger = logging.getLogger(__name__)


class MfaService:
    def __init__(self) -> None:
        pass

    def _get_kek(self) -> bytes:
        return hashlib.sha256(settings.MFA_KEK_SECRET.encode("utf-8")).digest()

    def encrypt_secret(self, secret: str) -> Tuple[bytes, bytes, bytes]:
        """Encrypt TOTP secret under master KEK using AES-256-GCM."""
        kek = self._get_kek()
        aesgcm = AESGCM(kek)
        iv = secrets.token_bytes(12)
        ciphertext_with_tag = aesgcm.encrypt(iv, secret.encode("utf-8"), None)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        return ciphertext, iv, tag

    def decrypt_secret(self, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
        """Decrypt TOTP secret using master KEK and AES-256-GCM."""
        kek = self._get_kek()
        aesgcm = AESGCM(kek)
        ciphertext_with_tag = ciphertext + tag
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        return plaintext.decode("utf-8")

    async def issue_setup_ticket(self, moderator: Moderator, plain_password: str) -> str:
        """Re-authenticates password and issues single-use setup ticket."""
        if not verify_password(plain_password, moderator.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect account password",
            )
        ticket = f"mfa_setup_tkt_{secrets.token_urlsafe(32)}"
        redis = get_redis()
        ticket_key = f"mfa:setup_ticket:{ticket}"
        payload = json.dumps({"moderator_id": str(moderator.id), "created_at": time.time()})
        try:
            await redis.set(ticket_key, payload, ex=settings.MFA_SETUP_TICKET_EXPIRE_SECONDS)
        except Exception as e:
            logger.error(f"Redis error issuing MFA setup ticket: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        return ticket

    async def verify_and_consume_setup_ticket(self, moderator_id: uuid.UUID, ticket: str) -> bool:
        """Consumes setup ticket atomically."""
        redis = get_redis()
        ticket_key = f"mfa:setup_ticket:{ticket}"
        try:
            # Atomic GETDEL
            data = await redis.execute_command("GETDEL", ticket_key)
        except Exception as e:
            logger.error(f"Redis error consuming setup ticket: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        if not data:
            return False
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        parsed = json.loads(data)
        return parsed.get("moderator_id") == str(moderator_id)

    async def begin_mfa_enrollment(self, moderator_id: uuid.UUID, username: str) -> Dict[str, Any]:
        """Generate a new unconfirmed TOTP secret and stage it in Redis."""
        secret = generate_totp_secret()
        redis = get_redis()
        key = f"mfa:pending:{moderator_id}"
        payload = json.dumps({"secret": secret, "created_at": time.time()})
        try:
            await redis.set(key, payload, ex=600)  # 10 minute setup window
        except Exception as e:
            logger.error(f"Redis error staging pending MFA secret: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        otpauth_uri = f"otpauth://totp/WhistleDrop:{username}?secret={secret}&issuer=WhistleDrop"
        return {
            "secret": secret,
            "otpauth_uri": otpauth_uri,
            "expires_in": 600,
        }

    async def finalize_mfa_enrollment(
        self,
        db: AsyncSession,
        moderator: Moderator,
        code: str,
    ) -> Tuple[datetime, List[str]]:
        """Validate initial TOTP code against pending secret, persist encrypted secret, and generate backup codes."""
        redis = get_redis()
        key = f"mfa:pending:{moderator.id}"
        try:
            data = await redis.get(key)
        except Exception as e:
            logger.error(f"Redis error fetching pending MFA secret: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        if not data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA enrollment session expired or not initialized. Request a new setup ticket.",
            )
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        parsed = json.loads(data)
        secret = parsed["secret"]

        if not verify_totp_code(secret, code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code. Ensure your authenticator app clock is synchronized.",
            )

        await redis.delete(key)

        ciphertext, iv, tag = self.encrypt_secret(secret)
        raw_backup_codes = generate_recovery_codes(10)
        now = datetime.now(timezone.utc)
        hashed_codes = [
            {
                "code_hash": hash_recovery_code(rc),
                "created_at": now.isoformat(),
                "used_at": None,
            }
            for rc in raw_backup_codes
        ]

        moderator.totp_secret_encrypted = ciphertext
        moderator.totp_secret_iv = iv
        moderator.totp_secret_tag = tag
        moderator.backup_codes = hashed_codes
        moderator.is_totp_enabled = True
        moderator.token_version += 1
        await db.commit()

        logger.info(f"AUDIT: MFA successfully enrolled for moderator {moderator.id}")
        return now, raw_backup_codes

    async def issue_challenge_ticket(self, moderator_id: uuid.UUID) -> str:
        """Issues short-lived MFA challenge ticket upon successful password check."""
        ticket = f"mfa_tkt_{secrets.token_urlsafe(32)}"
        redis = get_redis()
        key = f"mfa:challenge:{ticket}"
        payload = json.dumps({
            "moderator_id": str(moderator_id),
            "created_at": time.time(),
        })
        try:
            await redis.set(key, payload, ex=settings.MFA_CHALLENGE_TICKET_EXPIRE_SECONDS)
        except Exception as e:
            logger.error(f"Redis error issuing MFA challenge ticket: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        return ticket

    async def consume_challenge_ticket(self, ticket: str) -> Optional[uuid.UUID]:
        """Atomically consumes challenge ticket."""
        redis = get_redis()
        key = f"mfa:challenge:{ticket}"
        try:
            data = await redis.execute_command("GETDEL", key)
        except Exception as e:
            logger.error(f"Redis error consuming challenge ticket: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        if not data:
            return None
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        parsed = json.loads(data)
        return uuid.UUID(parsed["moderator_id"])

    async def check_totp_rate_limit_and_lockout(self, moderator: Moderator) -> None:
        """Enforces sliding-window rate limit and account lockout on failed TOTP."""
        now = datetime.now(timezone.utc)
        if moderator.totp_locked_until and moderator.totp_locked_until > now:
            remaining = int((moderator.totp_locked_until - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"MFA account locked due to excessive failures. Try again in {remaining} seconds.",
            )

    async def record_totp_failure(self, db: AsyncSession, moderator: Moderator) -> None:
        moderator.failed_totp_attempts += 1
        if moderator.failed_totp_attempts >= settings.MFA_MAX_FAILED_ATTEMPTS:
            moderator.totp_locked_until = datetime.now(timezone.utc) + timedelta(seconds=settings.MFA_LOCKOUT_SECONDS)
            moderator.failed_totp_attempts = 0
            logger.warning(f"Moderator {moderator.id} locked out of MFA for {settings.MFA_LOCKOUT_SECONDS}s")
        await db.commit()

    async def record_totp_success(self, db: AsyncSession, moderator: Moderator) -> None:
        if moderator.failed_totp_attempts > 0 or moderator.totp_locked_until is not None:
            moderator.failed_totp_attempts = 0
            moderator.totp_locked_until = None
            await db.commit()

    async def verify_totp_or_recovery_code(
        self,
        db: AsyncSession,
        moderator: Moderator,
        code: str,
    ) -> bool:
        """Verifies 6-digit TOTP code or single-use recovery code."""
        await self.check_totp_rate_limit_and_lockout(moderator)
        clean_code = code.strip()

        # 1. Check if it's a 6-digit TOTP
        if len(clean_code) == 6 and clean_code.isdigit():
            if not (moderator.totp_secret_encrypted and moderator.totp_secret_iv and moderator.totp_secret_tag):
                return False
            raw_secret = self.decrypt_secret(
                moderator.totp_secret_encrypted,
                moderator.totp_secret_iv,
                moderator.totp_secret_tag,
            )
            is_valid = verify_totp_code(raw_secret, clean_code)
            if is_valid:
                await self.record_totp_success(db, moderator)
                return True
            else:
                await self.record_totp_failure(db, moderator)
                return False

        # 2. Check if it's a recovery code
        if moderator.backup_codes:
            now_iso = datetime.now(timezone.utc).isoformat()
            codes_list = list(moderator.backup_codes)
            for item in codes_list:
                if item.get("used_at") is None:
                    code_hash = item.get("code_hash")
                    if code_hash and verify_recovery_code(clean_code, code_hash):
                        item["used_at"] = now_iso
                        from sqlalchemy.orm.attributes import flag_modified
                        moderator.backup_codes = [dict(c) for c in codes_list]
                        flag_modified(moderator, "backup_codes")
                        await self.record_totp_success(db, moderator)
                        await db.commit()
                        logger.info(f"Moderator {moderator.id} consumed a single-use recovery code.")
                        return True

        await self.record_totp_failure(db, moderator)
        return False


mfa_service = MfaService()
