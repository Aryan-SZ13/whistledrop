from collections import OrderedDict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import logging
import secrets
import time
from typing import Optional, Tuple
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.encryption import CaseEncryptionKey

logger = logging.getLogger(__name__)


class DecryptionContext(str, Enum):
    """Context governing authorization to decrypt encrypted payloads."""
    ANONYMOUS_PUBLIC_UPDATE = "ANONYMOUS_PUBLIC_UPDATE"
    MODERATOR_CASE_READ = "MODERATOR_CASE_READ"
    MODERATOR_MESSAGE_READ = "MODERATOR_MESSAGE_READ"
    EXPORT = "EXPORT"


class PayloadEncryptionService:
    """Service providing Application-Level Envelope Encryption (ALEE) for textual case payloads."""

    def __init__(self) -> None:
        # Process-local LRU cache: (report_id) -> (dek_bytes, expiry_timestamp)
        self._local_dek_cache: OrderedDict[uuid.UUID, Tuple[bytes, float]] = OrderedDict()
        self._cache_capacity: int = 500
        self._cache_ttl_seconds: float = 300.0

    def _get_kek_for_version(self, version: int) -> bytes:
        keyring = settings.PAYLOAD_KEK_KEYRING
        if isinstance(keyring, str):
            import json
            keyring = json.loads(keyring)

        version_str = str(version)
        if version_str not in keyring:
            raise ValueError(f"Payload KEK version {version} not found in keyring.")
        raw_hex_or_bytes = keyring[version_str]
        try:
            return bytes.fromhex(raw_hex_or_bytes)
        except ValueError:
            return raw_hex_or_bytes.encode("utf-8")[:32].ljust(32, b"\x00")

    def get_active_kek(self) -> Tuple[int, bytes]:
        version = settings.PAYLOAD_KEK_ACTIVE_VERSION
        return version, self._get_kek_for_version(version)

    def compute_aad(
        self,
        report_id: uuid.UUID,
        object_type: str,
        object_id: uuid.UUID,
        field_name: str,
        key_version: int,
    ) -> bytes:
        """Computes SHA-256 Additional Authenticated Data binding ciphertext to its security context."""
        canonical_str = f"v1:{report_id}:{object_type}:{object_id}:{field_name}:{key_version}"
        return hashlib.sha256(canonical_str.encode("utf-8")).digest()

    def _evict_cache_entry(self, report_id: uuid.UUID) -> None:
        self._local_dek_cache.pop(report_id, None)

    def _get_cached_dek(self, report_id: uuid.UUID) -> Optional[bytes]:
        entry = self._local_dek_cache.get(report_id)
        if entry is None:
            return None
        dek, expiry = entry
        if time.time() > expiry:
            self._local_dek_cache.pop(report_id, None)
            return None
        self._local_dek_cache.move_to_end(report_id)
        return dek

    def _put_cached_dek(self, report_id: uuid.UUID, dek: bytes) -> None:
        if len(self._local_dek_cache) >= self._cache_capacity:
            self._local_dek_cache.popitem(last=False)
        self._local_dek_cache[report_id] = (dek, time.time() + self._cache_ttl_seconds)

    async def get_or_create_case_dek(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Tuple[bytes, int]:
        """Retrieves existing active DEK or creates and wraps a new one under active KEK."""
        cached = self._get_cached_dek(report_id)
        if cached is not None:
            # Query key version from DB
            stmt = sa.select(CaseEncryptionKey.key_version, CaseEncryptionKey.is_destroyed).where(
                CaseEncryptionKey.report_id == report_id
            )
            res = (await db.execute(stmt)).first()
            if res and not res[1]:
                return cached, res[0]

        stmt = (
            sa.select(CaseEncryptionKey)
            .where(CaseEncryptionKey.report_id == report_id)
            .with_for_update()
        )
        key_row = (await db.execute(stmt)).scalar_one_or_none()

        if key_row is not None:
            if key_row.is_destroyed:
                raise ValueError("Case encryption key has been destroyed.")
            kek = self._get_kek_for_version(key_row.key_version)
            aesgcm_kek = AESGCM(kek)
            dek = aesgcm_kek.decrypt(key_row.dek_iv, key_row.dek_encrypted + key_row.dek_tag, None)
            self._put_cached_dek(report_id, dek)
            return dek, key_row.key_version

        # Generate fresh DEK
        dek = secrets.token_bytes(32)
        active_version, active_kek = self.get_active_kek()
        iv = secrets.token_bytes(12)
        aesgcm_kek = AESGCM(active_kek)
        ciphertext_and_tag = aesgcm_kek.encrypt(iv, dek, None)
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        new_key = CaseEncryptionKey(
            report_id=report_id,
            dek_encrypted=ciphertext,
            dek_iv=iv,
            dek_tag=tag,
            key_version=active_version,
            is_destroyed=False,
        )
        db.add(new_key)
        self._put_cached_dek(report_id, dek)
        return dek, active_version

    async def unwrap_case_dek(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> Tuple[bytes, int]:
        """Unwraps existing case DEK, verifying it has not been destroyed."""
        cached = self._get_cached_dek(report_id)
        if cached is not None:
            stmt = sa.select(CaseEncryptionKey.key_version, CaseEncryptionKey.is_destroyed).where(
                CaseEncryptionKey.report_id == report_id
            )
            res = (await db.execute(stmt)).first()
            if res and not res[1]:
                return cached, res[0]

        stmt = sa.select(CaseEncryptionKey).where(CaseEncryptionKey.report_id == report_id)
        key_row = (await db.execute(stmt)).scalar_one_or_none()
        if key_row is None:
            raise ValueError("Case encryption key not found.")
        if key_row.is_destroyed:
            raise ValueError("Case encryption key has been destroyed.")

        kek = self._get_kek_for_version(key_row.key_version)
        aesgcm_kek = AESGCM(kek)
        dek = aesgcm_kek.decrypt(key_row.dek_iv, key_row.dek_encrypted + key_row.dek_tag, None)
        self._put_cached_dek(report_id, dek)
        return dek, key_row.key_version

    async def encrypt_payload(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        object_type: str,
        object_id: uuid.UUID,
        field_name: str,
        plaintext: str,
    ) -> Tuple[bytes, bytes, bytes, int]:
        """Encrypts plaintext string with AES-256-GCM using case DEK and authenticated AAD."""
        dek, key_version = await self.get_or_create_case_dek(db, report_id)
        iv = secrets.token_bytes(12)
        aad = self.compute_aad(report_id, object_type, object_id, field_name, key_version)
        aesgcm = AESGCM(dek)
        ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        return ciphertext, iv, tag, key_version

    async def decrypt_payload(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        object_type: str,
        object_id: uuid.UUID,
        field_name: str,
        ciphertext: bytes,
        iv: bytes,
        tag: bytes,
        aad_version: int,
        context: DecryptionContext,
    ) -> str:
        """
        Decrypts payload evaluating authoritative sealed state AND decryption context.
        Raises 403 Forbidden in sealed state unless context is ANONYMOUS_PUBLIC_UPDATE.
        """
        # Authoritative check for sealed state
        from app.services.canary_service import canary_service
        is_sealed = await canary_service.is_system_sealed(db)
        if is_sealed:
            if context != DecryptionContext.ANONYMOUS_PUBLIC_UPDATE:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="System is in sealed mode; plaintext decryption disabled",
                )

        dek, _ = await self.unwrap_case_dek(db, report_id)
        aad = self.compute_aad(report_id, object_type, object_id, field_name, aad_version)
        aesgcm = AESGCM(dek)
        try:
            decrypted_bytes = aesgcm.decrypt(iv, ciphertext + tag, aad)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag:
            logger.error(
                f"InvalidTag during payload decryption: report_id={report_id}, "
                f"object_type={object_type}, object_id={object_id}, field={field_name}"
            )
            raise ValueError("Payload integrity violation: authentication tag mismatch or corrupted ciphertext.")

    async def destroy_case_dek(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> None:
        """Transactionally zeroes out and marks destroyed the case DEK."""
        from app.services.canary_service import canary_service
        if await canary_service.is_system_sealed(db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="System is in sealed mode; key destruction and cryptographic erasure are disabled",
            )
        self._evict_cache_entry(report_id)
        stmt = (
            sa.select(CaseEncryptionKey)
            .where(CaseEncryptionKey.report_id == report_id)
            .with_for_update()
        )
        key_row = (await db.execute(stmt)).scalar_one_or_none()
        if key_row:
            now = datetime.now(timezone.utc)
            key_row.dek_encrypted = b"\x00" * 32
            key_row.dek_iv = b"\x00" * 12
            key_row.dek_tag = b"\x00" * 16
            key_row.is_destroyed = True
            key_row.destroyed_at = now

    async def rewrap_case_dek(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> int:
        """Unwraps DEK with historical KEK and re-wraps under active KEK."""
        from app.services.canary_service import canary_service
        if await canary_service.is_system_sealed(db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="System is in sealed mode; administrative key operations disabled",
            )

        stmt = (
            sa.select(CaseEncryptionKey)
            .where(CaseEncryptionKey.report_id == report_id)
            .with_for_update()
        )
        key_row = (await db.execute(stmt)).scalar_one_or_none()
        if not key_row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case key not found")
        if key_row.is_destroyed:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Case key has been destroyed")

        active_version, active_kek = self.get_active_kek()
        if key_row.key_version == active_version:
            return active_version

        old_kek = self._get_kek_for_version(key_row.key_version)
        aesgcm_old = AESGCM(old_kek)
        dek = aesgcm_old.decrypt(key_row.dek_iv, key_row.dek_encrypted + key_row.dek_tag, None)

        iv = secrets.token_bytes(12)
        aesgcm_new = AESGCM(active_kek)
        ciphertext_and_tag = aesgcm_new.encrypt(iv, dek, None)

        key_row.dek_encrypted = ciphertext_and_tag[:-16]
        key_row.dek_iv = iv
        key_row.dek_tag = ciphertext_and_tag[-16:]
        key_row.key_version = active_version

        self._evict_cache_entry(report_id)
        return active_version


payload_encryption_service = PayloadEncryptionService()
