"""Evidence Envelope Encryption and Cryptographic Shredder Service (Phase 14).

Provides AES-256-GCM envelope encryption for evidence attachments, transactional
cryptographic erasure (DEK destruction), and best-effort disk block sanitization.

CRITICAL PHYSICAL STORAGE NOTE:
Application-level multi-pass file overwrite, fdatasync(), and unlinking cannot guarantee
physical flash memory destruction on modern solid-state drives (SSDs) due to wear-leveling,
flash translation layers (FTL), over-provisioning spare blocks, filesystem journaling (ext4, XFS),
copy-on-write filesystems (APFS, Btrfs, ZFS), snapshots, and virtualized block devices.
Therefore, Cryptographic Erasure within the application key-management boundary (irreversible
zeroization of wrapped Data Encryption Keys in the database) serves as the primary and definitive
guarantee that residual ciphertext on non-volatile media becomes permanently undecipherable.
"""
from dataclasses import dataclass
import hashlib
import logging
import os
from pathlib import Path
import secrets
from typing import Optional
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.enums import EvidenceScanStatus, EvidenceShredStatus
from app.models.evidence import EvidenceAttachment

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EnvelopeEncryptedPayload:
    """Encrypted evidence attachment components."""
    ciphertext: bytes
    file_nonce: bytes
    file_tag: bytes
    wrapped_dek: bytes
    dek_nonce: bytes
    dek_tag: bytes
    kek_key_id: str
    encryption_version: int = 1


def get_master_kek_bytes(kek_secret: Optional[str] = None) -> bytes:
    """Derive 32-byte Master Key Encryption Key (KEK) from configured secret."""
    raw = kek_secret or settings.EVIDENCE_KEK_SECRET
    if not raw:
        raise ValueError("EVIDENCE_KEK_SECRET is not configured.")
    # Check if raw is a 64-char hex string representing 32 bytes
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    # Otherwise derive 32 bytes via SHA-256
    return hashlib.sha256(raw.encode("utf-8")).digest()


class ShredderService:
    """Manages envelope encryption, cryptographic erasure, and disk sanitization."""

    def encrypt_evidence_content(
        self,
        plaintext: bytes,
        kek_key_id: Optional[str] = None,
        custom_kek: Optional[bytes] = None,
    ) -> EnvelopeEncryptedPayload:
        """Encrypt evidence bytes with a unique per-attachment DEK and wrap the DEK under master KEK."""
        kek_id = kek_key_id or settings.EVIDENCE_KEK_KEY_ID
        master_kek = custom_kek or get_master_kek_bytes()

        # 1. Generate unique 256-bit DEK
        dek = secrets.token_bytes(32)

        # 2. Encrypt plaintext content with DEK using AES-256-GCM
        file_nonce = secrets.token_bytes(12)
        aesgcm_dek = AESGCM(dek)
        file_enc = aesgcm_dek.encrypt(file_nonce, plaintext, None)
        ciphertext = file_enc[:-16]
        file_tag = file_enc[-16:]

        # 3. Wrap DEK under master KEK using AES-256-GCM
        dek_nonce = secrets.token_bytes(12)
        aesgcm_kek = AESGCM(master_kek)
        dek_enc = aesgcm_kek.encrypt(dek_nonce, dek, None)
        wrapped_dek = dek_enc[:-16]
        dek_tag = dek_enc[-16:]

        return EnvelopeEncryptedPayload(
            ciphertext=ciphertext,
            file_nonce=file_nonce,
            file_tag=file_tag,
            wrapped_dek=wrapped_dek,
            dek_nonce=dek_nonce,
            dek_tag=dek_tag,
            kek_key_id=kek_id,
            encryption_version=1,
        )

    def decrypt_evidence_content(
        self,
        ciphertext: bytes,
        wrapped_dek: bytes,
        dek_nonce: bytes,
        dek_tag: bytes,
        file_nonce: bytes,
        file_tag: bytes,
        kek_key_id: Optional[str] = None,
        custom_kek: Optional[bytes] = None,
    ) -> bytes:
        """Unwrap DEK under master KEK and decrypt ciphertext with authentication tag verification."""
        master_kek = custom_kek or get_master_kek_bytes()

        # 1. Unwrap DEK
        aesgcm_kek = AESGCM(master_kek)
        dek_enc = wrapped_dek + dek_tag
        dek = aesgcm_kek.decrypt(dek_nonce, dek_enc, None)

        # 2. Decrypt file content
        aesgcm_dek = AESGCM(dek)
        file_enc = ciphertext + file_tag
        plaintext = aesgcm_dek.decrypt(file_nonce, file_enc, None)
        return plaintext

    def best_effort_shred_file(self, file_path: Path) -> bool:
        """Best-effort application-level file overwrite and unlink.

        Performs multi-pass sanitization (CSPRNG bytes + null bytes) followed by fdatasync()
        before invoking unlink. Note that physical flash storage wear-leveling and journaling
        prevent guarantees of physical media destruction; cryptographic erasure of the DEK
        in the database is the primary security boundary.
        """
        if not file_path.is_file():
            return True

        try:
            file_size = file_path.stat().st_size
            if file_size > 0:
                with open(file_path, "r+b") as f:
                    fd = f.fileno()
                    # Pass 1: Cryptographic random bytes
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    try:
                        os.fdatasync(fd)
                    except Exception:
                        pass

                    # Pass 2: Null bytes
                    f.seek(0)
                    f.write(b"\x00" * file_size)
                    f.flush()
                    try:
                        os.fdatasync(fd)
                    except Exception:
                        pass

            file_path.unlink()
            return True
        except Exception as e:
            logger.warning("Best-effort file shredding encountered an OS error on %s: %s", file_path, str(e))
            return False

    async def destroy_attachment_keys_in_db(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> int:
        """Transactionally destroy DEKs in database, completing cryptographic erasure for all report evidence.

        Must be called under the report row lock and committed in the same transaction
        as the audit tombstone entry.
        """
        stmt = (
            sa.update(EvidenceAttachment)
            .where(EvidenceAttachment.report_id == report_id)
            .values(
                wrapped_dek=None,
                dek_nonce=None,
                dek_tag=None,
                file_nonce=None,
                file_tag=None,
                shred_status=EvidenceShredStatus.KEY_DESTROYED.value,
            )
        )
        res = await db.execute(stmt)
        return res.rowcount

    async def migrate_existing_unencrypted_evidence(
        self,
        db: AsyncSession,
        approved_dir: Path,
    ) -> int:
        """Migrate legacy unencrypted attachments to AES-256-GCM envelope encryption."""
        stmt = sa.select(EvidenceAttachment).where(
            EvidenceAttachment.wrapped_dek.is_(None),
            EvidenceAttachment.scan_status == EvidenceScanStatus.CLEAN,
        )
        res = await db.execute(stmt)
        attachments = list(res.scalars().all())
        migrated_count = 0

        for att in attachments:
            file_path = approved_dir / f"{att.storage_key}.bin"
            if not file_path.is_file():
                continue

            raw_bytes = file_path.read_bytes()
            encrypted = self.encrypt_evidence_content(raw_bytes)

            # Write ciphertext
            file_path.write_bytes(encrypted.ciphertext)

            # Update DB attachment record
            att.wrapped_dek = encrypted.wrapped_dek
            att.dek_nonce = encrypted.dek_nonce
            att.dek_tag = encrypted.dek_tag
            att.file_nonce = encrypted.file_nonce
            att.file_tag = encrypted.file_tag
            att.kek_key_id = encrypted.kek_key_id
            att.encryption_version = 1
            att.shred_status = EvidenceShredStatus.ACTIVE.value
            migrated_count += 1

        if migrated_count > 0:
            await db.commit()

        return migrated_count


shredder_service = ShredderService()
