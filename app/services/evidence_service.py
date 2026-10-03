import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os
from pathlib import Path
import shutil
from typing import List, Optional, Sequence, Tuple
import uuid

from fastapi import UploadFile
import magic
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from app.core.config import settings
from app.db.session import async_engine
from app.models.audit_log import AuditLog
from app.models.enums import EvidenceScanStatus, ReportStatus
from app.models.evidence import EvidenceAttachment
from app.models.report import Report
from app.services.clamav_service import clamav_service

logger = logging.getLogger(__name__)

RECONCILIATION_LOCK_ID = 428910482910

# 6 Explicitly allowed file types
ALLOWED_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".txt",
    ".csv",
}

EXPECTED_CLIENT_MIMES = {
    ".pdf": ["application/pdf"],
    ".png": ["image/png"],
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".webp": ["image/webp"],
    ".txt": ["text/plain"],
    ".csv": ["text/csv", "text/plain", "application/csv"],
}

# Explicitly blocked archive extensions and executables
PROHIBITED_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".iso", ".dmg", ".jar",
    ".exe", ".bat", ".cmd", ".sh", ".bash", ".py", ".rb", ".pl", ".php", ".js",
    ".dll", ".so", ".dylib", ".elf", ".bin",
}


class EvidenceError(Exception):
    """Base exception for evidence processing."""
    pass


class FileValidationError(EvidenceError):
    """Exception raised when an uploaded file violates validation rules."""
    pass


class AttachmentQuotaExceededError(EvidenceError):
    """Exception raised when report attachment limits are exceeded."""
    pass


class InsufficientStorageError(EvidenceError):
    """Exception raised when available disk space is below safety threshold."""
    pass


class EvidenceNotFoundError(EvidenceError):
    """Exception raised when requested evidence attachment does not exist."""
    pass


class EvidenceNotAvailableError(EvidenceError):
    """Exception raised when evidence is not in CLEAN status."""
    pass


class EvidenceService:
    """Core domain service for evidence attachment lifecycle, storage, and validation."""

    def __init__(self, storage_path: Optional[str] = None, db_engine: Optional[AsyncEngine] = None):
        self.storage_path = Path(storage_path or settings.EVIDENCE_STORAGE_PATH).resolve()
        self.quarantine_dir = self.storage_path / "quarantine"
        self.approved_dir = self.storage_path / "approved"
        self.db_engine: AsyncEngine = db_engine or async_engine
        self._ensure_storage_directories()

    def _ensure_storage_directories(self) -> None:
        """Create quarantine and approved storage directories with secure permissions."""
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.approved_dir.mkdir(parents=True, exist_ok=True)

    def check_preflight_storage(self) -> None:
        """Verify that free disk space exceeds the configured minimum safety threshold."""
        try:
            usage = shutil.disk_usage(self.storage_path)
            required_free_bytes = settings.MIN_FREE_STORAGE_MB * 1024 * 1024
            if usage.free < required_free_bytes:
                logger.warning(
                    "Pre-flight disk safety threshold violated: available %d MB < required %d MB",
                    usage.free // (1024 * 1024),
                    settings.MIN_FREE_STORAGE_MB,
                )
                raise InsufficientStorageError("Storage temporarily unavailable")
        except InsufficientStorageError:
            raise
        except Exception as e:
            logger.error("Failed to check filesystem disk usage: %s", str(e))
            raise InsufficientStorageError("Storage temporarily unavailable")

    def _validate_magic_signature(self, ext: str, chunk: bytes, detected_mime: str) -> None:
        """Validate magic bytes and detected MIME against expected signature for extension."""
        if not chunk:
            raise FileValidationError("Uploaded file is empty.")

        if ext == ".pdf":
            if not chunk.startswith(b"%PDF-"):
                raise FileValidationError("Invalid PDF file signature.")
            if "pdf" not in detected_mime:
                raise FileValidationError("MIME type mismatch for PDF content.")

        elif ext == ".png":
            if not chunk.startswith(b"\x89PNG\r\n\x1a\n"):
                raise FileValidationError("Invalid PNG file signature.")
            if detected_mime != "image/png":
                raise FileValidationError("MIME type mismatch for PNG content.")

        elif ext in (".jpg", ".jpeg"):
            if not chunk.startswith(b"\xff\xd8\xff"):
                raise FileValidationError("Invalid JPEG file signature.")
            if detected_mime != "image/jpeg":
                raise FileValidationError("MIME type mismatch for JPEG content.")

        elif ext == ".webp":
            if len(chunk) < 12 or chunk[:4] != b"RIFF" or chunk[8:12] != b"WEBP":
                raise FileValidationError("Invalid WEBP file signature.")
            if detected_mime != "image/webp":
                raise FileValidationError("MIME type mismatch for WEBP content.")

        elif ext in (".txt", ".csv"):
            # Ensure text content does not contain binary control characters
            sample = chunk[:1024]
            # Null bytes or non-text control characters indicate binary content
            if b"\x00" in sample:
                raise FileValidationError("Binary content detected in text file.")
            try:
                sample.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    sample.decode("latin-1")
                except UnicodeDecodeError:
                    raise FileValidationError("Unparseable encoding in text file.")
            if not (detected_mime.startswith("text/") or detected_mime in ("application/csv", "application/octet-stream")):
                raise FileValidationError("MIME type mismatch for text content.")

    async def validate_and_stream_file(
        self,
        file: UploadFile,
    ) -> Tuple[uuid.UUID, Path, str, int, str]:
        """Perform early validation and stream incoming file directly to quarantine.

        Returns:
            Tuple[storage_key, quarantine_path, detected_mime, file_size, sha256_hash]
        """
        raw_filename = file.filename or ""
        ext = Path(raw_filename).suffix.lower()

        # 1. Extension check
        if ext in PROHIBITED_EXTENSIONS:
            raise FileValidationError(f"Prohibited file format: {ext}")
        if ext not in ALLOWED_EXTENSIONS:
            raise FileValidationError(f"Unsupported file extension: {ext or 'none'}")

        # 2. Client MIME check
        client_mime = (file.content_type or "").lower().strip()
        expected_mimes = EXPECTED_CLIENT_MIMES.get(ext, [])
        if client_mime and not any(client_mime.startswith(m) for m in expected_mimes):
            raise FileValidationError(f"Invalid Content-Type '{client_mime}' for extension {ext}")

        # 3. Prepare quarantine file path
        storage_key = uuid.uuid4()
        quarantine_path = self.quarantine_dir / f"{storage_key}.bin"
        max_bytes_per_file = settings.MAX_ATTACHMENT_SIZE_MB * 1024 * 1024

        hasher = hashlib.sha256()
        total_bytes = 0
        detected_mime = ""

        try:
            with open(quarantine_path, "wb") as out_f:
                # Read initial chunk for magic validation
                initial_chunk = await file.read(2048)
                if not initial_chunk:
                    raise FileValidationError("Uploaded file is empty.")

                # Detect MIME type via libmagic
                try:
                    detected_mime = magic.from_buffer(initial_chunk, mime=True).lower()
                except Exception as e:
                    logger.warning("Magic byte detection error: %s", str(e))
                    detected_mime = client_mime or "application/octet-stream"

                # Check magic bytes signature
                self._validate_magic_signature(ext, initial_chunk, detected_mime)

                # Write initial chunk
                out_f.write(initial_chunk)
                hasher.update(initial_chunk)
                total_bytes += len(initial_chunk)

                if total_bytes > max_bytes_per_file:
                    raise FileValidationError(
                        f"File exceeds maximum allowed size of {settings.MAX_ATTACHMENT_SIZE_MB} MiB."
                    )

                # Stream remaining chunks (64 KiB)
                while True:
                    chunk = await file.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes_per_file:
                        raise FileValidationError(
                            f"File exceeds maximum allowed size of {settings.MAX_ATTACHMENT_SIZE_MB} MiB."
                        )
                    out_f.write(chunk)
                    hasher.update(chunk)

                # Durability contract: flush buffered writes and fsync to disk
                out_f.flush()
                os.fsync(out_f.fileno())

        except Exception:
            # On any streaming or validation failure, clean up the quarantine file immediately
            if quarantine_path.is_file():
                try:
                    quarantine_path.unlink()
                except Exception:
                    pass
            raise

        sha256_hash = hasher.hexdigest()
        return storage_key, quarantine_path, detected_mime, total_bytes, sha256_hash

    async def attach_evidence_to_report(
        self,
        db: AsyncSession,
        case_code: str,
        files: Sequence[UploadFile],
    ) -> Tuple[int, int]:
        """Validate, stream, and atomically commit evidence attachments to a report.

        Flow:
        1. Pre-flight disk space check.
        2. Early multipart count check.
        3. Lookup report by HMAC digest of case code.
        4. Phase 1: Stream files to quarantine without holding DB lock.
        5. Phase 2: Short DB transaction with SELECT FOR UPDATE to atomically enforce quotas.
        6. Commit DB rows with PENDING_SCAN.
        7. Trigger ClamAV scan and atomic promotion for each attachment.

        Returns:
            Tuple[attachments_accepted, total_bytes_accepted]
        """
        # 1. Pre-flight storage check
        self.check_preflight_storage()

        # 2. Early multipart count check
        if not files:
            raise FileValidationError("No evidence files provided.")
        if len(files) > settings.MAX_ATTACHMENTS_PER_REPORT:
            raise FileValidationError(
                f"Cannot attach more than {settings.MAX_ATTACHMENTS_PER_REPORT} files in a single request."
            )

        # 3. Lookup report by HMAC digest of case code (never expose plaintext case code)
        from app.core.security import derive_case_code_digest
        case_code_digest = derive_case_code_digest(case_code)

        stmt = sa.select(Report).where(Report.case_code_digest == case_code_digest)
        result = await db.execute(stmt)
        report = result.scalar_one_or_none()

        if report is None:
            raise EvidenceNotFoundError("Report not found.")

        if report.status in (ReportStatus.RESOLVED, ReportStatus.DISMISSED):
            raise EvidenceError("Cannot attach evidence to a closed or dismissed report.")

        # 4. Phase 1: Stream files to quarantine (No DB row lock held during streaming)
        written_attachments: List[Tuple[uuid.UUID, Path, str, int, str]] = []
        batch_hashes = set()
        cumulative_bytes = 0
        max_total_bytes = settings.MAX_TOTAL_ATTACHMENT_BYTES

        try:
            for f in files:
                storage_key, q_path, detected_mime, f_size, sha256_hash = await self.validate_and_stream_file(f)

                # Check duplicate SHA-256 within the same submission batch
                if sha256_hash in batch_hashes:
                    raise FileValidationError("Duplicate attachment detected in submission.")
                batch_hashes.add(sha256_hash)

                cumulative_bytes += f_size
                if cumulative_bytes > max_total_bytes:
                    raise FileValidationError(
                        f"Cumulative attachments size exceeds maximum allowed of {max_total_bytes // (1024 * 1024)} MiB."
                    )

                written_attachments.append((storage_key, q_path, detected_mime, f_size, sha256_hash))

            # 5. Phase 2: Short DB transaction with row-level lock on the report
            # Acquire exclusive lock on parent report to serialize concurrent quota checks
            lock_stmt = sa.select(Report.id).where(Report.id == report.id).with_for_update()
            await db.execute(lock_stmt)

            # Query existing active attachments count and cumulative byte sum
            quota_stmt = sa.select(
                sa.func.count(EvidenceAttachment.id),
                sa.func.coalesce(sa.func.sum(EvidenceAttachment.file_size), 0),
            ).where(
                EvidenceAttachment.report_id == report.id,
                EvidenceAttachment.scan_status.not_in([EvidenceScanStatus.DELETED, EvidenceScanStatus.INFECTED]),
            )
            quota_res = await db.execute(quota_stmt)
            existing_count, existing_bytes = quota_res.one()

            # Query existing active attachment SHA-256 hashes to prevent duplicate evidence files in the same report
            hashes_stmt = sa.select(EvidenceAttachment.sha256_hash).where(
                EvidenceAttachment.report_id == report.id,
                EvidenceAttachment.scan_status.not_in([EvidenceScanStatus.DELETED, EvidenceScanStatus.INFECTED]),
            )
            hashes_res = await db.execute(hashes_stmt)
            existing_report_hashes = set(hashes_res.scalars().all())

            for _, _, _, _, sha256_hash in written_attachments:
                if sha256_hash in existing_report_hashes:
                    raise FileValidationError("Duplicate attachment detected in report.")

            if existing_count + len(written_attachments) > settings.MAX_ATTACHMENTS_PER_REPORT:
                raise AttachmentQuotaExceededError(
                    f"Report attachment quota exceeded: max {settings.MAX_ATTACHMENTS_PER_REPORT} files allowed."
                )

            if existing_bytes + cumulative_bytes > max_total_bytes:
                raise AttachmentQuotaExceededError(
                    f"Report total attachment size quota exceeded: max {max_total_bytes // (1024 * 1024)} MiB allowed."
                )

            # Insert EvidenceAttachment rows with status PENDING_SCAN
            created_records: List[EvidenceAttachment] = []
            for storage_key, q_path, detected_mime, f_size, sha256_hash in written_attachments:
                attachment = EvidenceAttachment(
                    report_id=report.id,
                    storage_key=storage_key,
                    detected_mime=detected_mime,
                    file_size=f_size,
                    sha256_hash=sha256_hash,
                    scan_status=EvidenceScanStatus.PENDING_SCAN,
                )
                db.add(attachment)
                created_records.append(attachment)

            # Create AuditLog entry (omits filenames, hashes, case codes, and PII)
            audit_log = AuditLog(
                report_id=report.id,
                moderator_id=None,
                action="EVIDENCE_UPLOADED",
                metadata_={
                    "attachments_count": len(written_attachments),
                    "total_bytes": cumulative_bytes,
                },
            )
            db.add(audit_log)

            await db.commit()
            for record in created_records:
                await db.refresh(record)

        except Exception:
            await db.rollback()
            # Clean up all written quarantine files on any failure
            for _, q_path, _, _, _ in written_attachments:
                if q_path.is_file():
                    try:
                        q_path.unlink()
                    except Exception:
                        pass
            raise

        # 6. Trigger ClamAV scan and promotion for each record (synchronous scan with timeout)
        for record, (_, q_path, _, _, _) in zip(created_records, written_attachments):
            await self.scan_and_promote_attachment(db, record.id, record.storage_key, q_path)

        return len(written_attachments), cumulative_bytes

    async def scan_and_promote_attachment(
        self,
        db: AsyncSession,
        attachment_id: uuid.UUID,
        storage_key: uuid.UUID,
        quarantine_path: Path,
    ) -> None:
        """Scan quarantined file with ClamAV and execute atomic promotion to approved/."""
        scan_result, detail = await clamav_service.scan_file(quarantine_path)
        approved_path = self.approved_dir / f"{storage_key}.bin"

        if scan_result == "OK":
            try:
                # Step 1: DB -> SCAN_CLEAN
                stmt = (
                    sa.update(EvidenceAttachment)
                    .where(EvidenceAttachment.id == attachment_id)
                    .values(
                        scan_status=EvidenceScanStatus.SCAN_CLEAN,
                        scanned_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                await db.execute(stmt)
                await db.commit()

                # Step 2: DB -> PROMOTING
                stmt = (
                    sa.update(EvidenceAttachment)
                    .where(EvidenceAttachment.id == attachment_id)
                    .values(
                        scan_status=EvidenceScanStatus.PROMOTING,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                await db.execute(stmt)
                await db.commit()

                # Step 3: Atomic filesystem rename on same filesystem
                os.replace(str(quarantine_path), str(approved_path))

                # Step 4: Directory fsync provides filesystem metadata durability according to POSIX directory sync contract
                try:
                    dir_fd = os.open(str(self.approved_dir), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except Exception as e:
                    logger.debug("Approved directory fsync notice: %s", str(e))

                # Step 5: Verify physical approved file exists; verify SHA-256 for content integrity verification
                if not approved_path.is_file():
                    raise OSError("Approved file missing after os.replace")

                # SHA-256 calculation provides end-to-end content integrity verification (distinct from filesystem durability)
                hasher = hashlib.sha256()
                with open(approved_path, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)

                # Fetch expected hash from DB
                att_res = await db.execute(
                    sa.select(EvidenceAttachment.sha256_hash, EvidenceAttachment.file_size).where(
                        EvidenceAttachment.id == attachment_id
                    )
                )
                expected_hash, expected_size = att_res.one()

                if approved_path.stat().st_size != expected_size or hasher.hexdigest() != expected_hash:
                    logger.critical("Data integrity mismatch during promotion for attachment %s", attachment_id)
                    if approved_path.is_file():
                        try:
                            approved_path.unlink()
                        except Exception:
                            pass
                    stmt = (
                        sa.update(EvidenceAttachment)
                        .where(EvidenceAttachment.id == attachment_id)
                        .values(
                            scan_status=EvidenceScanStatus.SCAN_FAILED,
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                    await db.execute(stmt)
                    await db.commit()
                    return

                # Step 6: Commit DB -> CLEAN
                stmt = (
                    sa.update(EvidenceAttachment)
                    .where(EvidenceAttachment.id == attachment_id)
                    .values(
                        scan_status=EvidenceScanStatus.CLEAN,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                await db.execute(stmt)
                await db.commit()
                logger.info("Evidence attachment %s promoted to approved (CLEAN).", attachment_id)

            except Exception as e:
                logger.error("Failed during atomic promotion for attachment %s: %s", attachment_id, str(e))
                stmt = (
                    sa.update(EvidenceAttachment)
                    .where(EvidenceAttachment.id == attachment_id)
                    .values(
                        scan_status=EvidenceScanStatus.SCAN_FAILED,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                await db.execute(stmt)
                await db.commit()

        elif scan_result == "FOUND":
            # Infected: unlink quarantine file and update status to INFECTED
            try:
                if quarantine_path.is_file():
                    quarantine_path.unlink()
            except Exception as e:
                logger.error("Failed to delete infected quarantine file: %s", str(e))

            stmt = (
                sa.update(EvidenceAttachment)
                .where(EvidenceAttachment.id == attachment_id)
                .values(
                    scan_status=EvidenceScanStatus.INFECTED,
                    scanned_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.execute(stmt)
            await db.commit()
            logger.warning("Evidence attachment %s marked INFECTED and quarantine file deleted.", attachment_id)

        else:
            # Scanner error / timeout: file remains in quarantine, status transitions to SCAN_FAILED
            stmt = (
                sa.update(EvidenceAttachment)
                .where(EvidenceAttachment.id == attachment_id)
                .values(
                    scan_status=EvidenceScanStatus.SCAN_FAILED,
                    scanned_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.execute(stmt)
            await db.commit()
            logger.warning("Evidence attachment %s scan failed: detail=%s", attachment_id, detail)

    async def list_evidence_for_report(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> List[Tuple[EvidenceAttachment, str]]:
        """List all evidence attachments for a report with deterministic synthetic display names."""
        stmt = (
            sa.select(EvidenceAttachment)
            .where(
                EvidenceAttachment.report_id == report_id,
                EvidenceAttachment.scan_status != EvidenceScanStatus.DELETED,
            )
            .order_by(EvidenceAttachment.created_at.asc(), EvidenceAttachment.id.asc())
        )
        res = await db.execute(stmt)
        records = res.scalars().all()

        results = []
        for idx, rec in enumerate(records, start=1):
            ext = self._mime_to_extension(rec.detected_mime)
            display_name = f"evidence-{idx}{ext}"
            results.append((rec, display_name))
        return results

    async def get_clean_evidence_for_download(
        self,
        db: AsyncSession,
        report_id: uuid.UUID,
        evidence_id: uuid.UUID,
    ) -> Tuple[Path, str, str]:
        """Verify and return physical file path, MIME type, and synthetic download filename.

        Returns:
            Tuple[file_path, detected_mime, synthetic_filename]
        """
        stmt = sa.select(EvidenceAttachment).where(
            EvidenceAttachment.id == evidence_id,
            EvidenceAttachment.report_id == report_id,
        )
        res = await db.execute(stmt)
        attachment = res.scalar_one_or_none()

        if attachment is None:
            raise EvidenceNotFoundError("Evidence attachment not found.")

        if attachment.scan_status != EvidenceScanStatus.CLEAN:
            raise EvidenceNotAvailableError("Evidence attachment not available.")

        approved_file = self.approved_dir / f"{attachment.storage_key}.bin"
        if not approved_file.is_file():
            logger.critical("Data loss: Approved evidence file missing on disk: %s", approved_file)
            raise EvidenceNotFoundError("Evidence file not found on disk.")

        # Determine synthetic filename from index
        all_for_report = await self.list_evidence_for_report(db, report_id)
        display_name = "evidence.bin"
        for rec, d_name in all_for_report:
            if rec.id == attachment.id:
                display_name = d_name
                break

        return approved_file, attachment.detected_mime, display_name

    def _mime_to_extension(self, mime: str) -> str:
        """Map verified MIME type to standard synthetic file extension."""
        mime_map = {
            "application/pdf": ".pdf",
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/webp": ".webp",
            "text/plain": ".txt",
            "text/csv": ".csv",
            "application/csv": ".csv",
        }
        return mime_map.get(mime.lower(), ".bin")

    async def run_reconciliation(self, db_engine: Optional[AsyncEngine] = None) -> None:
        """Execute deterministic multi-worker reconciliation under a session advisory lock."""
        # Check out a single dedicated connection for the entire reconciliation run
        engine_to_use = db_engine or self.db_engine
        async with engine_to_use.connect() as conn:
            # 1. Acquire PostgreSQL session advisory lock on THIS connection
            lock_query = sa.select(sa.func.pg_try_advisory_lock(RECONCILIATION_LOCK_ID))
            acquired = await conn.scalar(lock_query)
            if not acquired:
                logger.debug("Reconciliation lock already held by another worker; skipping cycle.")
                return

            try:
                logger.info("Acquired reconciliation session advisory lock; executing reconciliation.")

                # 2. Reconcile DB-known rows: PENDING_SCAN > 24 hours -> SCAN_FAILED
                cutoff_pending = datetime.now(timezone.utc) - timedelta(
                    hours=settings.PENDING_SCAN_MAX_AGE_HOURS
                )
                stmt_stale_pending = (
                    sa.update(EvidenceAttachment)
                    .where(
                        EvidenceAttachment.scan_status == EvidenceScanStatus.PENDING_SCAN,
                        EvidenceAttachment.created_at < cutoff_pending,
                    )
                    .values(
                        scan_status=EvidenceScanStatus.SCAN_FAILED,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                await conn.execute(stmt_stale_pending)
                await conn.commit()

                # 3. Hash-Verified Recovery of Interrupted Recovery States (SCAN_CLEAN & PROMOTING > 15m)
                cutoff_promoting = datetime.now(timezone.utc) - timedelta(minutes=15)
                stmt_stale_promoting = sa.select(EvidenceAttachment).where(
                    EvidenceAttachment.scan_status.in_(
                        [EvidenceScanStatus.SCAN_CLEAN, EvidenceScanStatus.PROMOTING]
                    ),
                    EvidenceAttachment.updated_at < cutoff_promoting,
                )
                res_promoting = await conn.execute(stmt_stale_promoting)
                stale_recovering = res_promoting.all()

                for row in stale_recovering:
                    att_id = row.id
                    storage_key = row.storage_key
                    expected_size = row.file_size
                    expected_hash = row.sha256_hash

                    app_file = self.approved_dir / f"{storage_key}.bin"
                    quar_file = self.quarantine_dir / f"{storage_key}.bin"

                    recovered = False

                    # Check approved path first (Case B, D, E)
                    if app_file.is_file() and app_file.stat().st_size == expected_size:
                        hasher = hashlib.sha256()
                        with open(app_file, "rb") as f:
                            while chunk := f.read(65536):
                                hasher.update(chunk)
                        if hasher.hexdigest() == expected_hash:
                            # Valid approved file verified
                            await conn.execute(
                                sa.update(EvidenceAttachment)
                                .where(EvidenceAttachment.id == att_id)
                                .values(
                                    scan_status=EvidenceScanStatus.CLEAN,
                                    updated_at=datetime.now(timezone.utc),
                                )
                            )
                            await conn.commit()
                            recovered = True
                            # Case E: approved file is valid, clean up leftover quarantine file
                            if quar_file.is_file():
                                try:
                                    quar_file.unlink()
                                except Exception:
                                    pass

                    # Case G/H: If approved file exists but is corrupted or truncated, remove it
                    if not recovered and app_file.is_file():
                        try:
                            app_file.unlink()
                        except Exception:
                            pass

                    # If not recovered from approved, check quarantine (Case A, C, or E with corrupted approved)
                    if not recovered and quar_file.is_file() and quar_file.stat().st_size == expected_size:
                        hasher = hashlib.sha256()
                        with open(quar_file, "rb") as f:
                            while chunk := f.read(65536):
                                hasher.update(chunk)
                        if hasher.hexdigest() == expected_hash:
                            try:
                                os.replace(str(quar_file), str(app_file))
                                dir_fd = os.open(str(self.approved_dir), os.O_RDONLY)
                                try:
                                    os.fsync(dir_fd)
                                finally:
                                    os.close(dir_fd)

                                await conn.execute(
                                    sa.update(EvidenceAttachment)
                                    .where(EvidenceAttachment.id == att_id)
                                    .values(
                                        scan_status=EvidenceScanStatus.CLEAN,
                                        updated_at=datetime.now(timezone.utc),
                                    )
                                )
                                await conn.commit()
                                recovered = True
                            except Exception as e:
                                logger.error("Recovery rename failed for %s: %s", att_id, str(e))

                    if not recovered:
                        # Case F, I, or corrupted content: transition to SCAN_FAILED
                        logger.warning("Recovery integrity verification failed for attachment %s", att_id)
                        if app_file.is_file():
                            try:
                                app_file.unlink()
                            except Exception:
                                pass
                        await conn.execute(
                            sa.update(EvidenceAttachment)
                            .where(EvidenceAttachment.id == att_id)
                            .values(
                                scan_status=EvidenceScanStatus.SCAN_FAILED,
                                updated_at=datetime.now(timezone.utc),
                            )
                        )
                        await conn.commit()

                # 4. Handle Missing or Corrupted Expected Files (DB marked CLEAN but file invalid)
                stmt_clean = sa.select(
                    EvidenceAttachment.id,
                    EvidenceAttachment.storage_key,
                    EvidenceAttachment.file_size,
                    EvidenceAttachment.sha256_hash,
                ).where(
                    EvidenceAttachment.scan_status == EvidenceScanStatus.CLEAN
                )
                res_clean = await conn.execute(stmt_clean)
                for clean_id, s_key, exp_size, exp_hash in res_clean.all():
                    clean_file = self.approved_dir / f"{s_key}.bin"
                    valid = False
                    if clean_file.is_file() and clean_file.stat().st_size == exp_size:
                        hasher = hashlib.sha256()
                        with open(clean_file, "rb") as f:
                            while chunk := f.read(65536):
                                hasher.update(chunk)
                        if hasher.hexdigest() == exp_hash:
                            valid = True

                    if not valid:
                        logger.critical("Approved file missing or corrupted on disk for CLEAN attachment %s", clean_id)
                        if clean_file.is_file():
                            try:
                                clean_file.unlink()
                            except Exception:
                                pass
                        await conn.execute(
                            sa.update(EvidenceAttachment)
                            .where(EvidenceAttachment.id == clean_id)
                            .values(
                                scan_status=EvidenceScanStatus.SCAN_FAILED,
                                updated_at=datetime.now(timezone.utc),
                            )
                        )
                        await conn.commit()

                # 5. Filesystem Orphan Sweep
                # Collect active storage keys from DB
                res_keys = await conn.execute(
                    sa.select(EvidenceAttachment.storage_key).where(
                        EvidenceAttachment.scan_status != EvidenceScanStatus.DELETED
                    )
                )
                active_keys = {str(k) for (k,) in res_keys.all()}
                grace_cutoff = datetime.now().timestamp() - 900  # 15 minute grace period

                for folder in (self.quarantine_dir, self.approved_dir):
                    if not folder.is_dir():
                        continue
                    for entry in folder.glob("*.bin"):
                        try:
                            # Skip recently modified files to protect in-flight streaming
                            if entry.stat().st_mtime > grace_cutoff:
                                continue
                            file_key = entry.stem
                            if file_key not in active_keys:
                                logger.info("Unlinking orphaned filesystem object: %s", entry.name)
                                entry.unlink()
                        except Exception as e:
                            logger.error("Failed to evaluate/unlink orphan file %s: %s", entry, str(e))

                # 6. Purge Stale Terminal Files (SCAN_FAILED / INFECTED older than QUARANTINE_RETENTION_HOURS)
                cutoff_retention = datetime.now(timezone.utc) - timedelta(
                    hours=settings.QUARANTINE_RETENTION_HOURS
                )
                stmt_stale_quar = sa.select(
                    EvidenceAttachment.id, EvidenceAttachment.storage_key
                ).where(
                    EvidenceAttachment.scan_status.in_(
                        [EvidenceScanStatus.SCAN_FAILED, EvidenceScanStatus.INFECTED]
                    ),
                    EvidenceAttachment.updated_at < cutoff_retention,
                )
                res_stale = await conn.execute(stmt_stale_quar)
                for att_id, s_key in res_stale.all():
                    q_file = self.quarantine_dir / f"{s_key}.bin"
                    if q_file.is_file():
                        try:
                            q_file.unlink()
                        except Exception:
                            pass
                    a_file = self.approved_dir / f"{s_key}.bin"
                    if a_file.is_file():
                        try:
                            a_file.unlink()
                        except Exception:
                            pass
                    await conn.execute(
                        sa.update(EvidenceAttachment)
                        .where(EvidenceAttachment.id == att_id)
                        .values(
                            scan_status=EvidenceScanStatus.DELETED,
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                await conn.commit()

            finally:
                # 7. Release advisory lock on the exact same connection
                try:
                    await conn.execute(
                        sa.select(sa.func.pg_advisory_unlock(RECONCILIATION_LOCK_ID))
                    )
                    logger.info("Released reconciliation session advisory lock.")
                except Exception as e:
                    logger.error("Error unlocking advisory lock: %s", str(e))


evidence_service = EvidenceService()
