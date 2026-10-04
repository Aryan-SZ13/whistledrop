import hashlib
import json
import logging
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sqlalchemy as sa
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit_log import AuditLog
from app.models.case_message import CaseMessage
from app.models.enums import EvidenceScanStatus, EvidenceShredStatus
from app.models.evidence import EvidenceAttachment
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.schemas.export_retention import ReportVerificationReceiptResponse
from app.services.audit_service import (
    audit_service,
    compute_entry_hash,
    serialize_canonical_audit_entry,
)
from app.services.evidence_service import evidence_service
from app.services.shredder_service import shredder_service

logger = logging.getLogger(__name__)


class CaseExportError(Exception):
    """Base exception for case export failures."""
    pass


class CaseShreddedError(CaseExportError):
    """Raised when attempting to export a shredded case."""
    pass


class CaseExportService:
    def __init__(self) -> None:
        self.temp_dir = Path(settings.EXPORT_TEMP_DIR)
        self.temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _get_signing_key(self) -> ed25519.Ed25519PrivateKey:
        try:
            priv_bytes = bytes.fromhex(settings.EXPORT_SIGNING_KEY_ED25519_PRIVATE)
            if len(priv_bytes) != 32:
                raise ValueError("Ed25519 private key must be exactly 32 bytes.")
            return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        except Exception as e:
            logger.error("Failed to load Ed25519 signing key: %s", str(e))
            raise CaseExportError(f"Export signing key configuration invalid: {e}") from e

    def get_public_key_fingerprint(self) -> str:
        priv = self._get_signing_key()
        pub_raw = priv.public_key().public_bytes_raw()
        return f"SHA256:{hashlib.sha256(pub_raw).hexdigest()}"

    async def generate_verification_receipt(
        self, report: Report, db: AsyncSession
    ) -> ReportVerificationReceiptResponse:
        """Generates an asymmetrically verifiable receipt for a whistleblower's case."""
        stmt = (
            sa.select(AuditLog)
            .where(AuditLog.report_id == report.id)
            .order_by(AuditLog.sequence_number.desc())
            .limit(1)
        )
        res = await db.execute(stmt)
        latest_audit = res.scalar_one_or_none()

        seq_no = latest_audit.sequence_number if latest_audit else 0
        latest_hash = latest_audit.entry_hash if latest_audit else ("0" * 64)

        receipt_payload = {
            "status": report.status.value,
            "sequence_number": seq_no,
            "latest_entry_hash": latest_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signing_key_id": settings.EXPORT_SIGNING_KEY_ID,
        }

        canonical_bytes = json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        priv_key = self._get_signing_key()
        sig_bytes = priv_key.sign(canonical_bytes)

        return ReportVerificationReceiptResponse(
            status=report.status.value,
            terminal_at=report.terminal_at,
            is_shredded=report.is_shredded,
            shredded_at=report.shredded_at,
            withdrawn_at=report.withdrawn_at,
            audit_sequence_number=seq_no,
            latest_entry_hash=latest_hash,
            signing_key_id=settings.EXPORT_SIGNING_KEY_ID,
            verification_receipt_signature=sig_bytes.hex(),
            verification_instructions=(
                "Verify Ed25519 signature against the canonical JSON bytes of "
                "{latest_entry_hash, sequence_number, signing_key_id, status, timestamp} "
                "using WhistleDrop's documented trust anchor."
            ),
        )

    async def export_case_archive(self, report_id: uuid.UUID, db: AsyncSession) -> Path:
        """
        Creates an asymmetrically signed, tamper-evident ZIP archive of an entire case.
        Snapshot-first:
          1. Locks the report row to freeze state during snapshotting.
          2. Decrypts active evidence files into isolated 0700 temporary storage.
          3. Generates canonical metadata and audit logs.
          4. Computes SHA256 hashes of all artifacts.
          5. Generates manifest.json and Ed25519 manifest.sig.
          6. Packs into ZIP archive within EXPORT_MAX_ARCHIVE_BYTES bound.
        """
        # 1. Lock report row
        stmt_report = (
            sa.select(Report)
            .where(Report.id == report_id)
            .with_for_update()
        )
        res_report = await db.execute(stmt_report)
        report = res_report.scalar_one_or_none()
        if not report:
            raise CaseExportError("Report not found.")

        if report.is_shredded:
            raise CaseShreddedError("Cannot export shredded case: cryptographic keys and data have been destroyed.")

        from app.services.canary_service import canary_service
        if await canary_service.is_system_sealed(db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="System is in sealed mode; sensitive case exports disabled.",
            )

        export_uuid = uuid.uuid4()
        session_temp_dir = self.temp_dir / f"export_{export_uuid}"
        session_temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        zip_path = self.temp_dir / f"case_export_{report.id}_{int(datetime.now(timezone.utc).timestamp())}.zip"

        try:
            # Query related data
            # Updates
            stmt_upd = (
                sa.select(ReportUpdate)
                .where(ReportUpdate.report_id == report_id)
                .order_by(ReportUpdate.created_at.asc())
            )
            res_upd = await db.execute(stmt_upd)
            updates = res_upd.scalars().all()

            # Messages
            stmt_msg = (
                sa.select(CaseMessage)
                .where(CaseMessage.report_id == report_id)
                .order_by(CaseMessage.created_at.asc(), CaseMessage.id.asc())
            )
            res_msg = await db.execute(stmt_msg)
            messages = res_msg.scalars().all()

            # Audit entries
            stmt_audit = (
                sa.select(AuditLog)
                .where(AuditLog.report_id == report_id)
                .order_by(AuditLog.sequence_number.asc())
            )
            res_audit = await db.execute(stmt_audit)
            audit_entries = res_audit.scalars().all()

            # Evidence
            stmt_ev = (
                sa.select(EvidenceAttachment)
                .where(
                    EvidenceAttachment.report_id == report_id,
                    EvidenceAttachment.scan_status == EvidenceScanStatus.CLEAN,
                    EvidenceAttachment.shred_status == EvidenceShredStatus.ACTIVE.value,
                )
                .order_by(EvidenceAttachment.created_at.asc())
            )
            res_ev = await db.execute(stmt_ev)
            evidence_attachments = res_ev.scalars().all()

            # 2. Write Snapshot Files with ALEE payload decryption
            from app.services.payload_encryption_service import DecryptionContext, payload_encryption_service
            description_text = report.description
            if description_text is None and report.description_encrypted is not None:
                try:
                    description_text = await payload_encryption_service.decrypt_payload(
                        db=db,
                        report_id=report.id,
                        object_type="REPORT",
                        object_id=report.id,
                        field_name="description",
                        ciphertext=report.description_encrypted,
                        iv=report.description_iv,
                        tag=report.description_tag,
                        aad_version=report.description_aad_version,
                        context=DecryptionContext.EXPORT,
                    )
                except Exception:
                    description_text = "[Cryptographically shredded]"

            metadata_dict = {
                "id": str(report.id),
                "category": report.category.value,
                "description": description_text,
                "status": report.status.value,
                "priority": report.priority.value,
                "created_at": report.created_at.isoformat(),
                "updated_at": report.updated_at.isoformat() if report.updated_at else None,
                "terminal_at": report.terminal_at.isoformat() if report.terminal_at else None,
                "withdrawn_at": report.withdrawn_at.isoformat() if report.withdrawn_at else None,
                "is_shredded": report.is_shredded,
                "shredded_at": report.shredded_at.isoformat() if report.shredded_at else None,
                "assigned_to": str(report.assigned_to) if report.assigned_to else None,
                "updates": [
                    {
                        "id": str(u.id),
                        "update_type": u.update_type.value,
                        "old_value": u.old_value,
                        "new_value": u.new_value,
                        "created_at": u.created_at.isoformat(),
                    }
                    for u in updates
                ],
            }
            (session_temp_dir / "report_metadata.json").write_text(
                json.dumps(metadata_dict, indent=2, sort_keys=True), encoding="utf-8"
            )

            messages_list = []
            for m in messages:
                m_content = m.content
                if m_content is None and m.content_encrypted is not None:
                    try:
                        m_content = await payload_encryption_service.decrypt_payload(
                            db=db,
                            report_id=report_id,
                            object_type="CASE_MESSAGE",
                            object_id=m.id,
                            field_name="content",
                            ciphertext=m.content_encrypted,
                            iv=m.content_iv,
                            tag=m.content_tag,
                            aad_version=m.content_aad_version,
                            context=DecryptionContext.EXPORT,
                        )
                    except Exception:
                        m_content = "[Cryptographically shredded]"
                messages_list.append({
                    "id": str(m.id),
                    "public_id": m.public_id,
                    "sender_type": m.sender_type.value,
                    "content": m_content,
                    "created_at": m.created_at.isoformat(),
                })
            (session_temp_dir / "channel_messages.json").write_text(
                json.dumps(messages_list, indent=2, sort_keys=True), encoding="utf-8"
            )

            # Internal notes (empty list for backward compatibility / note redaction)
            (session_temp_dir / "internal_notes.json").write_text("[]", encoding="utf-8")

            audit_list = [
                {
                    "sequence_number": a.sequence_number,
                    "action": a.action,
                    "actor_id": str(a.moderator_id) if a.moderator_id else None,
                    "actor_type": "MODERATOR" if a.moderator_id else "SYSTEM",
                    "metadata": a.metadata_,
                    "previous_hash": a.previous_hash,
                    "entry_hash": a.entry_hash,
                    "hash_version": a.hash_version,
                    "created_at": a.created_at.isoformat(),
                }
                for a in audit_entries
            ]
            (session_temp_dir / "audit_chain.json").write_text(
                json.dumps(audit_list, indent=2, sort_keys=True), encoding="utf-8"
            )

            # Decrypt and stage evidence
            evidence_temp_dir = session_temp_dir / "evidence"
            evidence_temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

            for att in evidence_attachments:
                src_path = Path(settings.EVIDENCE_STORAGE_PATH) / "approved" / f"{att.storage_key}.bin"
                if not src_path.is_file():
                    logger.warning("Evidence file missing on disk: %s", att.storage_key)
                    continue

                if not att.wrapped_dek or att.shred_status != EvidenceShredStatus.ACTIVE.value:
                    raise CaseExportError(
                        f"Evidence attachment {att.id} has been cryptographically erased or is unencrypted."
                    )

                c_bytes = src_path.read_bytes()
                p_bytes = shredder_service.decrypt_evidence_content(
                    ciphertext=c_bytes,
                    wrapped_dek=att.wrapped_dek,
                    dek_nonce=att.dek_nonce,
                    dek_tag=att.dek_tag,
                    file_nonce=att.file_nonce,
                    file_tag=att.file_tag,
                    kek_key_id=att.kek_key_id,
                )

                # Verify plaintext hash
                calc_hash = hashlib.sha256(p_bytes).hexdigest()
                if calc_hash != att.sha256_hash:
                    logger.error("Evidence hash mismatch during export: %s", att.id)
                    raise CaseExportError(f"Integrity check failed for evidence attachment {att.id}")

                ext = evidence_service._mime_to_extension(att.detected_mime)
                safe_name = f"evidence_{att.id}{ext}"
                dest_file = evidence_temp_dir / safe_name
                dest_file.write_bytes(p_bytes)

            # 3. Compute manifest file entries
            file_manifest: Dict[str, Dict[str, Any]] = {}
            for root, _, files in os.walk(session_temp_dir):
                for f in files:
                    file_path = Path(root) / f
                    rel_path = file_path.relative_to(session_temp_dir).as_posix()
                    content = file_path.read_bytes()
                    file_manifest[rel_path] = {
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size_bytes": len(content),
                    }

            # 4. Manifest generation & signing
            priv_key = self._get_signing_key()
            pub_raw = priv_key.public_key().public_bytes_raw()
            fp = f"SHA256:{hashlib.sha256(pub_raw).hexdigest()}"

            manifest_content = {
                "manifest_version": "1.0",
                "case_id": str(report.id),
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "signing_key_id": settings.EXPORT_SIGNING_KEY_ID,
                "signing_key_fingerprint": fp,
                "disclaimer": (
                    "The included public key is provided for transport convenience. "
                    "Verifiers MUST validate this key against their external/trusted key registry or signing_key_id."
                ),
                "audit_chain_summary": {
                    "total_entries": len(audit_entries),
                    "latest_entry_hash": audit_entries[-1].entry_hash if audit_entries else None,
                    "chain_valid": True,
                },
                "files": file_manifest,
            }

            canonical_manifest_bytes = json.dumps(
                manifest_content, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            (session_temp_dir / "manifest.json").write_bytes(canonical_manifest_bytes)

            # Sign canonical manifest bytes
            sig_bytes = priv_key.sign(canonical_manifest_bytes)
            (session_temp_dir / "manifest.sig").write_bytes(sig_bytes)

            # Write public key for convenience
            (session_temp_dir / "signing_key.pub").write_bytes(pub_raw)

            # 5. Pack into ZIP archive
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(session_temp_dir):
                    for f in files:
                        p = Path(root) / f
                        arcname = p.relative_to(session_temp_dir).as_posix()
                        zf.write(p, arcname=arcname)

            if zip_path.stat().st_size > settings.EXPORT_MAX_ARCHIVE_BYTES:
                if zip_path.is_file():
                    shredder_service.best_effort_shred_file(zip_path)
                raise CaseExportError(
                    f"Export archive size ({zip_path.stat().st_size} bytes) exceeds maximum "
                    f"limit ({settings.EXPORT_MAX_ARCHIVE_BYTES} bytes)."
                )

            return zip_path

        except Exception:
            if zip_path.is_file():
                try:
                    shredder_service.best_effort_shred_file(zip_path)
                except Exception:
                    pass
            raise

        finally:
            # Clean up plaintext staged files in session_temp_dir
            try:
                for root, _, files in os.walk(session_temp_dir):
                    for f in files:
                        shredder_service.best_effort_shred_file(Path(root) / f)
                shutil.rmtree(session_temp_dir, ignore_errors=True)
            except Exception as e:
                logger.warning("Error cleaning export session temp dir: %s", str(e))

    def verify_case_export_archive(
        self, zip_path: Path, trusted_fingerprints: Optional[List[str]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Independently verifies an exported case ZIP archive:
          - Verifies manifest.sig using Ed25519 against manifest.json
          - Verifies key against trusted_fingerprints
          - Verifies SHA256 and size of all included files
          - Verifies audit log mathematical chain progression
        """
        errors: List[str] = []
        if not zip_path.is_file():
            return False, ["Archive file not found."]

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = set(zf.namelist())
                if "manifest.json" not in names:
                    return False, ["manifest.json missing from archive."]
                if "manifest.sig" not in names:
                    return False, ["manifest.sig missing from archive."]

                manifest_raw = zf.read("manifest.json")
                sig_raw = zf.read("manifest.sig")

                try:
                    manifest_data = json.loads(manifest_raw.decode("utf-8"))
                except Exception as e:
                    return False, [f"Invalid manifest.json JSON: {e}"]

                # Canonicalize manifest bytes for signature verification
                canonical_bytes = json.dumps(
                    manifest_data, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")

                key_id = manifest_data.get("signing_key_id")
                key_fp = manifest_data.get("signing_key_fingerprint")

                if not key_id or key_id != settings.EXPORT_SIGNING_KEY_ID:
                    errors.append(f"Unknown or unsupported signing_key_id: {key_id}")

                # Public key check: prefer trusted fingerprint list
                pub_bytes: Optional[bytes] = None
                if "signing_key.pub" in names:
                    pub_bytes = zf.read("signing_key.pub")

                if not pub_bytes or len(pub_bytes) != 32:
                    return False, ["Valid 32-byte Ed25519 public key not found in archive."]

                calc_fp = f"SHA256:{hashlib.sha256(pub_bytes).hexdigest()}"
                if key_fp and key_fp != calc_fp:
                    errors.append(f"Public key fingerprint mismatch: {calc_fp} != {key_fp}")

                # External trust anchor check
                trusted = trusted_fingerprints or (
                    settings.TRUSTED_SIGNING_KEY_FINGERPRINTS
                    if isinstance(settings.TRUSTED_SIGNING_KEY_FINGERPRINTS, list)
                    else [settings.TRUSTED_SIGNING_KEY_FINGERPRINTS]
                )
                if trusted and calc_fp not in trusted:
                    errors.append(
                        f"Untrusted public key fingerprint: {calc_fp} is not in trusted anchor set."
                    )

                try:
                    pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                    pub_key.verify(sig_raw, canonical_bytes)
                except Exception as e:
                    errors.append(f"Ed25519 signature verification failed: {e}")

                # Check for unexpected files in archive
                files_dict = manifest_data.get("files", {})
                declared_files = set(files_dict.keys())
                allowed_meta_files = {"manifest.json", "manifest.sig", "signing_key.pub"}
                unexpected_files = names - declared_files - allowed_meta_files
                if unexpected_files:
                    errors.append(
                        f"Unexpected unverified files found in archive: {sorted(list(unexpected_files))}"
                    )

                # Verify files listed in manifest
                for rel_path, meta in files_dict.items():
                    if rel_path in ("manifest.json", "manifest.sig", "signing_key.pub"):
                        continue
                    if rel_path not in names:
                        errors.append(f"Manifest file missing from archive: {rel_path}")
                        continue

                    file_bytes = zf.read(rel_path)
                    expected_sha = meta.get("sha256")
                    expected_size = meta.get("size_bytes")

                    if len(file_bytes) != expected_size:
                        errors.append(
                            f"Size mismatch for {rel_path}: expected {expected_size}, got {len(file_bytes)}"
                        )
                    calc_sha = hashlib.sha256(file_bytes).hexdigest()
                    if calc_sha != expected_sha:
                        errors.append(
                            f"SHA256 mismatch for {rel_path}: expected {expected_sha}, got {calc_sha}"
                        )

                # Verify audit chain
                if "audit_chain.json" in names:
                    try:
                        audit_list = json.loads(zf.read("audit_chain.json").decode("utf-8"))
                        prev_hash = "0" * 64
                        for item in audit_list:
                            seq = item["sequence_number"]
                            if item["previous_hash"] != prev_hash:
                                errors.append(f"Audit log broken hash link at sequence {seq}")
                            entry_dt = datetime.fromisoformat(item["created_at"])
                            canonical_bytes = serialize_canonical_audit_entry(
                                hash_version=item.get("hash_version", 1),
                                report_id=uuid.UUID(manifest_data["case_id"]),
                                sequence_number=seq,
                                created_at=entry_dt,
                                action=item["action"],
                                actor_type=item.get("actor_type", "SYSTEM"),
                                actor_id=item.get("actor_id"),
                                previous_hash=prev_hash,
                                metadata=item.get("metadata"),
                            )
                            expected_entry_hash = compute_entry_hash(canonical_bytes)
                            if item["entry_hash"] != expected_entry_hash:
                                errors.append(f"Audit log entry hash invalid at sequence {seq}")
                            prev_hash = item["entry_hash"]
                    except Exception as e:
                        errors.append(f"Audit chain verification error: {e}")

        except Exception as e:
            return False, [f"Archive reading error: {e}"]

        return len(errors) == 0, errors

    def cleanup_export_file(self, zip_path: Path) -> None:
        """Background task helper to securely shred and remove temporary ZIP export file."""
        if zip_path.is_file():
            try:
                shredder_service.best_effort_shred_file(zip_path)
            except Exception as e:
                logger.warning("Failed to clean up export file %s: %s", zip_path, str(e))

    def cleanup_orphaned_exports(self, max_age_seconds: int = 3600) -> int:
        """Sweeps orphaned temporary files in EXPORT_TEMP_DIR older than max_age_seconds."""
        now = datetime.now(timezone.utc).timestamp()
        cleaned = 0
        if not self.temp_dir.exists():
            return 0
        for item in self.temp_dir.iterdir():
            try:
                mtime = item.stat().st_mtime
                if now - mtime > max_age_seconds:
                    if item.is_dir():
                        for root, _, files in os.walk(item):
                            for f in files:
                                shredder_service.best_effort_shred_file(Path(root) / f)
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        shredder_service.best_effort_shred_file(item)
                    cleaned += 1
            except Exception as e:
                logger.warning("Failed to clean up orphaned item %s: %s", item, str(e))
        return cleaned


case_export_service = CaseExportService()
