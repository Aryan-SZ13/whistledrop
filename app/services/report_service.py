from datetime import datetime, timezone
import hashlib
import logging
from typing import Optional, Tuple
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import derive_case_code_digest, generate_case_code
from app.models.enums import ReportStatus, ReportUpdateType
from app.models.report import Report
from app.models.report_update import ReportUpdate
from app.schemas.report import (
    ReportCreate,
    ReportTrackingResponse,
    ReportUpdatePublic,
)
from app.schemas.transparency import MerkleReceipt
from app.services.audit_service import audit_service
from app.services.canary_service import canary_service
from app.services.payload_encryption_service import (
    DecryptionContext,
    payload_encryption_service,
)
from app.services.transparency_service import transparency_service

logger = logging.getLogger(__name__)


class ReportService:
    """Business logic for anonymous report submission and management."""

    async def create_report(
        self,
        db: AsyncSession,
        report_in: ReportCreate,
    ) -> Tuple[Report, str]:
        """Create a new anonymous report atomically within a database transaction.

        Flow:
        1. Generate a high-entropy case code using CSPRNG.
        2. Derive HMAC-SHA256 digest using CASE_CODE_SECRET.
        3. Persist the Report model record with status SUBMITTED (storing only digest).
        4. Encrypt sensitive description using Application-Level Envelope Encryption (ALEE).
        5. Persist an AuditLog record (excluding case code, description, and client metadata).
        6. Commit an immutable Merkle leaf to the append-only transparency tree.
        7. Atomically commit the transaction.
        8. Return the persisted Report model and the reusable plaintext case code.

        Returns:
            Tuple[Report, str]: The persisted report model and the plaintext case code.
        """
        # 1. Generate case code using cryptographically secure RNG
        case_code = generate_case_code()

        # 2. Derive HMAC digest using CASE_CODE_SECRET
        case_code_digest = derive_case_code_digest(case_code)

        try:
            # 3. Create Report model instance (only storing digest, never plaintext case code)
            evidence_url_str = str(report_in.evidence_url) if report_in.evidence_url else None
            report = Report(
                case_code_digest=case_code_digest,
                category=report_in.category,
                description=None,  # Will be stored encrypted
                evidence_url=evidence_url_str,
                status=ReportStatus.SUBMITTED,
            )
            db.add(report)
            await db.flush()  # Populates report.id for internal audit log and encryption linkage

            # 4. Phase 18: Encrypt description with per-case DEK and AAD binding
            if report_in.description:
                ciphertext, iv, tag, key_version = await payload_encryption_service.encrypt_payload(
                    db=db,
                    report_id=report.id,
                    object_type="REPORT",
                    object_id=report.id,
                    field_name="description",
                    plaintext=report_in.description,
                )
                report.description_encrypted = ciphertext
                report.description_iv = iv
                report.description_tag = tag
                report.description_aad_version = key_version

            # 5. Create safe audit log entry via audit_service (tamper-evident hash chain)
            await audit_service.append_entry(
                db=db,
                report_id=report.id,
                action="REPORT_SUBMITTED",
                actor_type="REPORTER",
                actor_id=None,
                metadata={
                    "category": report.category.value,
                    "has_evidence": bool(report.evidence_url),
                },
            )

            # 6. Phase 19: Append-Only Merkle Transparency commitment
            payload_digest = hashlib.sha256(
                f"{report.id}:{report.category.value}:{report.created_at}".encode("utf-8")
            ).digest()
            merkle_leaf, tree_size = await transparency_service.commit_merkle_leaf(
                db=db,
                event_type="report.submitted",
                opaque_reference=str(report.id),
                payload_digest=payload_digest,
                occurred_at=report.created_at,
            )
            report._merkle_receipt = MerkleReceipt(
                leaf_index=merkle_leaf.leaf_index,
                leaf_hash=merkle_leaf.leaf_hash,
                tree_size=tree_size,
                event_type=merkle_leaf.event_type,
                opaque_reference=merkle_leaf.opaque_reference,
                committed_at=merkle_leaf.created_at,
            )

            # 7. Publish transactional outbox event
            from app.services.outbox_service import outbox_service
            await outbox_service.publish_event(
                db=db,
                event_type="report.created",
                report_id=report.id,
                case_code_digest=report.case_code_digest,
                raw_data={
                    "status": report.status.value,
                    "category": report.category.value,
                    "priority": report.priority.value,
                },
            )

            # 8. Commit all records atomically
            await db.commit()
            await db.refresh(report)

            # 9. Minimal operational logging
            logger.info("Report submitted successfully: category=%s", report.category.value)

            return report, case_code

        except Exception as e:
            await db.rollback()
            logger.error("Failed to submit anonymous report, transaction rolled back: %s", str(e))
            raise

    async def get_report_tracking(
        self,
        db: AsyncSession,
        case_code: str,
    ) -> Optional[ReportTrackingResponse]:
        """Retrieve the public tracking state of a report by its case code.

        Flow:
        1. Normalize case code by stripping whitespace.
        2. Derive HMAC-SHA256 digest using CASE_CODE_SECRET.
        3. Perform indexed lookup on reports.case_code_digest.
        4. If found, retrieve chronological public updates without moderator/audit details.
        5. Decrypt PUBLIC_UPDATE content using ANONYMOUS_PUBLIC_UPDATE context (allowed even under seal).
        6. Map to public ReportTrackingResponse schema with strict field minimization.

        Returns:
            Optional[ReportTrackingResponse]: Public tracking schema if found, None otherwise.
        """
        if not case_code:
            return None

        # 1. Normalize case code where intended
        normalized_code = case_code.strip()
        if not normalized_code:
            return None

        # 2. Derive HMAC digest using centralized security function
        case_code_digest = derive_case_code_digest(normalized_code)

        # 3. Query report by indexed digest
        stmt = sa.select(Report).where(Report.case_code_digest == case_code_digest)
        result = await db.execute(stmt)
        report = result.scalar_one_or_none()

        if report is None:
            return None

        # 4. Query chronological public updates with least-privilege column selection
        stmt_updates = (
            sa.select(
                ReportUpdate.message,
                ReportUpdate.created_at,
            )
            .where(
                ReportUpdate.report_id == report.id,
                ReportUpdate.type == ReportUpdateType.PUBLIC_UPDATE,
            )
            .order_by(ReportUpdate.created_at.asc(), ReportUpdate.id.asc())
        )
        res_updates = await db.execute(stmt_updates)
        update_rows = res_updates.all()

        # Check if any updates require decryption
        has_encrypted = any(u.message is None for u in update_rows)
        enc_rows = []
        if has_encrypted:
            stmt_enc = (
                sa.select(
                    ReportUpdate.id,
                    ReportUpdate.message_encrypted,
                    ReportUpdate.message_iv,
                    ReportUpdate.message_tag,
                    ReportUpdate.message_aad_version,
                )
                .where(
                    ReportUpdate.report_id == report.id,
                    ReportUpdate.type == ReportUpdateType.PUBLIC_UPDATE,
                )
                .order_by(ReportUpdate.created_at.asc(), ReportUpdate.id.asc())
            )
            res_enc = await db.execute(stmt_enc)
            enc_rows = res_enc.all()

        # 5. Construct public tracking response with decryption under ANONYMOUS_PUBLIC_UPDATE context
        public_updates = []
        for idx, u in enumerate(update_rows):
            msg_text = u.message
            if msg_text is None and idx < len(enc_rows):
                erow = enc_rows[idx]
                if erow.message_encrypted is not None:
                    try:
                        msg_text = await payload_encryption_service.decrypt_payload(
                            db=db,
                            report_id=report.id,
                            object_type="REPORT_UPDATE",
                            object_id=erow.id,
                            field_name="message",
                            ciphertext=erow.message_encrypted,
                            iv=erow.message_iv,
                            tag=erow.message_tag,
                            aad_version=erow.message_aad_version,
                            context=DecryptionContext.ANONYMOUS_PUBLIC_UPDATE,
                        )
                    except Exception as exc:
                        logger.error("Failed to decrypt public update for report %s: %s", report.id, exc)
                        msg_text = "[Encrypted update unavailable]"

            if msg_text:
                public_updates.append(
                    ReportUpdatePublic(
                        message=msg_text,
                        created_at=u.created_at,
                    )
                )

        return ReportTrackingResponse(
            status=report.status,
            updates=public_updates,
        )


report_service = ReportService()
