from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import HTTPException, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import verify_totp_code
from app.db.redis import get_redis
from app.models.audit_log import AuditLog
from app.models.enums import ReportStatus
from app.models.moderator import Moderator
from app.models.quorum import QuorumRequest
from app.models.report import Report
from app.services.audit_service import audit_service
from app.services.mfa_service import mfa_service
from app.services.outbox_service import outbox_service

logger = logging.getLogger(__name__)

ALLOWLISTED_ACTIONS = {
    "MANUAL_RETENTION_SWEEP",
    "ADMIN_CASE_REOPEN",
    "MODERATOR_ROLE_CHANGE",
    "MODERATOR_DEACTIVATE",
    "WEBHOOK_ENDPOINT_DELETE",
}


class QuorumExecutionContext:
    """Carried into domain services to prove that Four-Eyes approval has been verified."""
    def __init__(self, quorum_id: uuid.UUID, approver_id: uuid.UUID, proposal: QuorumRequest) -> None:
        self.quorum_id = quorum_id
        self.approver_id = approver_id
        self.proposal = proposal


class QuorumRequiredException(HTTPException):
    def __init__(self, action_type: str, target_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "status": "QUORUM_REQUIRED",
                "message": f"Action '{action_type}' requires dual-control administrator quorum approval before execution.",
                "action_type": action_type,
                "target_id": target_id,
                "details": details or {},
            },
        )


class QuorumService:
    def __init__(self) -> None:
        pass

    def compute_proposal_hash(
        self,
        action_type: str,
        target_id: Optional[str],
        parameters: Dict[str, Any],
    ) -> str:
        canonical_str = f"v1:{action_type}:{target_id or 'none'}:{json.dumps(parameters, sort_keys=True, separators=(',', ':'))}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    async def create_proposal(
        self,
        db: AsyncSession,
        action_type: str,
        target_id: Optional[str],
        parameters: Dict[str, Any],
        reason: str,
        proposer: Moderator,
    ) -> QuorumRequest:
        if action_type not in ALLOWLISTED_ACTIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Action type '{action_type}' is not allowlisted for quorum control.",
            )

        proposal_hash = self.compute_proposal_hash(action_type, target_id, parameters)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.QUORUM_DEFAULT_TTL_MINUTES)

        proposal = QuorumRequest(
            action_type=action_type,
            target_id=target_id,
            proposal_hash=proposal_hash,
            proposed_by_id=proposer.id,
            status="PENDING",
            parameters=parameters,
            reason=reason,
            expires_at=expires_at,
        )
        db.add(proposal)
        await db.commit()
        await db.refresh(proposal)

        # Publish outbox notification event
        await outbox_service.publish_event(
            db=db,
            event_type="quorum.requested",
            raw_data={
                "quorum_id": str(proposal.id),
                "action_type": action_type,
                "target_id": target_id,
            },
        )
        await db.commit()

        logger.info(f"Quorum proposal {proposal.id} created by admin {proposer.id} for action {action_type}.")
        return proposal

    async def list_proposals(
        self,
        db: AsyncSession,
        status_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[QuorumRequest]:
        stmt = sa.select(QuorumRequest)
        if status_filter:
            stmt = stmt.where(QuorumRequest.status == status_filter)
        stmt = stmt.order_by(QuorumRequest.created_at.desc()).limit(limit).offset(offset)
        return list((await db.execute(stmt)).scalars().all())

    async def get_proposal(self, db: AsyncSession, proposal_id: uuid.UUID) -> QuorumRequest:
        stmt = sa.select(QuorumRequest).where(QuorumRequest.id == proposal_id)
        proposal = (await db.execute(stmt)).scalar_one_or_none()
        if not proposal:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Quorum request not found")
        return proposal

    async def approve_and_execute(
        self,
        db: AsyncSession,
        proposal_id: uuid.UUID,
        approver: Moderator,
        approval_reason: str,
        totp_code: str,
    ) -> Dict[str, Any]:
        """Approves and executes a pending quorum request atomically with fresh MFA proof."""
        now = datetime.now(timezone.utc)

        # 1. Lock quorum request
        stmt = (
            sa.select(QuorumRequest)
            .where(QuorumRequest.id == proposal_id)
            .with_for_update()
        )
        proposal = (await db.execute(stmt)).scalar_one_or_none()
        if not proposal:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Quorum request not found")

        # 2. Assert status PENDING
        if proposal.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Quorum request is in '{proposal.status}' state and cannot be approved.",
            )

        # 3. Assert not expired
        if proposal.expires_at <= now:
            proposal.status = "EXPIRED"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Quorum request has expired.",
            )

        # 4. Assert distinct operator (Four-Eyes Invariant)
        if proposal.proposed_by_id == approver.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Violation of Four-Eyes principle: Administrator cannot approve their own proposal.",
            )

        # 5. Fresh MFA proof verification bound to (approver, proposal_id, action_type, time_step)
        if not approver.is_totp_enabled or not approver.totp_secret_encrypted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Approving administrator must have MFA enabled.",
            )
        raw_secret = mfa_service.decrypt_secret(
            approver.totp_secret_encrypted,
            approver.totp_secret_iv,
            approver.totp_secret_tag,
        )
        if not verify_totp_code(raw_secret, totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid fresh MFA proof.",
            )

        # Prevent proof replay on the same quorum approval
        time_step = int(time.time() // 30)
        redis = get_redis()
        proof_key = f"used_totp_proof:{approver.id}:{proposal.id}:{time_step}"
        try:
            acquired = await redis.set(proof_key, "1", nx=True, ex=60)
            if not acquired:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="TOTP proof has already been consumed for this quorum approval.",
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Redis error checking TOTP proof replay: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )

        # 6. Verify proposal_hash integrity
        recomputed_hash = self.compute_proposal_hash(
            proposal.action_type,
            proposal.target_id,
            proposal.parameters,
        )
        if recomputed_hash != proposal.proposal_hash:
            logger.critical(
                f"Quorum proposal {proposal.id} parameter tampering detected! "
                f"Stored: {proposal.proposal_hash}, Recomputed: {recomputed_hash}"
            )
            proposal.status = "FAILED_CONFLICT"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Proposal parameter integrity violation detected.",
            )

        # 7. Execute allowlisted action with lock ordering
        context = QuorumExecutionContext(
            quorum_id=proposal.id,
            approver_id=approver.id,
            proposal=proposal,
        )
        result = await self._execute_allowlisted_action(db, proposal, context)

        # 8. Mark proposal EXECUTED atomically
        proposal.status = "EXECUTED"
        proposal.executed_at = now
        proposal.approved_by_id = approver.id
        proposal.approval_reason = approval_reason
        proposal.approval_signature = hashlib.sha256(
            f"{proposal.proposal_hash}:{approver.id}:{now.isoformat()}".encode()
        ).hexdigest()

        # 9. Append audit log entry documenting dual-party attribution for report actions
        report_uuid = None
        if proposal.action_type in ("ADMIN_CASE_REOPEN",) and proposal.target_id:
            try:
                report_uuid = uuid.UUID(proposal.target_id)
            except ValueError:
                pass

        if report_uuid:
            await audit_service.append_entry(
                db=db,
                report_id=report_uuid,
                action=f"QUORUM_ACTION_{proposal.action_type}",
                actor_type="MODERATOR",
                actor_id=approver.id,
                metadata={
                    "quorum_id": str(proposal.id),
                    "action_type": proposal.action_type,
                    "proposed_by_id": str(proposal.proposed_by_id),
                    "approved_by_id": str(approver.id),
                    "approval_reason": approval_reason,
                },
            )

        # 10. Publish outbox event
        await outbox_service.publish_event(
            db=db,
            event_type="quorum.approved",
            report_id=report_uuid,
            raw_data={
                "quorum_id": str(proposal.id),
                "action_type": proposal.action_type,
            },
        )

        await db.commit()
        logger.info(f"Quorum action {proposal.action_type} (id: {proposal.id}) executed successfully.")
        return result

    async def _execute_allowlisted_action(
        self,
        db: AsyncSession,
        proposal: QuorumRequest,
        context: QuorumExecutionContext,
    ) -> Dict[str, Any]:
        """Dispatches to domain services using verified QuorumExecutionContext."""
        action = proposal.action_type
        params = proposal.parameters

        if action == "ADMIN_CASE_REOPEN":
            from app.services.moderator_service import moderator_service
            report_id = uuid.UUID(proposal.target_id)
            expected_ver = params.get("expected_version")
            reopen_reason = params.get("reopen_reason", "Quorum-approved reopening")

            # Execute with quorum context
            report, audit = await moderator_service.reopen_report_internal(
                db=db,
                report_id=report_id,
                expected_version=expected_ver,
                reopen_reason=reopen_reason,
                admin_id=context.approver_id,
                quorum_context=context,
            )
            return {"report_id": str(report.id), "status": report.status.value, "version_id": report.version_id}

        elif action == "MANUAL_RETENTION_SWEEP":
            from app.services.retention_service import retention_service
            limit = params.get("limit", 50)
            res = await retention_service.execute_retention_sweep_internal(
                db=db,
                limit=limit,
                quorum_context=context,
            )
            return {
                "processed_count": res.processed_count,
                "shredded_evidence_count": res.shredded_evidence_count,
            }

        elif action == "WEBHOOK_ENDPOINT_DELETE":
            from app.services.webhook_dispatcher_service import webhook_dispatcher_service
            endpoint_id = uuid.UUID(proposal.target_id)
            await webhook_dispatcher_service.delete_endpoint(db, endpoint_id)
            return {"endpoint_id": str(endpoint_id), "status": "deleted"}

        elif action == "MODERATOR_ROLE_CHANGE":
            mod_id = uuid.UUID(proposal.target_id)
            new_role = params["new_role"]
            target_mod = (await db.execute(sa.select(Moderator).where(Moderator.id == mod_id).with_for_update())).scalar_one()
            from app.models.enums import ModeratorRole
            target_mod.role = ModeratorRole(new_role)
            return {"moderator_id": str(mod_id), "new_role": new_role}

        elif action == "MODERATOR_DEACTIVATE":
            mod_id = uuid.UUID(proposal.target_id)
            target_mod = (await db.execute(sa.select(Moderator).where(Moderator.id == mod_id).with_for_update())).scalar_one()
            target_mod.is_active = False
            return {"moderator_id": str(mod_id), "is_active": False}

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported action {action}")

    async def reject_proposal(
        self,
        db: AsyncSession,
        proposal_id: uuid.UUID,
        rejector: Moderator,
        rejection_reason: str,
    ) -> None:
        stmt = (
            sa.select(QuorumRequest)
            .where(QuorumRequest.id == proposal_id)
            .with_for_update()
        )
        proposal = (await db.execute(stmt)).scalar_one_or_none()
        if not proposal:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Quorum request not found")

        if proposal.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Quorum request is in '{proposal.status}' state and cannot be rejected.",
            )

        if proposal.proposed_by_id == rejector.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Proposer cannot reject their own proposal via reviewer flow.",
            )

        proposal.status = "REJECTED"
        proposal.approval_reason = f"REJECTED: {rejection_reason}"
        await db.commit()
        logger.info(f"Quorum request {proposal_id} rejected by {rejector.id}.")


quorum_service = QuorumService()
