import logging
from typing import List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.moderator import Moderator
from app.schemas.quorum import (
    QuorumApproveRequest,
    QuorumApproveResponse,
    QuorumCreateRequest,
    QuorumRejectRequest,
    QuorumRejectResponse,
    QuorumResponse,
)
from app.services.quorum_service import quorum_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "",
    response_model=QuorumResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose a critical action requiring dual-control quorum",
)
async def create_quorum_proposal(
    body: QuorumCreateRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> QuorumResponse:
    """Creates a pending quorum proposal with immutable proposal_hash."""
    proposal = await quorum_service.create_proposal(
        db=db,
        action_type=body.action_type,
        target_id=body.target_id,
        parameters=body.parameters,
        reason=body.reason,
        proposer=current_admin,
    )
    logger.info(
        "AUDIT: Quorum proposal created: proposal_id=%s, action_type=%s, proposer_id=%s",
        proposal.id,
        proposal.action_type,
        current_admin.id,
    )
    return QuorumResponse.model_validate(proposal)


@router.get(
    "",
    response_model=List[QuorumResponse],
    status_code=status.HTTP_200_OK,
    summary="List quorum proposals",
)
async def list_quorum_proposals(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> List[QuorumResponse]:
    """Lists quorum proposals with optional status filter."""
    proposals = await quorum_service.list_proposals(
        db=db,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )
    return [QuorumResponse.model_validate(p) for p in proposals]


@router.get(
    "/{id}",
    response_model=QuorumResponse,
    status_code=status.HTTP_200_OK,
    summary="Get quorum proposal details",
)
async def get_quorum_proposal(
    id: uuid.UUID,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> QuorumResponse:
    """Retrieves full details and status of a quorum proposal."""
    proposal = await quorum_service.get_proposal(db=db, proposal_id=id)
    return QuorumResponse.model_validate(proposal)


@router.post(
    "/{id}/approve",
    response_model=QuorumApproveResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve and execute a pending quorum proposal with live MFA proof",
)
async def approve_quorum_proposal(
    id: uuid.UUID,
    body: QuorumApproveRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> QuorumApproveResponse:
    """Verifies fresh MFA proof and executes proposal atomically under Four-Eyes invariant."""
    result = await quorum_service.approve_and_execute(
        db=db,
        proposal_id=id,
        approver=current_admin,
        approval_reason=body.approval_reason,
        totp_code=body.totp_code,
    )
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    proposal = await quorum_service.get_proposal(db=db, proposal_id=id)

    logger.info(
        "AUDIT: Quorum proposal approved and executed: proposal_id=%s, approver_id=%s",
        id,
        current_admin.id,
    )
    return QuorumApproveResponse(
        status="EXECUTED",
        executed_at=now,
        action_type=proposal.action_type,
        result=result,
    )


@router.post(
    "/{id}/reject",
    response_model=QuorumRejectResponse,
    status_code=status.HTTP_200_OK,
    summary="Reject a pending quorum proposal",
)
async def reject_quorum_proposal(
    id: uuid.UUID,
    body: QuorumRejectRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> QuorumRejectResponse:
    """Rejects a pending quorum proposal by an independent reviewer."""
    await quorum_service.reject_proposal(
        db=db,
        proposal_id=id,
        rejector=current_admin,
        rejection_reason=body.rejection_reason,
    )
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    logger.info(
        "AUDIT: Quorum proposal rejected: proposal_id=%s, rejector_id=%s",
        id,
        current_admin.id,
    )
    return QuorumRejectResponse(
        status="REJECTED",
        rejected_at=now,
    )
