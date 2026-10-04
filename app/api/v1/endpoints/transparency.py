from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.transparency import (
    ConsistencyProofResponse,
    InclusionProofResponse,
    SignedTreeHeadResponse,
)
from app.services.transparency_service import transparency_service

router = APIRouter()


@router.get("/sth", response_model=SignedTreeHeadResponse)
async def get_latest_signed_tree_head(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> SignedTreeHeadResponse:
    """Returns the latest signed tree head (STH) with root hash and Ed25519 signature."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    sth = await transparency_service.get_latest_sth(db)
    return SignedTreeHeadResponse.model_validate(sth)


@router.get("/proof/inclusion", response_model=InclusionProofResponse)
async def get_inclusion_proof(
    leaf_index: int = Query(..., ge=0, description="0-indexed leaf position"),
    tree_size: int = Query(..., ge=1, description="Tree size for the proof"),
    response: Response = None,
    db: AsyncSession = Depends(get_db),
) -> InclusionProofResponse:
    """Returns an RFC 6962 audit path verifying inclusion of leaf_index in tree_size."""
    if response:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    proof_data = await transparency_service.get_inclusion_proof(db, leaf_index, tree_size)
    return InclusionProofResponse.model_validate(proof_data)


@router.get("/proof/consistency", response_model=ConsistencyProofResponse)
async def get_consistency_proof(
    first: Optional[int] = Query(None, ge=1, description="First tree size"),
    second: Optional[int] = Query(None, ge=1, description="Second tree size"),
    first_tree_size: Optional[int] = Query(None, ge=1, description="First tree size alias"),
    second_tree_size: Optional[int] = Query(None, ge=1, description="Second tree size alias"),
    response: Response = None,
    db: AsyncSession = Depends(get_db),
) -> ConsistencyProofResponse:
    """Returns an RFC 6962 consistency proof that tree of first_size is a prefix of second_size."""
    f = first if first is not None else first_tree_size
    s = second if second is not None else second_tree_size
    if f is None or s is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail="Both first and second tree sizes are required.")

    if response:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    proof_data = await transparency_service.get_consistency_proof(db, f, s)
    return ConsistencyProofResponse.model_validate(proof_data)
