from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.canary import CanaryResponse
from app.services.canary_service import canary_service

router = APIRouter()


@router.get("/latest", response_model=Optional[CanaryResponse])
async def get_latest_canary(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Optional[CanaryResponse]:
    """Returns the latest signed warrant canary statement and its validity window."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    canary = await canary_service.get_latest_canary(db)
    if canary is None:
        return None
    now = datetime.now(timezone.utc)
    return CanaryResponse.from_canary(canary, now=now)


@router.get("/history", response_model=List[CanaryResponse])
async def get_canary_history(
    response: Response,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[CanaryResponse]:
    """Returns paginated historical warrant canary statements."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    canaries = await canary_service.get_canary_history(db, limit=limit, offset=offset)
    now = datetime.now(timezone.utc)
    return [CanaryResponse.from_canary(c, now=now) for c in canaries]
