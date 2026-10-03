from fastapi import APIRouter
from app import __version__
from app.core.config import settings

router = APIRouter()


@router.get("/health", summary="Health Check")
async def health_check():
    """Returns the operational status of the service."""
    return {
        "status": "ok",
        "app": settings.PROJECT_NAME,
        "environment": settings.ENV,
        "version": __version__,
    }
