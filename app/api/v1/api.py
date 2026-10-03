from fastapi import APIRouter
from app.api.v1.endpoints import auth, health, reports

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(reports.router, tags=["Reports"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

