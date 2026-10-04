from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    canary,
    health,
    moderator,
    quorum,
    reports,
    transparency,
    webhooks,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(reports.router, tags=["Reports"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(moderator.router, prefix="/moderator", tags=["Moderation"])
api_router.include_router(webhooks.router, prefix="/moderator/webhooks", tags=["Webhooks"])
api_router.include_router(quorum.router, prefix="/moderator/quorum", tags=["Quorum Governance"])
api_router.include_router(transparency.router, prefix="/transparency", tags=["Merkle Transparency Log"])
api_router.include_router(canary.router, prefix="/canary", tags=["Warrant Canary"])
