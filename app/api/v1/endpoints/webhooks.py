import logging
from typing import List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.config import settings
from app.db.session import get_db
from app.models.moderator import Moderator
from app.schemas.webhook import (
    WebhookCreateRequest,
    WebhookCreateResponse,
    WebhookDeliveryResponse,
    WebhookResponse,
    WebhookTestResponse,
    WebhookUpdateRequest,
)
from app.services.outbox_service import outbox_service
from app.services.quorum_service import QuorumRequiredException
from app.services.webhook_dispatcher_service import webhook_dispatcher_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "",
    response_model=WebhookCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new webhook endpoint",
)
async def create_webhook(
    body: WebhookCreateRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> WebhookCreateResponse:
    """Registers a webhook endpoint with SSRF validation and returns the generated shared secret once."""
    endpoint, raw_secret = await webhook_dispatcher_service.create_endpoint(
        db=db,
        url=str(body.url),
        description=body.description,
        subscribed_events=body.subscribed_events,
        created_by_id=current_admin.id,
    )
    logger.info("AUDIT: Webhook endpoint registered: endpoint_id=%s by admin=%s", endpoint.id, current_admin.id)
    return WebhookCreateResponse(
        id=endpoint.id,
        url=endpoint.url,
        description=endpoint.description,
        subscribed_events=endpoint.subscribed_events,
        webhook_secret=raw_secret,
        is_active=endpoint.is_active,
        created_at=endpoint.created_at,
    )


@router.get(
    "",
    response_model=List[WebhookResponse],
    status_code=status.HTTP_200_OK,
    summary="List webhook endpoints",
)
async def list_webhooks(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> List[WebhookResponse]:
    """Lists registered webhook endpoints without exposing secrets."""
    endpoints = await webhook_dispatcher_service.list_endpoints(db=db, limit=limit, offset=offset)
    return [WebhookResponse.model_validate(ep) for ep in endpoints]


@router.get(
    "/{id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Get webhook endpoint details",
)
async def get_webhook(
    id: uuid.UUID,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    """Retrieves webhook endpoint details without exposing secrets."""
    endpoint = await webhook_dispatcher_service.get_endpoint(db, id)
    return WebhookResponse.model_validate(endpoint)


@router.patch(
    "/{id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Update webhook endpoint",
)
async def update_webhook(
    id: uuid.UUID,
    body: WebhookUpdateRequest,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    """Updates active status, subscription list, or description."""
    endpoint = await webhook_dispatcher_service.update_endpoint(
        db=db,
        endpoint_id=id,
        is_active=body.is_active,
        subscribed_events=body.subscribed_events,
        description=body.description,
    )
    logger.info("AUDIT: Webhook endpoint updated: endpoint_id=%s by admin=%s", endpoint.id, current_admin.id)
    return WebhookResponse.model_validate(endpoint)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete webhook endpoint",
)
async def delete_webhook(
    id: uuid.UUID,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Deletes a webhook endpoint. If dual control is enforced, requires quorum approval."""
    if settings.QUORUM_ENFORCE_WEBHOOK_DELETE:
        raise QuorumRequiredException(
            action_type="WEBHOOK_ENDPOINT_DELETE",
            target_id=str(id),
            details={"message": "Deletion of webhook endpoints requires quorum approval"},
        )
    await webhook_dispatcher_service.delete_endpoint(db, id)
    logger.info("AUDIT: Webhook endpoint deleted: endpoint_id=%s by admin=%s", id, current_admin.id)


@router.post(
    "/{id}/test",
    response_model=WebhookTestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Dispatch a synthetic test event to webhook",
)
async def test_webhook(
    id: uuid.UUID,
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> WebhookTestResponse:
    """Enqueues a test event for the specified webhook endpoint."""
    endpoint = await webhook_dispatcher_service.get_endpoint(db, id)
    event = await outbox_service.publish_event(
        db=db,
        event_type=endpoint.subscribed_events[0] if endpoint.subscribed_events else "report.created",
        raw_data={"test": True, "endpoint_id": str(endpoint.id)},
    )
    await db.commit()
    return WebhookTestResponse(
        status="test_event_queued",
        opaque_event_id=event.opaque_event_id,
    )


@router.get(
    "/{id}/deliveries",
    response_model=List[WebhookDeliveryResponse],
    status_code=status.HTTP_200_OK,
    summary="Get delivery logs for webhook endpoint",
)
async def get_webhook_deliveries(
    id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_admin: Moderator = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> List[WebhookDeliveryResponse]:
    """Retrieves delivery attempt history for an endpoint."""
    deliveries = await webhook_dispatcher_service.get_deliveries(
        db=db,
        endpoint_id=id,
        limit=limit,
        offset=offset,
    )
    return [WebhookDeliveryResponse.model_validate(d) for d in deliveries]
