from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import logging
import random
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status
import httpx
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.webhook import OutboxEvent, WebhookDelivery, WebhookEndpoint
from app.services.ssrf_validator import resolve_and_validate_destination, validate_webhook_url

logger = logging.getLogger(__name__)


class WebhookDispatcherService:
    def __init__(self) -> None:
        pass

    def _get_kek(self) -> bytes:
        return hashlib.sha256(settings.WEBHOOK_KEK_SECRET.encode("utf-8")).digest()

    def encrypt_secret(self, secret: str) -> Tuple[bytes, bytes, bytes]:
        kek = self._get_kek()
        aesgcm = AESGCM(kek)
        iv = secrets.token_bytes(12)
        ciphertext_with_tag = aesgcm.encrypt(iv, secret.encode("utf-8"), None)
        return ciphertext_with_tag[:-16], iv, ciphertext_with_tag[-16:]

    def decrypt_secret(self, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
        kek = self._get_kek()
        aesgcm = AESGCM(kek)
        return aesgcm.decrypt(iv, ciphertext + tag, None).decode("utf-8")

    async def create_endpoint(
        self,
        db: AsyncSession,
        url: str,
        description: Optional[str],
        subscribed_events: List[str],
        created_by_id: uuid.UUID,
    ) -> Tuple[WebhookEndpoint, str]:
        """Validates SSRF safety, generates shared secret, encrypts it, and saves endpoint."""
        # SSRF pre-check
        try:
            resolve_and_validate_destination(url)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Webhook URL validation failed: {e}",
            )

        raw_secret = f"whsec_{secrets.token_urlsafe(32)}"
        cipher, iv, tag = self.encrypt_secret(raw_secret)

        endpoint = WebhookEndpoint(
            url=url,
            description=description,
            secret_encrypted=cipher,
            secret_iv=iv,
            secret_tag=tag,
            is_active=True,
            subscribed_events=subscribed_events,
            created_by_id=created_by_id,
        )
        db.add(endpoint)
        await db.commit()
        await db.refresh(endpoint)
        return endpoint, raw_secret

    async def list_endpoints(
        self,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
    ) -> List[WebhookEndpoint]:
        stmt = (
            sa.select(WebhookEndpoint)
            .order_by(WebhookEndpoint.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await db.execute(stmt)).scalars().all())

    async def get_endpoint(self, db: AsyncSession, endpoint_id: uuid.UUID) -> WebhookEndpoint:
        stmt = sa.select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint_id)
        endpoint = (await db.execute(stmt)).scalar_one_or_none()
        if not endpoint:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook endpoint not found")
        return endpoint

    async def update_endpoint(
        self,
        db: AsyncSession,
        endpoint_id: uuid.UUID,
        is_active: Optional[bool] = None,
        subscribed_events: Optional[List[str]] = None,
        description: Optional[str] = None,
    ) -> WebhookEndpoint:
        endpoint = await self.get_endpoint(db, endpoint_id)
        if is_active is not None:
            endpoint.is_active = is_active
            if not is_active:
                endpoint.disabled_at = datetime.now(timezone.utc)
            else:
                endpoint.disabled_at = None
        if subscribed_events is not None:
            endpoint.subscribed_events = subscribed_events
        if description is not None:
            endpoint.description = description
        await db.commit()
        await db.refresh(endpoint)
        return endpoint

    async def delete_endpoint(self, db: AsyncSession, endpoint_id: uuid.UUID) -> None:
        endpoint = await self.get_endpoint(db, endpoint_id)
        await db.delete(endpoint)
        await db.commit()

    async def get_deliveries(
        self,
        db: AsyncSession,
        endpoint_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> List[WebhookDelivery]:
        stmt = (
            sa.select(WebhookDelivery)
            .where(WebhookDelivery.endpoint_id == endpoint_id)
            .order_by(WebhookDelivery.delivered_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await db.execute(stmt)).scalars().all())

    def calculate_signature(self, secret: str, timestamp: int, payload_str: str) -> str:
        """Calculates HMAC-SHA256 signature over {timestamp}.{payload}."""
        signed_bytes = f"{timestamp}.{payload_str}".encode("utf-8")
        return hmac.new(secret.encode("utf-8"), signed_bytes, hashlib.sha256).hexdigest()

    async def claim_batch(self, db: AsyncSession, worker_id: str, limit: int = 50) -> List[OutboxEvent]:
        """Durable lease claim transaction: selects pending/failed/expired events and commits lease."""
        now = datetime.now(timezone.utc)
        lease_expires = now + timedelta(seconds=settings.OUTBOX_LEASE_TTL_SECONDS)

        # 1. Select with FOR UPDATE SKIP LOCKED
        claim_stmt = (
            sa.select(OutboxEvent)
            .where(
                sa.or_(
                    sa.and_(OutboxEvent.status == "PENDING", OutboxEvent.next_retry_at <= now),
                    sa.and_(OutboxEvent.status == "FAILED", OutboxEvent.next_retry_at <= now),
                    sa.and_(OutboxEvent.status == "CLAIMED", OutboxEvent.lease_expires_at <= now),
                )
            )
            .order_by(OutboxEvent.created_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        events = list((await db.execute(claim_stmt)).scalars().all())
        if not events:
            return []

        # 2. Update status to CLAIMED
        event_ids = [e.id for e in events]
        await db.execute(
            sa.update(OutboxEvent)
            .where(OutboxEvent.id.in_(event_ids))
            .values(
                status="CLAIMED",
                lease_worker_id=worker_id,
                lease_expires_at=lease_expires,
            )
        )
        # 3. Commit claim transaction BEFORE HTTP
        await db.commit()
        return events

    async def dispatch_event_to_endpoints(
        self,
        db: AsyncSession,
        event: OutboxEvent,
        client: httpx.AsyncClient,
    ) -> bool:
        """Dispatches an event to all subscribed endpoints outside DB transactions."""
        # Query active endpoints subscribed to this event_type
        endpoints_stmt = (
            sa.select(WebhookEndpoint)
            .where(WebhookEndpoint.is_active == True)
        )
        endpoints = list((await db.execute(endpoints_stmt)).scalars().all())
        matching_endpoints = [ep for ep in endpoints if event.event_type in ep.subscribed_events]

        if not matching_endpoints:
            # Nothing to dispatch to, mark dispatched
            event.status = "DISPATCHED"
            event.dispatched_at = datetime.now(timezone.utc)
            await db.commit()
            return True

        payload_str = json.dumps(event.payload, sort_keys=True, separators=(",", ":"))
        timestamp = int(datetime.now(timezone.utc).timestamp())
        all_succeeded = True
        last_error = None

        for ep in matching_endpoints:
            opaque_del_id = f"dlv_{secrets.token_urlsafe(24)}"
            secret = self.decrypt_secret(ep.secret_encrypted, ep.secret_iv, ep.secret_tag)
            sig = self.calculate_signature(secret, timestamp, payload_str)

            headers = {
                "Content-Type": "application/json",
                "X-WhistleDrop-Event-ID": event.opaque_event_id,
                "X-WhistleDrop-Delivery-ID": opaque_del_id,
                "X-WhistleDrop-Signature": f"t={timestamp},v1={sig}",
            }

            # Pre-validate SSRF and resolve
            start_time = time.time()
            status_code = None
            error_msg = None
            try:
                # SSRF validation check
                resolve_and_validate_destination(ep.url)
                # HTTP dispatch (redirects disabled)
                resp = await client.post(ep.url, content=payload_str, headers=headers)
                latency = (time.time() - start_time) * 1000.0
                status_code = resp.status_code
                if resp.is_success:
                    ep.failure_count = 0
                else:
                    all_succeeded = False
                    ep.failure_count += 1
                    error_msg = f"HTTP {status_code}: {resp.text[:200]}"
                    last_error = error_msg
            except Exception as e:
                latency = (time.time() - start_time) * 1000.0
                all_succeeded = False
                ep.failure_count += 1
                error_msg = str(e)[:450]
                last_error = error_msg

            # Record delivery attempt
            delivery = WebhookDelivery(
                outbox_event_id=event.id,
                endpoint_id=ep.id,
                opaque_delivery_id=opaque_del_id,
                attempt_number=event.retry_count + 1,
                status_code=status_code,
                latency_ms=latency,
                error_message=error_msg,
            )
            db.add(delivery)

        # Update event status
        if all_succeeded:
            event.status = "DISPATCHED"
            event.dispatched_at = datetime.now(timezone.utc)
            event.error_summary = None
        else:
            event.retry_count += 1
            if event.retry_count >= settings.OUTBOX_MAX_RETRIES:
                event.status = "DEAD_LETTER"
                event.error_summary = f"Max retries exceeded. Last error: {last_error}"
            else:
                event.status = "FAILED"
                backoff_base = 5.0
                backoff_delay = min(1800.0, backoff_base * (2 ** event.retry_count) + random.uniform(0.5, 3.0))
                event.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=backoff_delay)
                event.error_summary = last_error

        await db.commit()
        return all_succeeded


webhook_dispatcher_service = WebhookDispatcherService()
