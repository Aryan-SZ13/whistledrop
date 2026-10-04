from datetime import datetime, timezone
import hashlib
import hmac
import logging
import secrets
from typing import Any, Dict, Optional
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.webhook import OutboxEvent

logger = logging.getLogger(__name__)


class OutboxService:
    def __init__(self) -> None:
        pass

    def derive_case_reference(self, case_code_digest: str) -> str:
        """Derives an external opaque pseudonym reference for a case code digest."""
        digest_bytes = case_code_digest.strip().encode("utf-8")
        salt_bytes = settings.WEBHOOK_SALT.encode("utf-8")
        h = hmac.new(salt_bytes, digest_bytes, hashlib.sha256).hexdigest()
        return f"ref_{h[:16]}"

    async def publish_event(
        self,
        db: AsyncSession,
        event_type: str,
        report_id: Optional[uuid.UUID] = None,
        raw_data: Optional[Dict[str, Any]] = None,
        case_code_digest: Optional[str] = None,
    ) -> OutboxEvent:
        """Publishes an event to the transactional outbox table within the caller's transaction.

        Payloads are strictly sanitized. Never exposes case codes, internal report UUIDs,
        descriptions, messages, or IP addresses.
        """
        opaque_event_id = f"evt_{secrets.token_urlsafe(24)}"
        case_reference = None
        if case_code_digest:
            case_reference = self.derive_case_reference(case_code_digest)

        data_dict: Dict[str, Any] = {}
        if case_reference:
            data_dict["case_reference"] = case_reference

        if raw_data:
            # Strictly copy only safe whitelist metadata fields
            allowed_fields = {"status", "category", "priority", "created_at", "action_type", "assigned"}
            for k, v in raw_data.items():
                if k in allowed_fields and v is not None:
                    data_dict[k] = str(v) if not isinstance(v, (int, float, bool)) else v

        payload = {
            "event_id": opaque_event_id,
            "schema_version": "1.0",
            "event_type": event_type,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": data_dict,
        }

        outbox_event = OutboxEvent(
            opaque_event_id=opaque_event_id,
            event_type=event_type,
            report_id=report_id,
            payload=payload,
            status="PENDING",
            retry_count=0,
            next_retry_at=datetime.now(timezone.utc),
        )
        db.add(outbox_event)
        await db.flush()
        return outbox_event


outbox_service = OutboxService()
