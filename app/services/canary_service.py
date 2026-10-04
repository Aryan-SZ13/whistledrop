from datetime import datetime, timedelta, timezone
import hashlib
import logging
from typing import List, Optional, Tuple
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException, status
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.security_state import SystemSecurityState, WarrantCanary

logger = logging.getLogger(__name__)


class CanaryService:
    """Service managing Cryptographic Warrant Canaries, Dead-Man's Switch & Emergency Access Sealing."""

    def __init__(self) -> None:
        self.signing_key_id = settings.CANARY_SIGNING_KEY_ID

    def _get_signing_key(self) -> ed25519.Ed25519PrivateKey:
        raw_key = settings.CANARY_SIGNING_KEY_ED25519_PRIVATE
        try:
            seed = bytes.fromhex(raw_key)
        except ValueError:
            seed = raw_key.encode("utf-8")[:32].ljust(32, b"\x00")
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    def get_public_key_fingerprint(self) -> str:
        priv = self._get_signing_key()
        pub_bytes = priv.public_key().public_bytes_raw()
        return f"SHA256:{hashlib.sha256(pub_bytes).hexdigest()}"

    async def get_or_create_security_state(self, db: AsyncSession) -> SystemSecurityState:
        """Retrieves singleton security state row, initializing if missing."""
        stmt = sa.select(SystemSecurityState).where(SystemSecurityState.id == 1)
        res = (await db.execute(stmt)).scalar_one_or_none()
        if res is None:
            now = datetime.now(timezone.utc)
            res = SystemSecurityState(
                id=1,
                is_sealed=False,
                dead_man_due_at=now + timedelta(days=settings.DEAD_MAN_INTERVAL_DAYS),
                last_check_in_at=now,
            )
            db.add(res)
            await db.flush()
        return res

    async def is_system_sealed(self, db: AsyncSession) -> bool:
        """Authoritatively checks whether the platform is in Emergency Sealed mode."""
        state = await self.get_or_create_security_state(db)
        return bool(state.is_sealed)

    async def get_latest_canary(self, db: AsyncSession) -> Optional[WarrantCanary]:
        """Returns the most recent warrant canary statement."""
        stmt = sa.select(WarrantCanary).order_by(WarrantCanary.canary_sequence.desc()).limit(1)
        return (await db.execute(stmt)).scalar_one_or_none()

    async def get_canary_history(
        self,
        db: AsyncSession,
        limit: int = 20,
        offset: int = 0,
    ) -> List[WarrantCanary]:
        """Returns paginated historical warrant canary statements."""
        stmt = (
            sa.select(WarrantCanary)
            .order_by(WarrantCanary.canary_sequence.desc())
            .limit(limit)
            .offset(offset)
        )
        return list((await db.execute(stmt)).scalars().all())

    async def publish_canary(
        self,
        db: AsyncSession,
        admin_id: uuid.UUID,
        statement_text: str,
        validity_days: int = 30,
    ) -> WarrantCanary:
        """Publishes a signed warrant canary statement directly by authorized admin."""
        now = datetime.now(timezone.utc)
        stmt_seq = sa.select(sa.func.coalesce(sa.func.max(WarrantCanary.canary_sequence), 0))
        current_max = (await db.execute(stmt_seq)).scalar_one()
        next_seq = current_max + 1

        statement_hash = hashlib.sha256(statement_text.encode("utf-8")).hexdigest()
        priv_key = self._get_signing_key()
        sig_bytes = priv_key.sign(bytes.fromhex(statement_hash))
        sig_hex = sig_bytes.hex()

        valid_until = now + timedelta(days=validity_days)

        canary = WarrantCanary(
            canary_sequence=next_seq,
            statement_hash=statement_hash,
            statement_text=statement_text,
            valid_from=now,
            valid_until=valid_until,
            published_at=now,
            signature=sig_hex,
            signing_key_id=self.signing_key_id,
            first_approved_by_id=admin_id,
        )
        db.add(canary)
        await db.flush()

        from app.services.outbox_service import outbox_service
        await outbox_service.publish_event(
            db=db,
            event_type="canary.refreshed",
            raw_data={
                "canary_sequence": next_seq,
                "statement_hash": statement_hash,
                "valid_until": valid_until.isoformat(),
            },
        )
        return canary

    async def execute_canary_publish(
        self,
        db: AsyncSession,
        statement_text: str,
        proposer_id: uuid.UUID,
        approver_id: uuid.UUID,
        quorum_request_id: uuid.UUID,
    ) -> WarrantCanary:
        """Executes publication of a signed warrant canary after Quorum approval."""
        if proposer_id == approver_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Proposer and approver must be distinct administrators",
            )

        now = datetime.now(timezone.utc)
        stmt_seq = sa.select(sa.func.coalesce(sa.func.max(WarrantCanary.canary_sequence), 0))
        current_max = (await db.execute(stmt_seq)).scalar_one()
        next_seq = current_max + 1

        statement_hash = hashlib.sha256(statement_text.encode("utf-8")).hexdigest()
        priv_key = self._get_signing_key()
        sig_bytes = priv_key.sign(bytes.fromhex(statement_hash))
        sig_hex = sig_bytes.hex()

        valid_until = now + timedelta(days=settings.CANARY_VALIDITY_DAYS)

        canary = WarrantCanary(
            canary_sequence=next_seq,
            statement_hash=statement_hash,
            statement_text=statement_text,
            valid_from=now,
            valid_until=valid_until,
            published_at=now,
            signature=sig_hex,
            signing_key_id=self.signing_key_id,
            first_approved_by_id=proposer_id,
            second_approved_by_id=approver_id,
            quorum_request_id=quorum_request_id,
        )
        db.add(canary)
        await db.flush()

        from app.services.outbox_service import outbox_service
        await outbox_service.publish_event(
            db=db,
            event_type="canary.refreshed",
            raw_data={
                "canary_sequence": next_seq,
                "statement_hash": statement_hash,
                "valid_until": valid_until.isoformat(),
            },
        )
        return canary

    async def admin_check_in(
        self,
        db: AsyncSession,
        admin_id: uuid.UUID,
    ) -> datetime:
        """Performs Dead-Man's Switch administrator check-in, pushing due date forward."""
        stmt = sa.select(SystemSecurityState).where(SystemSecurityState.id == 1).with_for_update()
        state = (await db.execute(stmt)).scalar_one_or_none()
        if state is None:
            state = await self.get_or_create_security_state(db)

        now = datetime.now(timezone.utc)
        next_due = now + timedelta(days=settings.DEAD_MAN_INTERVAL_DAYS)
        state.dead_man_due_at = next_due
        state.last_check_in_at = now
        state.last_check_in_by_id = admin_id
        await db.commit()
        return next_due

    async def execute_emergency_seal(
        self,
        db: AsyncSession,
        initiator_id: uuid.UUID,
        reason: str,
    ) -> SystemSecurityState:
        """Executes emergency sealing, disabling operator plaintext decryption."""
        stmt = sa.select(SystemSecurityState).where(SystemSecurityState.id == 1).with_for_update()
        state = (await db.execute(stmt)).scalar_one_or_none()
        if state is None:
            state = await self.get_or_create_security_state(db)

        now = datetime.now(timezone.utc)
        state.is_sealed = True
        state.sealed_at = now
        state.sealed_by_id = initiator_id
        state.seal_reason = reason
        await db.flush()

        from app.services.outbox_service import outbox_service
        await outbox_service.publish_event(
            db=db,
            event_type="emergency.sealed",
            raw_data={"sealed_at": now.isoformat(), "reason": reason[:200]},
        )
        return state

    async def execute_emergency_unseal(
        self,
        db: AsyncSession,
        approver_id: uuid.UUID,
    ) -> SystemSecurityState:
        """Restores normal operations from emergency sealed state after Quorum approval."""
        stmt = sa.select(SystemSecurityState).where(SystemSecurityState.id == 1).with_for_update()
        state = (await db.execute(stmt)).scalar_one_or_none()
        if state is None:
            state = await self.get_or_create_security_state(db)

        state.is_sealed = False
        state.sealed_at = None
        state.sealed_by_id = None
        state.seal_reason = None
        await db.flush()

        from app.services.outbox_service import outbox_service
        await outbox_service.publish_event(
            db=db,
            event_type="emergency.unsealed",
            raw_data={"unsealed_at": datetime.now(timezone.utc).isoformat()},
        )
        return state

    def verify_canary_signature_standalone(
        self,
        statement_text: str,
        signature_hex: str,
        public_key_bytes: bytes,
    ) -> bool:
        """Standalone verification of an Ed25519 signature on a canary statement."""
        statement_hash = hashlib.sha256(statement_text.encode("utf-8")).digest()
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        try:
            pub_key.verify(bytes.fromhex(signature_hex), statement_hash)
            return True
        except Exception:
            return False


canary_service = CanaryService()
