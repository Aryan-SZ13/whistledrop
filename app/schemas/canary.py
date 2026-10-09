from datetime import datetime
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class CanaryResponse(BaseModel):
    canary_sequence: int = Field(..., description="Monotonically increasing sequence number")
    statement_text: str = Field(..., description="Exact statement text signed by administrators")
    statement_hash: str = Field(..., description="SHA-256 digest of statement text")
    valid_from: datetime = Field(..., description="Statement validity start timestamp")
    valid_until: datetime = Field(..., description="Statement validity expiration timestamp")
    published_at: datetime = Field(..., description="Statement publication timestamp")
    is_current: bool = Field(..., description="True if valid_until is strictly in the future")
    signature: str = Field(..., description="Ed25519 digital signature over statement_hash")
    signing_key_id: str = Field(..., description="Identifier of the canary signing key")

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_canary(cls, c: Any, now: Optional[datetime] = None) -> "CanaryResponse":
        if now is None:
            from datetime import timezone
            now = datetime.now(timezone.utc)
        return cls(
            canary_sequence=c.canary_sequence,
            statement_text=c.statement_text,
            statement_hash=c.statement_hash,
            valid_from=c.valid_from,
            valid_until=c.valid_until,
            published_at=c.published_at,
            is_current=now <= c.valid_until,
            signature=c.signature,
            signing_key_id=c.signing_key_id,
        )


class CanaryCreateRequest(BaseModel):
    statement_text: str = Field(..., min_length=20, max_length=5000, description="Full canary statement text")


class AdminCheckInRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, description="Fresh 6-digit TOTP code")


class EmergencySealRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=500, description="Justification for emergency sealing")


class EmergencyUnsealRequest(BaseModel):
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6, description="Fresh 6-digit TOTP code verifying administrator identity")


class SecurityStateResponse(BaseModel):
    is_sealed: bool = Field(..., description="Whether platform is in emergency sealed mode")
    sealed_at: Optional[datetime] = Field(None, description="Timestamp of seal activation")
    seal_reason: Optional[str] = Field(None, description="Operator reason for sealing")
    dead_man_due_at: datetime = Field(..., description="Timestamp when next administrator check-in is due")
    last_check_in_at: datetime = Field(..., description="Timestamp of last successful check-in")

    model_config = ConfigDict(from_attributes=True)
