from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReportVerificationReceiptResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    status: str
    terminal_at: Optional[datetime] = None
    is_shredded: bool = False
    shredded_at: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None
    audit_sequence_number: int
    latest_entry_hash: str
    signing_key_id: str
    verification_receipt_signature: str
    verification_instructions: str


class ReportWithdrawRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Optional[str] = Field(default=None, max_length=500)
    confirm: bool = Field(default=True)


class ReportWithdrawResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    message: str
    withdrawn_at: datetime
    status: str
    terminal_at: datetime
    evidence_shred_status: str
    latest_audit_hash: str


class AuditChainVerifyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    is_valid: bool
    total_entries: int
    broken_sequence_number: Optional[int] = None
    error_detail: Optional[str] = None
    latest_entry_hash: Optional[str] = None


class RetentionPreviewItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_id: str
    status: str
    terminal_at: datetime
    days_past_terminal: float
    evidence_count: int


class RetentionPreviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    eligible_count: int
    reports: List[RetentionPreviewItem]


class RetentionExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: Optional[int] = Field(default=None, ge=1, le=1000)
    force: Optional[bool] = False


class RetentionExecuteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    processed_count: int
    shredded_evidence_count: int
    failed_count: int
    lock_acquired: bool
    details: List[Dict[str, Any]] = Field(default_factory=list)
