import pytest
from pydantic import ValidationError

from app.core.config import Settings


def get_valid_settings_dict():
    """Return a baseline dictionary of valid configuration values."""
    return {
        "JWT_SECRET": "a" * 32,
        "CASE_CODE_SECRET": "b" * 32,
        "RATE_LIMIT_KEY_SECRET": "c" * 32,
        "ENV": "development",
        "DEBUG": True,
    }


def test_evidence_config_valid_defaults():
    """Default Phase 8 evidence and ClamAV configuration values must pass validation."""
    data = get_valid_settings_dict()
    s = Settings(**data)
    assert s.MAX_ATTACHMENT_SIZE_MB == 10
    assert s.MAX_ATTACHMENTS_PER_REPORT == 5
    assert s.MAX_TOTAL_ATTACHMENT_BYTES == 26214400
    assert s.MIN_FREE_STORAGE_MB == 1024
    assert s.CLAMAV_PORT == 3310
    assert s.CLAMAV_SCAN_TIMEOUT == 30
    assert s.PENDING_SCAN_MAX_AGE_HOURS == 24
    assert s.QUARANTINE_RETENTION_HOURS == 72
    assert s.RECONCILIATION_INTERVAL_MINUTES == 60
    assert s.ATTACHMENT_UPLOAD_RATE_LIMIT == 10
    assert s.ATTACHMENT_UPLOAD_RATE_WINDOW_SECONDS == 300


@pytest.mark.parametrize(
    "field,invalid_val",
    [
        ("MAX_ATTACHMENT_SIZE_MB", 0),
        ("MAX_ATTACHMENT_SIZE_MB", -1),
        ("MAX_ATTACHMENTS_PER_REPORT", 0),
        ("MAX_ATTACHMENTS_PER_REPORT", -5),
        ("MIN_FREE_STORAGE_MB", 0),
        ("MIN_FREE_STORAGE_MB", -10),
        ("CLAMAV_SCAN_TIMEOUT", 0),
        ("CLAMAV_SCAN_TIMEOUT", -1),
        ("PENDING_SCAN_MAX_AGE_HOURS", 0),
        ("QUARANTINE_RETENTION_HOURS", 0),
        ("RECONCILIATION_INTERVAL_MINUTES", 0),
        ("ATTACHMENT_UPLOAD_RATE_LIMIT", 0),
        ("ATTACHMENT_UPLOAD_RATE_WINDOW_SECONDS", 0),
        ("MAX_TOTAL_ATTACHMENT_BYTES", 1000),  # Under 1 MiB
        ("CLAMAV_PORT", 0),
        ("CLAMAV_PORT", 70000),
    ],
)
def test_evidence_config_invalid_bounds_rejected(field, invalid_val):
    """Zero, negative, or out-of-range configuration values must be rejected."""
    data = get_valid_settings_dict()
    data[field] = invalid_val
    with pytest.raises(ValidationError):
        Settings(**data)


def test_evidence_config_per_file_exceeds_total_rejected():
    """MAX_ATTACHMENT_SIZE_MB in bytes cannot exceed MAX_TOTAL_ATTACHMENT_BYTES."""
    data = get_valid_settings_dict()
    data["MAX_ATTACHMENT_SIZE_MB"] = 30  # 30 MiB
    data["MAX_TOTAL_ATTACHMENT_BYTES"] = 20 * 1024 * 1024  # 20 MiB
    with pytest.raises(ValidationError, match="MAX_ATTACHMENT_SIZE_MB in bytes cannot exceed MAX_TOTAL_ATTACHMENT_BYTES"):
        Settings(**data)
