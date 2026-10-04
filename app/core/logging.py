import contextvars
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, Optional

# Context variable for propagating correlation ID across async tasks
current_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_request_id", default=None
)

# Defense-in-depth redaction regexes
CASE_CODE_REGEX = re.compile(r"wdc_[A-Za-z0-9_-]{20,}")
BEARER_TOKEN_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", re.IGNORECASE)


class RequestIDFilter(logging.Filter):
    """Injects current_request_id from contextvars into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        rid = current_request_id.get()
        record.request_id = rid if rid else None
        return True


class RegexRedactionFilter(logging.Filter):
    """Defense-in-depth safety filter that redacts accidental sensitive patterns."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            if "wdc_" in msg:
                msg = CASE_CODE_REGEX.sub("[REDACTED_CASE_CODE]", msg)
            if "Bearer " in msg or "bearer " in msg:
                msg = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", msg)
            record.msg = msg

        context = getattr(record, "context", None)
        if isinstance(context, dict):
            for k, v in list(context.items()):
                if isinstance(v, str):
                    if "wdc_" in v:
                        context[k] = CASE_CODE_REGEX.sub("[REDACTED_CASE_CODE]", v)
                    if "Bearer " in v or "bearer " in v:
                        context[k] = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", v)
        return True



class StructuredJsonFormatter(logging.Formatter):
    """Allowlist-oriented JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include request ID if bound
        request_id = getattr(record, "request_id", None) or current_request_id.get()
        if request_id:
            log_entry["request_id"] = request_id

        # Include structured context if attached to record
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            log_entry["context"] = context

        # Safe exception logging
        if record.exc_info and record.exc_info[0]:
            log_entry["exception_type"] = record.exc_info[0].__name__

        return json.dumps(log_entry, default=str)


def setup_logging(level: str = "INFO", json_format: bool = True) -> None:
    """Configure root and application loggers."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())

    # Clear existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(StructuredJsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(name)s: %(message)s"))

    handler.addFilter(RequestIDFilter())
    handler.addFilter(RegexRedactionFilter())
    root_logger.addHandler(handler)
