import enum


class ReportCategory(str, enum.Enum):
    """Categorization for submitted whistleblower reports."""
    SECURITY = "SECURITY"
    HARASSMENT = "HARASSMENT"
    CORRUPTION = "CORRUPTION"
    TECHNICAL = "TECHNICAL"
    OTHER = "OTHER"


class ReportStatus(str, enum.Enum):
    """Lifecycle statuses for whistleblower reports."""
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class ReportPriority(str, enum.Enum):
    """Severity and urgency classification for whistleblower reports."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReportUpdateType(str, enum.Enum):
    """Visibility types for updates posted to a report."""
    PUBLIC_UPDATE = "PUBLIC_UPDATE"
    INTERNAL_NOTE = "INTERNAL_NOTE"


class ModeratorRole(str, enum.Enum):
    """Roles and authorization tiers for moderators."""
    MODERATOR = "MODERATOR"
    ADMIN = "ADMIN"


class EvidenceScanStatus(str, enum.Enum):
    """Lifecycle and scanning statuses for report evidence attachments."""
    PENDING_SCAN = "PENDING_SCAN"
    SCAN_CLEAN = "SCAN_CLEAN"
    PROMOTING = "PROMOTING"
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    SCAN_FAILED = "SCAN_FAILED"
    DELETED = "DELETED"


class MessageSenderType(str, enum.Enum):
    """Sender classification for case messages."""
    REPORTER = "REPORTER"
    MODERATOR = "MODERATOR"
