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


class ReportUpdateType(str, enum.Enum):
    """Visibility types for updates posted to a report."""
    PUBLIC_UPDATE = "PUBLIC_UPDATE"
    INTERNAL_NOTE = "INTERNAL_NOTE"


class ModeratorRole(str, enum.Enum):
    """Roles and authorization tiers for moderators."""
    MODERATOR = "MODERATOR"
    ADMIN = "ADMIN"

