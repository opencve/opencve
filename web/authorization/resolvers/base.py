from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProjectPermissionGrant:
    """Permissions granted by one project permission source."""

    permissions: frozenset[str]
    source: str
    display_role: Optional[str] = None
