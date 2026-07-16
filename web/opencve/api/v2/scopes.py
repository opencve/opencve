from enum import Enum

from django.conf import settings

from organizations.models import OrganizationAPIToken


SCOPE_LABELS = {
    "catalog:read": "Vulnerability catalog (read)",
    "org:read": "Organization settings (read)",
    "org:write": "Organization settings (write)",
    "members:read": "Members (read)",
    "members:write": "Members (write)",
    "audit_logs:read": "Audit logs (read)",
    "projects:read": "Projects (read)",
    "projects:write": "Projects (write)",
    "subscriptions:read": "Subscriptions (read)",
    "subscriptions:write": "Subscriptions (write)",
    "tracker:read": "CVE tracker (read)",
    "tracker:write": "CVE tracker (write)",
    "reports:read": "Reports (read)",
    "notifications:read": "Notifications (read)",
    "notifications:write": "Notifications (write)",
    "automations:read": "Automations (read)",
    "automations:write": "Automations (write)",
}


class APIScope(str, Enum):
    CATALOG_READ = "catalog:read"
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"
    MEMBERS_READ = "members:read"
    MEMBERS_WRITE = "members:write"
    AUDIT_LOGS_READ = "audit_logs:read"
    PROJECTS_READ = "projects:read"
    PROJECTS_WRITE = "projects:write"
    SUBSCRIPTIONS_READ = "subscriptions:read"
    SUBSCRIPTIONS_WRITE = "subscriptions:write"
    TRACKER_READ = "tracker:read"
    TRACKER_WRITE = "tracker:write"
    REPORTS_READ = "reports:read"
    NOTIFICATIONS_READ = "notifications:read"
    NOTIFICATIONS_WRITE = "notifications:write"
    AUTOMATIONS_READ = "automations:read"
    AUTOMATIONS_WRITE = "automations:write"


def get_available_scopes():
    """Return all supported API scopes."""
    return list(APIScope)


def get_scope_choices():
    """Return (value, label) pairs for scope selection UI."""
    return [
        (scope.value, SCOPE_LABELS.get(scope.value, scope.value)) for scope in APIScope
    ]


def normalize_token_scopes(scopes):
    """Validate and deduplicate scope strings. Raises ValueError for unknown scopes."""
    valid = {scope.value for scope in APIScope}
    normalized = []
    seen = set()

    for scope in scopes:
        if scope not in valid:
            raise ValueError(f"Unknown scope: {scope}")
        if scope not in seen:
            normalized.append(scope)
            seen.add(scope)

    return normalized


def _scope_satisfied(token_scopes: list[str], required: APIScope) -> bool:
    """Check if the token scopes satisfy the required scope"""
    if required.value in token_scopes:
        return True

    if required.value.endswith(":read"):
        resource = required.value.rsplit(":", 1)[0]
        return f"{resource}:write" in token_scopes

    return False


def token_has_scope(token: OrganizationAPIToken, scope: APIScope | None) -> bool:
    """Check whether a token grants the required scope."""
    if scope is None:
        return True

    if (
        scope.value.endswith(":write")
        and token.access_mode == OrganizationAPIToken.AccessMode.READ
    ):
        return False

    if not getattr(settings, "API_SCOPES_ENABLED", False):
        return True

    if not token.scopes:
        return True

    return _scope_satisfied(token.scopes, scope)
