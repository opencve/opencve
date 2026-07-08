from enum import Enum

from django.conf import settings

from organizations.models import OrganizationAPIToken


SCOPE_LABELS = {
    "org:read": "Organization (read)",
    "org:write": "Organization (write)",
    "members:read": "Members (read)",
    "members:write": "Members (write)",
    "projects:read": "Projects (read)",
    "projects:write": "Projects (write)",
    "subscriptions:write": "Subscriptions (write)",
    "tracker:write": "CVE tracker (write)",
    "notifications:write": "Notifications (write)",
    "automations:write": "Automations (write)",
    "reports:read": "Reports (read)",
    "tags:write": "Tags (write)",
    "views:write": "Saved views (write)",
    "tokens:write": "API tokens (write)",
}


class APIScope(str, Enum):
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"
    MEMBERS_READ = "members:read"
    MEMBERS_WRITE = "members:write"
    PROJECTS_READ = "projects:read"
    PROJECTS_WRITE = "projects:write"
    SUBSCRIPTIONS_WRITE = "subscriptions:write"
    TRACKER_WRITE = "tracker:write"
    NOTIFICATIONS_WRITE = "notifications:write"
    AUTOMATIONS_WRITE = "automations:write"
    REPORTS_READ = "reports:read"
    TAGS_WRITE = "tags:write"
    VIEWS_WRITE = "views:write"
    TOKENS_WRITE = "tokens:write"


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
