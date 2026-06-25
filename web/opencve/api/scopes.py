from enum import Enum

from django.conf import settings

from organizations.models import OrganizationAPIToken


class APIScope(str, Enum):
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"
    MEMBERS_READ = "members:read"
    MEMBERS_WRITE = "members:write"
    PROJECTS_READ = "projects:read"
    PROJECTS_WRITE = "projects:write"
    SUBSCRIPTIONS_WRITE = "subscriptions:write"
    TRACKER_WRITE = "tracker:write"
    COMMENTS_WRITE = "comments:write"
    NOTIFICATIONS_WRITE = "notifications:write"
    AUTOMATIONS_WRITE = "automations:write"
    REPORTS_READ = "reports:read"
    TAGS_WRITE = "tags:write"
    VIEWS_WRITE = "views:write"
    TOKENS_WRITE = "tokens:write"


READ_SCOPES = {scope for scope in APIScope if scope.value.endswith(":read")}
WRITE_SCOPES = {scope for scope in APIScope if scope.value.endswith(":write")}


def _scope_satisfied(token_scopes: list[str], required: APIScope) -> bool:
    if required.value in token_scopes:
        return True
    if required.value.endswith(":read"):
        resource = required.value.rsplit(":", 1)[0]
        return f"{resource}:write" in token_scopes
    return False


def token_has_scope(token: OrganizationAPIToken, scope: APIScope | None) -> bool:
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


def user_can_write_org(user, organization) -> bool:
    from organizations.models import Membership

    return Membership.objects.filter(
        user=user,
        organization=organization,
        role=Membership.OWNER,
        date_joined__isnull=False,
    ).exists()


def user_is_org_member(user, organization) -> bool:
    from organizations.models import Membership

    return Membership.objects.filter(
        user=user,
        organization=organization,
        date_joined__isnull=False,
    ).exists()
