from django.conf import settings
from django.db.models import QuerySet
from django.utils.module_loading import import_string

from authorization.policies import get_active_membership, is_org_admin_or_owner
from authorization.roles import PROJECT_ADMIN
from projects.models import Project


def accessible_projects(user, organization) -> QuerySet[Project]:
    """Projects visible to user: all org projects for admin/owner, else explicit memberships."""
    if user is None or not user.is_authenticated or organization is None:
        return Project.objects.none()

    membership = get_active_membership(user, organization)
    if membership is None:
        return Project.objects.none()

    base_qs = Project.objects.filter(organization=organization)

    if is_org_admin_or_owner(membership):
        qs = base_qs
    else:
        qs = base_qs.filter(
            memberships__membership=membership,
            memberships__membership__date_joined__isnull=False,
        ).distinct()

    for ext_path in getattr(
        settings, "AUTHORIZATION_ACCESSIBLE_PROJECTS_QUERYSET_EXTENSIONS", []
    ):
        ext = import_string(ext_path)
        qs = ext(user, organization, qs)

    return qs.order_by("name")


def subscription_manageable_projects(user, organization) -> QuerySet[Project]:
    """Active projects where the user may manage vendor/product subscriptions."""
    if user is None or not user.is_authenticated or organization is None:
        return Project.objects.none()

    membership = get_active_membership(user, organization)
    if membership is None:
        return Project.objects.none()

    base_qs = Project.objects.filter(organization=organization, active=True)

    if is_org_admin_or_owner(membership):
        return base_qs.order_by("name")

    return (
        base_qs.filter(
            memberships__membership=membership,
            memberships__membership__date_joined__isnull=False,
            memberships__role=PROJECT_ADMIN,
        )
        .distinct()
        .order_by("name")
    )


def get_project_for_user(user, organization, project_name):
    """Return project if user has access, else None (used as 404 gate in views)."""
    try:
        project = Project.objects.get(organization=organization, name=project_name)
    except Project.DoesNotExist:
        return None
    if not accessible_projects(user, organization).filter(pk=project.pk).exists():
        return None
    return project
