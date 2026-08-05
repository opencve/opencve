from authorization.querysets import accessible_projects
from users.models import User


def get_accessible_projects_vendors(organization, user):
    """Aggregate vendor/product keys from projects the user can access."""
    unique_vendors = set()
    for subscriptions in accessible_projects(user, organization).values_list(
        "subscriptions", flat=True
    ):
        unique_vendors.update(subscriptions.get("vendors", []))
        unique_vendors.update(subscriptions.get("products", []))
    return sorted(unique_vendors)


def assignable_tracker_users(organization, project):
    """Users who may be assigned as CVE tracker assignees (explicit project roles only)."""
    from projects.models import ProjectMembership

    if organization is None or project is None:
        return User.objects.none()

    return (
        User.objects.filter(
            membership__organization=organization,
            membership__date_joined__isnull=False,
            membership__project_memberships__project=project,
            membership__project_memberships__role__in=(
                ProjectMembership.CONTRIBUTOR,
                ProjectMembership.PROJECT_ADMIN,
            ),
        )
        .distinct()
        .order_by("username")
    )
