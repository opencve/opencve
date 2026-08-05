import logging

from django.conf import settings
from django.utils.module_loading import import_string

from authorization.registry import RoleRegistry
from authorization.resolvers.base import ProjectPermissionGrant
from authorization.roles import ORG_ADMIN, ORG_OWNER, PROJECT_ADMIN

logger = logging.getLogger(__name__)


class OrgImplicitPermissionSource:
    """Grant Project Admin to org Owner/Admin without explicit project membership."""

    source_id = "org_implicit"

    def resolve(
        self, user, organization, project, membership
    ) -> ProjectPermissionGrant | None:
        if membership is None or not membership.date_joined:
            return None
        if membership.role not in (ORG_OWNER, ORG_ADMIN):
            return None
        permissions = RoleRegistry.get_project_permissions(PROJECT_ADMIN)
        return ProjectPermissionGrant(
            permissions=permissions,
            source=self.source_id,
            display_role=PROJECT_ADMIN,
        )


class DirectProjectMembershipSource:
    """Grant permissions from an explicit ProjectMembership row."""

    source_id = "direct_membership"

    def resolve(
        self, user, organization, project, membership
    ) -> ProjectPermissionGrant | None:
        if membership is None or not membership.date_joined:
            return None
        from projects.models import ProjectMembership

        try:
            pm = ProjectMembership.objects.select_related("membership", "project").get(
                project=project,
                membership=membership,
            )
        except ProjectMembership.DoesNotExist:
            return None

        if pm.project.organization_id != pm.membership.organization_id:
            logger.warning(
                "Inconsistent ProjectMembership pk=%s: project org %s != membership org %s",
                pm.pk,
                pm.project.organization_id,
                pm.membership.organization_id,
            )
            return None

        permissions = RoleRegistry.get_project_permissions(pm.role)
        return ProjectPermissionGrant(
            permissions=permissions,
            source=self.source_id,
            display_role=pm.role,
        )


def get_permission_sources():
    """Instantiate configured project permission sources (unioned at resolve time)."""
    source_paths = getattr(
        settings,
        "AUTHORIZATION_PROJECT_PERMISSION_SOURCES",
        [
            "authorization.resolvers.sources.OrgImplicitPermissionSource",
            "authorization.resolvers.sources.DirectProjectMembershipSource",
        ],
    )
    return [import_string(path)() for path in source_paths]
