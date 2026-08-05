from authorization.registry import RoleRegistry
from authorization.resolvers.sources import get_permission_sources
from authorization.roles import ORG_ADMIN, ORG_ADMIN_ROLES, ORG_MEMBER, ORG_OWNER
from organizations.models import Membership


def get_active_membership(user, organization):
    """Return the user's active membership in organization, or None."""
    if user is None or not user.is_authenticated or organization is None:
        return None
    return Membership.objects.filter(
        user=user,
        organization=organization,
        date_joined__isnull=False,
    ).first()


def get_org_permissions(membership) -> frozenset[str]:
    """Resolve organization-level permissions for a membership."""
    if membership is None:
        return frozenset()
    return RoleRegistry.get_org_permissions(membership.role)


def get_project_permissions(user, organization, project) -> frozenset[str]:
    """Union project permissions from all configured permission sources."""
    membership = get_active_membership(user, organization)
    result = frozenset()
    for source in get_permission_sources():
        grant = source.resolve(user, organization, project, membership)
        if grant:
            result |= grant.permissions
    return result


def can_manage_membership(actor_membership, target_membership) -> bool:
    """Whether actor can change role or remove target_membership."""
    if actor_membership is None or target_membership is None:
        return False
    if actor_membership.organization_id != target_membership.organization_id:
        return False
    if actor_membership.pk == target_membership.pk:
        return False

    actor_role = actor_membership.role
    target_role = target_membership.role

    if actor_role == ORG_OWNER:
        return True
    if actor_role == ORG_ADMIN and target_role == ORG_MEMBER:
        return True
    return False


def can_remove_membership(actor_membership, target_membership) -> bool:
    """Whether actor may remove target from the organization (UI hint)."""
    if actor_membership is None or target_membership is None:
        return False
    if actor_membership.organization_id != target_membership.organization_id:
        return False
    if actor_membership.pk == target_membership.pk:
        return True
    return can_manage_membership(actor_membership, target_membership)


def can_access_org_settings(membership) -> bool:
    """Whether member can open organization settings pages."""
    if membership is None or membership.date_joined is None:
        return False
    from authorization.permissions import ORG_MEMBERS_VIEW

    return ORG_MEMBERS_VIEW in RoleRegistry.get_org_permissions(membership.role)


def can_assign_org_role(actor_membership, role_key: str) -> bool:
    """Whether actor may assign role_key when inviting or updating org members."""
    if actor_membership is None:
        return False
    if not RoleRegistry.is_valid_org_role(role_key):
        return False
    defn = RoleRegistry.get_org_role(role_key)
    if defn.assignable_by is None:
        return False
    return defn.assignable_by(actor_membership)


def is_org_admin_or_owner(membership) -> bool:
    """Whether membership has org Owner or Admin role."""
    return membership is not None and membership.role in ORG_ADMIN_ROLES
