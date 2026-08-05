from rest_framework.exceptions import ValidationError

from authorization.policies import get_active_membership
from authorization.registry import RoleRegistry
from authorization.roles import PROJECT_CONTRIBUTOR
from projects.models import ProjectMembership


def validate_project_membership_coherence(*, project, membership) -> None:
    if project.organization_id != membership.organization_id:
        raise ValidationError(
            {"membership": "Membership does not belong to the project's organization."}
        )


def validate_project_role(role: str) -> None:
    if not role or not RoleRegistry.is_valid_project_role(role):
        raise ValidationError({"role": "Invalid project role."})


def add_project_member(*, project, membership, role, actor_user, actor_organization):
    validate_project_membership_coherence(project=project, membership=membership)
    validate_project_role(role)

    actor_membership = get_active_membership(actor_user, actor_organization)
    from authorization.context import AuthorizationContext

    ctx = AuthorizationContext(actor_user, actor_organization)
    if not ctx.has_project_permission(project, "project.members.manage"):
        raise ValidationError("You do not have permission to manage project members.")

    if ProjectMembership.objects.filter(
        project=project, membership=membership
    ).exists():
        raise ValidationError(
            {"membership": "Member already assigned to this project."}
        )

    pm = ProjectMembership(project=project, membership=membership, role=role)
    pm.full_clean()
    pm.save()
    return pm


def update_project_member_role(
    *, project_membership, role, actor_user, actor_organization
):
    validate_project_role(role)
    project = project_membership.project
    membership = project_membership.membership

    actor_membership = get_active_membership(actor_user, actor_organization)
    from authorization.context import AuthorizationContext

    ctx = AuthorizationContext(actor_user, actor_organization)
    if not ctx.has_project_permission(project, "project.members.manage"):
        raise ValidationError("You do not have permission to manage project members.")

    if actor_membership and actor_membership.pk == membership.pk:
        raise ValidationError("You cannot change your own project role.")

    project_membership.role = role
    project_membership.full_clean()
    project_membership.save(update_fields=["role"])
    return project_membership


def remove_project_member(*, project_membership, actor_user, actor_organization):
    project = project_membership.project
    membership = project_membership.membership

    from authorization.context import AuthorizationContext

    ctx = AuthorizationContext(actor_user, actor_organization)
    if not ctx.has_project_permission(project, "project.members.manage"):
        raise ValidationError("You do not have permission to manage project members.")

    actor_membership = get_active_membership(actor_user, actor_organization)
    if actor_membership and actor_membership.pk == membership.pk:
        raise ValidationError("You cannot remove yourself from the project this way.")

    project_membership.delete()


def get_default_project_role_for_new_member():
    return PROJECT_CONTRIBUTOR
