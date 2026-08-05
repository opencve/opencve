from django import template

from authorization.context import get_authorization_context
from authorization.policies import (
    can_access_org_settings,
    can_manage_membership,
    can_remove_membership,
)
from authorization.registry import RoleRegistry

register = template.Library()


@register.simple_tag(takes_context=True)
def has_org_permission(context, permission):
    """Template tag: True when the user has an organization permission."""
    request = context.get("request")
    if not request or not request.user.is_authenticated:
        return False
    return get_authorization_context(request).has_org_permission(permission)


@register.simple_tag(takes_context=True)
def has_project_permission(context, project, permission):
    """Template tag: True when the user has a permission on the given project."""
    request = context.get("request")
    if not request or not request.user.is_authenticated or project is None:
        return False
    return get_authorization_context(request).has_project_permission(
        project, permission
    )


@register.simple_tag
def org_role_label(role_key):
    if not RoleRegistry.is_valid_org_role(role_key):
        return role_key
    return RoleRegistry.get_org_role(role_key).label


@register.simple_tag
def can_edit_org_member_role(actor_membership, target_membership, org_role_choices):
    if not org_role_choices or len(org_role_choices) <= 1:
        return False
    return can_manage_membership(actor_membership, target_membership)


@register.simple_tag
def can_remove_org_member(actor_membership, target_membership):
    return can_remove_membership(actor_membership, target_membership)


@register.simple_tag
def membership_can_access_org_settings(membership):
    return can_access_org_settings(membership)
