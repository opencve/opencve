from django.utils.crypto import get_random_string
from rest_framework.exceptions import ValidationError

from authorization.policies import can_assign_org_role, can_manage_membership
from authorization.registry import RoleRegistry
from authorization.roles import ORG_ADMIN, ORG_MEMBER, ORG_OWNER
from organizations.models import Membership
from organizations.utils import (
    send_organization_invitation_email,
    send_organization_signup_invitation_email,
)
from users.models import User


def generate_invitation_key():
    return get_random_string(64).lower()


def validate_org_role(role: str) -> None:
    if not role or not RoleRegistry.is_valid_org_role(role):
        raise ValidationError("Invalid role.")


def invite_member(*, organization, email, role, request=None, actor_membership=None):
    """Invite a member to an organization"""
    validate_org_role(role)
    if actor_membership and not can_assign_org_role(actor_membership, role):
        raise ValidationError("You do not have permission to assign this role.")

    email = email.strip().lower()
    user = User.objects.filter(email=email).first()

    if user:
        if organization.membership_set.filter(user=user).exists():
            raise ValidationError({"email": "Member already exist"})

        membership = Membership.objects.create(
            user=user,
            organization=organization,
            role=role,
            key=generate_invitation_key(),
        )

        if request is not None:
            send_organization_invitation_email(membership, request)

        return membership

    if organization.membership_set.filter(email=email, user__isnull=True).exists():
        raise ValidationError(
            {"email": "An invitation has already been sent to this email address"}
        )

    membership = Membership.objects.create(
        user=None,
        email=email,
        organization=organization,
        role=role,
        key=generate_invitation_key(),
    )
    if request is not None:
        send_organization_signup_invitation_email(membership, request)
    return membership


def validate_member_role_update(*, membership, role, actor_membership=None):
    """Validate role of the member"""
    validate_org_role(role)

    if actor_membership:
        if actor_membership.pk == membership.pk:
            raise ValidationError("You cannot change your own role.")
        if not can_manage_membership(actor_membership, membership):
            raise ValidationError("You do not have permission to manage this member.")
        if not can_assign_org_role(actor_membership, role):
            raise ValidationError("You do not have permission to assign this role.")

    if not membership.date_joined:
        raise ValidationError("Cannot change role for pending invitations.")

    joined_owners = membership.organization.membership_set.filter(
        role=ORG_OWNER, date_joined__isnull=False
    )
    if (
        membership.role == ORG_OWNER
        and joined_owners.count() == 1
        and role != ORG_OWNER
    ):
        raise ValidationError("You cannot demote the only owner of the organization.")


def update_member_role(*, membership, role, actor_membership=None):
    """Update the role of the member"""
    validate_member_role_update(
        membership=membership, role=role, actor_membership=actor_membership
    )
    membership.role = role
    membership.save(update_fields=["role"])
    return membership


def validate_member_removal(*, membership, actor_membership=None):
    """Validate that a membership can be removed from its organization."""
    if actor_membership:
        if actor_membership.pk == membership.pk and membership.role == ORG_OWNER:
            joined_owners = membership.organization.membership_set.filter(
                role=ORG_OWNER, date_joined__isnull=False
            )
            if joined_owners.count() == 1:
                raise ValidationError("Cannot remove the last owner.")
        if not can_manage_membership(actor_membership, membership):
            if actor_membership.pk != membership.pk:
                raise ValidationError(
                    "You do not have permission to remove this member."
                )

    joined_owners = membership.organization.membership_set.filter(
        role=ORG_OWNER, date_joined__isnull=False
    )
    if joined_owners.count() == 1 and joined_owners.first() == membership:
        raise ValidationError("Cannot remove the last owner.")


def remove_member(*, membership, actor_membership=None):
    """Remove the member from its organization"""
    validate_member_removal(membership=membership, actor_membership=actor_membership)
    membership.delete()
