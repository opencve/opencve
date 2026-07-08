from django.utils.crypto import get_random_string
from rest_framework.exceptions import ValidationError

from organizations.models import Membership
from organizations.utils import (
    send_organization_invitation_email,
    send_organization_signup_invitation_email,
)
from users.models import User


def generate_invitation_key():
    return get_random_string(64).lower()


def invite_member(*, organization, email, role, request=None):
    """Invite a member to an organization"""
    email = email.strip().lower()
    user = User.objects.filter(email=email).first()

    if user:

        # Check if the user is already a member of the organization
        if organization.membership_set.filter(user=user).exists():
            raise ValidationError({"email": "Member already exist"})

        # Create a membership for the existing user
        membership = Membership.objects.create(
            user=user,
            organization=organization,
            role=role,
            key=generate_invitation_key(),
        )

        if request is not None:
            send_organization_invitation_email(membership, request)

        return membership

    # Check if an invitation has already been sent to this email address
    if organization.membership_set.filter(email=email, user__isnull=True).exists():
        raise ValidationError(
            {"email": "An invitation has already been sent to this email address"}
        )

    # Create a membership for the email address
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


def validate_member_role_update(*, membership, role):
    """Validate role of the nmember"""
    if not role:
        raise ValidationError("Role is required.")

    # Validate the role value
    valid_roles = {choice[0] for choice in Membership.ROLES}
    if role not in valid_roles:
        raise ValidationError("Invalid role.")

    # Check if the membership is pending
    if not membership.date_joined:
        raise ValidationError("Cannot change role for pending invitations.")

    # Check if the membership is the only remaining owner
    owners = membership.organization.membership_set.filter(
        role=Membership.OWNER, date_joined__isnull=False
    )
    if (
        membership.role == Membership.OWNER
        and owners.count() == 1
        and role == Membership.MEMBER
    ):
        raise ValidationError("You cannot demote the only owner of the organization.")


def update_member_role(*, membership, role):
    """Update the role of the member"""
    validate_member_role_update(membership=membership, role=role)
    membership.role = role
    membership.save(update_fields=["role"])
    return membership


def validate_member_removal(*, membership):
    """Validate that a membership can be removed from its organization."""
    joined_owners = membership.organization.membership_set.filter(
        role=Membership.OWNER, date_joined__isnull=False
    )
    if joined_owners.count() == 1 and joined_owners.first() == membership:
        raise ValidationError("Cannot remove the last owner.")


def remove_member(*, membership):
    """Remove the member from its organization"""
    validate_member_removal(membership=membership)
    membership.delete()
