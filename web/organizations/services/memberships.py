import secrets

from rest_framework.exceptions import ValidationError

from organizations.models import Membership


def generate_invitation_key():
    return secrets.token_urlsafe(24)[:32]


def invite_member(*, organization, email, role):
    if organization.membership_set.filter(email=email).exists():
        raise ValidationError({"email": "This member is already invited."})
    return Membership.objects.create(
        organization=organization,
        email=email,
        role=role,
        key=generate_invitation_key(),
    )


def update_member_role(*, membership, role):
    membership.role = role
    membership.save(update_fields=["role", "updated_at"])
    return membership


def remove_member(*, membership):
    if (
        membership.is_owner
        and membership.organization.membership_set.filter(
            role=Membership.OWNER, date_joined__isnull=False
        ).count()
        <= 1
    ):
        raise ValidationError("Cannot remove the last owner.")
    membership.delete()
