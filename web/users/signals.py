from allauth.account.models import EmailAddress
from allauth.account.signals import email_confirmed, user_signed_up
from django.dispatch import receiver
from organizations.models import Membership


def link_pending_memberships(user):
    # Find all pending memberships with matching email
    pending_memberships = Membership.objects.filter(
        email__iexact=user.email,
        user__isnull=True,
    )

    # Link all pending memberships to the user
    for membership in pending_memberships:
        membership.user = user
        membership.email = None
        membership.save()


@receiver(email_confirmed)
def handle_email_confirmed(request, email_address, **kwargs):
    """
    Handle email confirmation and automatically link pending organization invitations.
    """
    link_pending_memberships(email_address.user)


@receiver(user_signed_up)
def handle_user_signed_up(request, user, **kwargs):
    """Link pending invitations when signing up with an already verified email."""
    if EmailAddress.objects.filter(
        user=user, email__iexact=user.email, verified=True
    ).exists():
        link_pending_memberships(user)
