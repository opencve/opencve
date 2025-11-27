from allauth.account.signals import email_confirmed
from django.dispatch import receiver
from organizations.models import Membership


@receiver(email_confirmed)
def handle_email_confirmed(request, email_address, **kwargs):
    """
    Handle email confirmation and automatically link pending organization invitations.
    """
    user = email_address.user

    # Find all pending memberships with matching email
    pending_memberships = Membership.objects.filter(
        email=user.email,
        user__isnull=True,
    )

    # Link all pending memberships to the user
    for membership in pending_memberships:
        membership.user = user
        membership.email = None
        membership.save()
