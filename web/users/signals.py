from allauth.account.signals import email_confirmed
from django.dispatch import receiver
from django.conf import settings
from django.utils import timezone
from organizations.models import Membership, Organization

try:
    from django_auth_ldap.backend import populate_user

    @receiver(populate_user)
    def sync_ldap_groups_to_orgs(sender, user, ldap_user, **kwargs):
        """
        Synchronise les groupes AD vers les organisations OpenCVE après chaque auth LDAP.
        """
        mapping = getattr(settings, "LDAP_GROUP_ORG_MAPPING", {})
        if not mapping:
            return

        user_group_dns = set(ldap_user.group_dns)

        for group_dn, config in mapping.items():
            if group_dn not in user_group_dns:
                continue

            org, _ = Organization.objects.get_or_create(name=config["org"])
            membership, created = Membership.objects.get_or_create(
                user=user,
                organization=org,
                defaults={
                    "role": config["role"],
                    "date_invited": timezone.now(),
                    "date_joined": timezone.now(),
                },
            )
            if not created and membership.role != config["role"]:
                membership.role = config["role"]
                membership.save(update_fields=["role"])

except ImportError:
    pass


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
