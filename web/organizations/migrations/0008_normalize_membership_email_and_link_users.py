# Generated manually

from django.db import migrations


def normalize_email_and_link_users(apps, schema_editor):
    """
    For memberships with a non-normalized email (e.g. containing uppercase):
    - Normalize the email to lowercase.
    - If a user exists with that normalized email, link the membership to that user.
    """
    Membership = apps.get_model("organizations", "Membership")
    User = apps.get_model("users", "User")

    # Memberships with an email and no user yet (pending invitation)
    pending = Membership.objects.filter(email__isnull=False, user__isnull=True)

    for membership in pending:
        if membership.email != membership.email.lower():
            normalized_email = membership.email.strip().lower()
            membership.email = normalized_email
            membership.save(update_fields=["email"])

            try:
                user = User.objects.get(email__iexact=normalized_email)
            except User.DoesNotExist:
                continue

            membership.user = user
            membership.email = None
            membership.save(update_fields=["user", "email"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0007_cleanup_auditlog_organizationapitoken"),
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(normalize_email_and_link_users, noop),
    ]
