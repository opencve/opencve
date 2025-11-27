from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.urls import reverse


def send_organization_invitation_email(membership, request):
    """
    Send an invitation email to an existing user to join an organization.
    """
    organizations_url = request.build_absolute_uri(reverse("list_organizations"))

    context = {
        "organization": membership.organization,
        "organizations_url": organizations_url,
        "user": membership.user,
    }

    subject = f"{settings.ACCOUNT_EMAIL_SUBJECT_PREFIX}Invitation to join {membership.organization.name}"

    # Send text version of the email
    text_content = render_to_string(
        "organizations/emails/invitation_existing_user.txt", context
    )
    msg = EmailMessage(
        subject=subject,
        body=text_content,
        from_email=(
            settings.DEFAULT_FROM_EMAIL
            if hasattr(settings, "DEFAULT_FROM_EMAIL")
            else None
        ),
        to=[membership.user.email],
    )
    msg.send()


def send_organization_signup_invitation_email(membership, request):
    """
    Send an invitation email to a new user to sign up and join an organization.
    """
    signup_url = request.build_absolute_uri(reverse("account_signup"))

    context = {
        "organization": membership.organization,
        "signup_url": signup_url,
        "email": membership.email,
    }

    subject = f"{settings.ACCOUNT_EMAIL_SUBJECT_PREFIX}Invitation to join {membership.organization.name} on OpenCVE"

    # Send text version of the email
    text_content = render_to_string(
        "organizations/emails/invitation_new_user.txt", context
    )
    msg = EmailMessage(
        subject=subject,
        body=text_content,
        from_email=(
            settings.DEFAULT_FROM_EMAIL
            if hasattr(settings, "DEFAULT_FROM_EMAIL")
            else None
        ),
        to=[membership.email],
    )
    msg.send()
