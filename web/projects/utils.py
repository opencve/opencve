from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string


def send_notification_confirmation_email(notification, request):
    """
    Send a confirmation email to the notification target address.
    The email states who created the notification and includes a confirmation link.
    """
    extras = notification.configuration.get("extras", {})
    email_to = extras.get("email")
    created_by_email = extras.get("created_by_email", "")
    confirmation_token = extras.get("confirmation_token")
    if not email_to or not confirmation_token:
        return

    confirm_url = request.build_absolute_uri(
        f"/notifications/confirm/{confirmation_token}/"
    )

    context = {
        "organization": notification.project.organization.name,
        "project": notification.project.name,
        "created_by_email": created_by_email,
        "confirm_url": confirm_url,
    }

    subject = (
        f"{settings.ACCOUNT_EMAIL_SUBJECT_PREFIX}Notification subscription confirmation"
    )

    text_content = render_to_string(
        "projects/emails/notification_confirmation.txt", context
    )
    msg = EmailMessage(
        subject=subject,
        body=text_content,
        from_email=(
            settings.DEFAULT_FROM_EMAIL
            if hasattr(settings, "DEFAULT_FROM_EMAIL")
            else None
        ),
        to=[email_to],
    )
    msg.send()
