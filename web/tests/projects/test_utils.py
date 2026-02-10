from django.test import RequestFactory, override_settings

from projects.utils import send_notification_confirmation_email


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_send_notification_confirmation_email_sends_email(
    create_organization, create_user, create_project, create_notification
):
    """Send one email with correct subject, recipient and body."""
    user = create_user()
    org = create_organization(name="MyOrg", user=user)
    project = create_project(name="MyProject", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {
                "email": "recipient@example.com",
                "created_by_email": "creator@example.com",
                "confirmation_token": "secret-token-123",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    request = RequestFactory().get("/")
    request.META["SERVER_NAME"] = "example.com"
    request.META["SERVER_PORT"] = "80"

    send_notification_confirmation_email(notification, request)

    assert len(outbox) == 1
    msg = outbox[0]
    assert msg.to == ["recipient@example.com"]
    assert "Notification subscription confirmation" in msg.subject
    assert "creator@example.com" in msg.body
    assert "MyOrg" in msg.body
    assert "MyProject" in msg.body
    assert "/notifications/confirm/secret-token-123/" in msg.body


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_send_notification_confirmation_email_does_nothing_when_email_missing(
    create_organization, create_project, create_notification
):
    """Return without sending when extras.email is missing."""
    org = create_organization(name="Org")
    project = create_project(name="Project", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {
                "created_by_email": "creator@example.com",
                "confirmation_token": "token",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    request = RequestFactory().get("/")

    send_notification_confirmation_email(notification, request)

    assert len(outbox) == 0


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_send_notification_confirmation_email_does_nothing_when_token_missing(
    create_organization, create_project, create_notification
):
    """Return without sending when confirmation_token is missing."""
    org = create_organization(name="Org")
    project = create_project(name="Project", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {
                "email": "recipient@example.com",
                "created_by_email": "creator@example.com",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    request = RequestFactory().get("/")

    send_notification_confirmation_email(notification, request)

    assert len(outbox) == 0
