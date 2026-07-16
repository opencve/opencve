import json

import pytest
from django.test import override_settings

from organizations.models import OrganizationAPIToken
from projects.models import Notification
from projects.services.notifications import NOTIFICATION_NAME_TAKEN_MESSAGE
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    notification_detail_url,
    notification_list_url,
    write_token,
)


@pytest.mark.django_db
def test_list_hides_secrets(
    client, api_context, write_token, create_project, create_notification
):
    """List hides secret values in notification configurations."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_notification(
        name="email-alerts",
        project=project,
        type="email",
        configuration={
            "extras": {
                "email": "alerts@example.com",
                "confirmation_token": "secret-token",
                "created_by_email": "creator@example.com",
            }
        },
        is_enabled=False,
    )
    create_notification(
        name="slack-alerts",
        project=project,
        type="slack",
        configuration={
            "extras": {"webhook_url": "https://hooks.slack.com/services/secret"}
        },
    )
    create_notification(
        name="webhook-alerts",
        project=project,
        type="webhook",
        configuration={
            "extras": {
                "url": "https://example.com/hooks/opencve",
                "headers": {"X-User-Token": "secret"},
            }
        },
    )

    response = client.get(notification_list_url(), **bearer(write_token))

    assert response.status_code == 200
    results = {item["name"]: item for item in response.json()["results"]}
    assert results["email-alerts"]["configuration"] == {"email": "alerts@example.com"}
    assert results["email-alerts"]["is_pending_email_confirmation"] is True
    assert results["slack-alerts"]["configuration"] == {
        "webhook_url": "https://hooks.slack.com/services/***/***"
    }
    assert "is_pending_email_confirmation" not in results["slack-alerts"]
    assert results["webhook-alerts"]["configuration"] == {
        "url_configured": True,
        "headers_configured": True,
        "host": "example.com",
        "header_names": ["X-User-Token"],
    }
    assert "is_pending_email_confirmation" not in results["webhook-alerts"]


@pytest.mark.django_db
def test_retrieve_hides_secrets(
    client, api_context, write_token, create_project, create_notification
):
    """Retrieve hides secret values in notification configurations."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_notification(
        name="webhook-alerts",
        project=project,
        type="webhook",
        configuration={
            "extras": {
                "url": "https://example.com/hooks/opencve",
                "headers": {"X-User-Token": "secret"},
            }
        },
    )

    response = client.get(
        notification_detail_url("webhook-alerts"),
        **bearer(write_token),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["configuration"] == {
        "url_configured": True,
        "headers_configured": True,
        "host": "example.com",
        "header_names": ["X-User-Token"],
    }
    assert "is_pending_email_confirmation" not in data
    assert "secret" not in response.content.decode()


@pytest.mark.django_db
def test_create_accepts_secrets_but_response_is_safe(
    client, api_context, write_token, create_project
):
    """Create persists secrets but returns a safe configuration payload."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        notification_list_url(),
        data=json.dumps(
            {
                "name": "webhook-alerts",
                "type": "webhook",
                "configuration": {
                    "url": "https://example.com/hooks/opencve",
                    "headers": {"X-User-Token": "secret-value"},
                },
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["configuration"] == {
        "url_configured": True,
        "headers_configured": True,
        "host": "example.com",
        "header_names": ["X-User-Token"],
    }
    assert "secret-value" not in response.content.decode()

    notification = Notification.objects.get(name="webhook-alerts")
    assert (
        notification.configuration["extras"]["url"]
        == "https://example.com/hooks/opencve"
    )
    assert notification.configuration["extras"]["headers"] == {
        "X-User-Token": "secret-value"
    }


@pytest.mark.django_db
def test_create_email_persists_configuration(
    client, api_context, write_token, create_project
):
    """Create email notification persists configuration and starts disabled."""
    user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        notification_list_url(),
        data=json.dumps(
            {
                "name": "Mail to Security team",
                "type": "email",
                "configuration": {"email": "security@example.com"},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["configuration"] == {"email": "security@example.com"}
    assert data["is_enabled"] is False
    assert data["is_pending_email_confirmation"] is True

    notification = Notification.objects.get(name="Mail to Security team")
    extras = notification.configuration["extras"]
    assert extras["email"] == "security@example.com"
    assert extras["created_by_email"] == user.email
    assert extras["confirmation_token"]


@pytest.mark.django_db
def test_create_rejects_duplicate_name(
    client, api_context, write_token, create_project, create_notification
):
    """Create rejects duplicate notification names within a project."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_notification(
        name="Mail to Security team",
        project=project,
        type="email",
        configuration={"extras": {"email": "existing@example.com"}},
    )

    response = client.post(
        notification_list_url(),
        data=json.dumps(
            {
                "name": "Mail to Security team",
                "type": "email",
                "configuration": {"email": "security@example.com"},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    assert response.json()["error"]["details"]["name"] == [
        NOTIFICATION_NAME_TAKEN_MESSAGE
    ]


@pytest.mark.django_db
def test_patch_accepts_secrets_but_response_is_safe(
    client, api_context, write_token, create_project, create_notification
):
    """Patch persists secrets but returns a safe configuration payload."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_notification(
        name="slack-alerts",
        project=project,
        type="slack",
        configuration={
            "extras": {"webhook_url": "https://hooks.slack.com/services/old"}
        },
    )

    response = client.patch(
        notification_detail_url("slack-alerts"),
        data=json.dumps(
            {
                "configuration": {
                    "webhook_url": "https://hooks.slack.com/services/new-secret"
                }
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["configuration"] == {
        "webhook_url": "https://hooks.slack.com/services/***/***"
    }
    assert "new-secret" not in response.content.decode()

    notification = Notification.objects.get(name="slack-alerts")
    assert (
        notification.configuration["extras"]["webhook_url"]
        == "https://hooks.slack.com/services/new-secret"
    )


@pytest.mark.django_db
def test_delete_notification_returns_204(
    client, api_context, write_token, create_project, create_notification
):
    """DELETE removes a notification and returns 204."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_notification(
        name="slack-alerts",
        project=project,
        type="slack",
        configuration={
            "extras": {"webhook_url": "https://hooks.slack.com/services/old"}
        },
    )

    response = client.delete(
        notification_detail_url("slack-alerts"),
        **bearer(write_token),
    )

    assert response.status_code == 204
    assert not Notification.objects.filter(
        name="slack-alerts", project=project
    ).exists()


@pytest.mark.django_db
def test_create_rejects_reserved_name(client, api_context, write_token, create_project):
    """Create rejects the reserved notification name 'add'."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        notification_list_url(),
        data=json.dumps(
            {
                "name": "add",
                "type": "email",
                "configuration": {"email": "security@example.com"},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This name is reserved."]},
    )


@pytest.mark.django_db
def test_create_rejects_invalid_name_chars(
    client, api_context, write_token, create_project
):
    """Create rejects notification names with invalid characters."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        notification_list_url(),
        data=json.dumps(
            {
                "name": "bad@name",
                "type": "email",
                "configuration": {"email": "security@example.com"},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={
            "name": ["Special characters (except dash and underscore) are not accepted"]
        },
    )


@pytest.mark.django_db
def test_create_rejects_missing_configuration_for_type(
    client, api_context, write_token, create_project
):
    """Create rejects notification types missing required configuration."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        notification_list_url(),
        data=json.dumps({"name": "webhook-alerts", "type": "webhook"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    assert "Missing required configuration keys" in str(
        response.json()["error"]["details"]["configuration"]
    )


@pytest.mark.django_db
def test_create_rejects_ssrf_blocked_url(
    client, api_context, write_token, create_project
):
    """Create rejects webhook URLs blocked by SSRF protections."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        notification_list_url(),
        data=json.dumps(
            {
                "name": "internal-hook",
                "type": "webhook",
                "configuration": {"url": "http://127.0.0.1/hook"},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    assert "This URL is not allowed." in str(response.json()["error"]["details"])


@pytest.mark.django_db
def test_patch_email_change_disables_notification(
    client, api_context, write_token, create_project, create_notification
):
    """Patching the email address disables the notification pending confirmation."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_notification(
        name="email-alerts",
        project=project,
        type="email",
        configuration={
            "extras": {
                "email": "alerts@example.com",
                "confirmation_token": "confirmed",
            }
        },
        is_enabled=True,
    )

    response = client.patch(
        notification_detail_url("email-alerts"),
        data=json.dumps({"configuration": {"email": "new@example.com"}}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["is_enabled"] is False
    assert response.json()["is_pending_email_confirmation"] is True

    notification = Notification.objects.get(name="email-alerts")
    assert notification.is_enabled is False
    assert notification.configuration["extras"]["email"] == "new@example.com"


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_missing_notifications_read_scope_returns_403(
    client, api_context, create_org_token, create_project
):
    """List rejects tokens missing the notifications:read scope."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["projects:write"],
    )

    response = client.get(notification_list_url(), **bearer(token_string))

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="notifications:read",
    )
