import pytest
from django.core.exceptions import ValidationError

from projects.services.notifications import (
    NOTIFICATION_NAME_TAKEN_MESSAGE,
    build_notification_extras,
    mask_slack_webhook_url,
    normalize_configuration_input,
    safe_notification_configuration,
    validate_notification_name,
    validate_notification_outbound_url,
    validate_notification_write_configuration,
)


def test_safe_notification_configuration_email():
    """Return only the public email field for email notifications."""
    assert safe_notification_configuration(
        "email",
        {
            "email": "user@example.com",
            "confirmation_token": "secret",
            "unsubscribe_token": "secret",
            "created_by_email": "creator@example.com",
        },
    ) == {"email": "user@example.com"}


def test_safe_notification_configuration_slack():
    """Mask the secret parts of a Slack webhook URL in API responses."""
    assert safe_notification_configuration(
        "slack",
        {"webhook_url": "https://hooks.slack.com/services/T024BE7LD/B024BE7LD/secret"},
    ) == {"webhook_url": "https://hooks.slack.com/services/***/***"}


def test_safe_notification_configuration_slack_without_url():
    """Return an empty payload when a Slack notification has no webhook URL."""
    assert safe_notification_configuration("slack", {}) == {}


def test_safe_notification_configuration_webhook():
    """Return a safe summary of webhook configuration without exposing secrets."""
    assert safe_notification_configuration(
        "webhook",
        {
            "url": "https://example.com/hooks/opencve",
            "headers": {"X-User-Token": "secret-value"},
        },
    ) == {
        "url_configured": True,
        "headers_configured": True,
        "host": "example.com",
        "header_names": ["X-User-Token"],
    }


def test_build_notification_extras_merges_existing_secrets():
    """Merge updated values while preserving existing secret fields for email."""
    extras = build_notification_extras(
        "email",
        {"email": "new@example.com"},
        existing_extras={
            "email": "old@example.com",
            "confirmation_token": "keep-me",
            "created_by_email": "creator@example.com",
        },
    )
    assert extras["email"] == "new@example.com"
    assert extras["confirmation_token"] == "keep-me"
    assert extras["created_by_email"] == "creator@example.com"


def test_validate_notification_write_configuration_rejects_unknown_keys():
    """Reject configuration payloads containing keys not allowed for the type."""
    with pytest.raises(ValidationError, match="Unknown configuration keys"):
        validate_notification_write_configuration(
            "email",
            {"email": "user@example.com", "confirmation_token": "nope"},
        )


def test_validate_notification_write_configuration_accepts_legacy_extras_wrapper():
    """Unwrap legacy configuration payloads stored under an 'extras' key."""
    config = validate_notification_write_configuration(
        "webhook",
        {"extras": {"url": "https://example.com", "headers": {}}},
    )
    assert config == {"url": "https://example.com", "headers": {}}


@pytest.mark.django_db
def test_validate_notification_name_reserved():
    """Reject reserved notification names such as 'add'."""
    with pytest.raises(ValidationError, match="reserved"):
        validate_notification_name("add")


@pytest.mark.django_db
def test_validate_notification_name_taken(
    create_organization, create_project, create_notification
):
    """Reject duplicate names and allow keeping the current name on update."""
    org = create_organization(name="org")
    project = create_project(name="proj", organization=org)
    notification = create_notification(name="existing", project=project)

    with pytest.raises(ValidationError, match=NOTIFICATION_NAME_TAKEN_MESSAGE):
        validate_notification_name("existing", project=project)

    validate_notification_name(
        "existing",
        project=project,
        exclude_notification=notification,
    )


def test_validate_notification_name_invalid_chars():
    """Reject notification names containing invalid characters."""
    with pytest.raises(ValidationError, match="Special characters"):
        validate_notification_name("bad@name")


def test_validate_notification_outbound_url_ssrf():
    """Reject outbound URLs pointing to private addresses."""
    with pytest.raises(ValidationError, match="This URL is not allowed."):
        validate_notification_outbound_url("http://127.0.0.1/hook")


def test_validate_notification_write_configuration_require_values():
    """Reject webhook configuration missing required values."""
    with pytest.raises(ValidationError, match="Missing required configuration keys"):
        validate_notification_write_configuration(
            "webhook",
            {"headers": {}},
            require_values=True,
        )


def test_validate_notification_write_configuration_invalid_headers():
    """Reject webhook headers that are not string key-value pairs."""
    with pytest.raises(
        ValidationError, match="HTTP headers must be string key-value pairs."
    ):
        validate_notification_write_configuration(
            "webhook",
            {"headers": {"X-Token": 123}},
        )


def test_normalize_configuration_input_non_object():
    """Reject configuration input that is not an object."""
    with pytest.raises(ValidationError, match="configuration must be an object."):
        normalize_configuration_input("not-a-dict")


def test_mask_slack_webhook_url_malformed_url():
    """Return a default masked URL for malformed Slack webhook URLs."""
    assert mask_slack_webhook_url("not-a-valid-url") == (
        "https://hooks.slack.com/services/***/***"
    )
