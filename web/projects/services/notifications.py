from urllib.parse import urlparse
import re

from django.core.exceptions import ValidationError

from opencve.utils.ssrf import UnsafeURL, validate_public_http_url
from projects.models import Notification

NOTIFICATION_WRITE_KEYS = {
    "email": frozenset({"email"}),
    "webhook": frozenset({"url", "headers"}),
    "slack": frozenset({"webhook_url"}),
}

NOTIFICATION_REQUIRED_KEYS = {
    "email": frozenset({"email"}),
    "webhook": frozenset({"url"}),
    "slack": frozenset({"webhook_url"}),
}

RESERVED_NOTIFICATION_NAMES = frozenset({"add"})
NOTIFICATION_NAME_RESERVED_MESSAGE = "This name is reserved."
NOTIFICATION_NAME_TAKEN_MESSAGE = "This name already exists."
NOTIFICATION_NAME_INVALID_MESSAGE = (
    "Special characters (except dash and underscore) are not accepted"
)

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9\-_ ]+$")


def validate_notification_name(name, *, project=None, exclude_notification=None):
    """Validate the notification name"""
    if name in RESERVED_NOTIFICATION_NAMES:
        raise ValidationError(NOTIFICATION_NAME_RESERVED_MESSAGE)

    if not _NAME_PATTERN.match(name):
        raise ValidationError(NOTIFICATION_NAME_INVALID_MESSAGE)

    if project is None:
        return

    queryset = Notification.objects.filter(project=project, name=name)
    if exclude_notification is not None:
        queryset = queryset.exclude(pk=exclude_notification.pk)

    if queryset.exists():
        raise ValidationError(NOTIFICATION_NAME_TAKEN_MESSAGE)


def normalize_configuration_input(configuration):
    """Accept flat configuration or legacy {"extras": ...} wrapper."""
    if not configuration:
        return {}

    if not isinstance(configuration, dict):
        raise ValidationError("configuration must be an object.")

    if set(configuration.keys()) == {"extras"}:
        inner = configuration.get("extras")
        if inner is None:
            return {}
        if not isinstance(inner, dict):
            raise ValidationError("configuration.extras must be an object.")
        return inner

    return configuration


def validate_notification_outbound_url(url):
    """Validate the notification outbound URL"""
    try:
        validate_public_http_url(url)
    except UnsafeURL:
        raise ValidationError("This URL is not allowed.")
    return url


def validate_notification_write_configuration(
    notification_type, configuration, *, require_values=False
):
    """Validate the notification write configuration"""
    config = normalize_configuration_input(configuration)

    # Check if there are unknown configuration keys
    allowed = NOTIFICATION_WRITE_KEYS.get(notification_type, frozenset())
    unknown = set(config.keys()) - allowed

    if unknown:
        raise ValidationError(
            "Unknown configuration keys for "
            f"{notification_type}: {', '.join(sorted(unknown))}"
        )

    # Check if there are missing required configuration keys
    if require_values:
        required = NOTIFICATION_REQUIRED_KEYS.get(notification_type, frozenset())
        missing = required - set(config.keys())

        if missing:
            raise ValidationError(
                f"Missing required configuration keys for "
                f"{notification_type}: {', '.join(sorted(missing))}."
            )
        for key in required:
            if not config.get(key):
                raise ValidationError(
                    f"Configuration key {key!r} is required for {notification_type}."
                )

    # Validate the notification outbound URL
    if config.get("url"):
        validate_notification_outbound_url(config["url"])

    # Validate the Slack webhook URL
    if config.get("webhook_url"):
        validate_notification_outbound_url(config["webhook_url"])

    # Validate the HTTP headers
    if notification_type == "webhook" and "headers" in config:
        headers = config["headers"]
        if headers is None:
            config["headers"] = {}
        elif not isinstance(headers, dict):
            raise ValidationError("headers must be an object.")
        else:
            for key, value in headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValidationError(
                        "HTTP headers must be string key-value pairs."
                    )

    return config


def build_notification_extras(notification_type, configuration, existing_extras=None):
    """Build stored extras from API configuration input."""
    config = validate_notification_write_configuration(notification_type, configuration)
    extras = dict(existing_extras or {})

    if notification_type == "email" and "email" in config:
        extras["email"] = config["email"]
    elif notification_type == "webhook":
        if "url" in config:
            extras["url"] = config["url"]
        if "headers" in config:
            extras["headers"] = config["headers"]
    elif notification_type == "slack" and "webhook_url" in config:
        extras["webhook_url"] = config["webhook_url"]

    return extras


def mask_slack_webhook_url(url):
    """Return a redacted Slack webhook URL safe for API responses."""
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme and parsed.hostname:
        return f"{parsed.scheme}://{parsed.hostname}/services/***/***"

    return "https://hooks.slack.com/services/***/***"


def safe_notification_configuration(notification_type, extras):
    """Return a secret-free configuration payload for API read responses."""
    extras = extras or {}

    if notification_type == "email":
        if extras.get("email"):
            return {"email": extras["email"]}
        return {}

    if notification_type == "slack":
        webhook_url = extras.get("webhook_url")
        if not webhook_url:
            return {}
        return {"webhook_url": mask_slack_webhook_url(webhook_url)}

    if notification_type == "webhook":
        url = extras.get("url")
        headers = extras.get("headers") or {}
        result = {
            "url_configured": bool(url),
            "headers_configured": bool(headers),
        }
        if url:
            parsed = urlparse(url)
            host = parsed.hostname
            if host and parsed.port:
                host = f"{host}:{parsed.port}"
            if host:
                result["host"] = host
        if headers:
            result["header_names"] = list(headers.keys())
        return result

    return {}
