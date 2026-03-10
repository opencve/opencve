import json
import uuid
from datetime import datetime

from opencve.constants import RESOURCE_LABELS


def is_valid_uuid(val):
    """Check if a given value is a valid UUID"""
    try:
        uuid.UUID(str(val))
    except ValueError:
        return False
    return True


class DateConverter:
    regex = r"\d{4}-\d{1,2}-\d{1,2}"
    format = "%Y-%m-%d"

    def to_python(self, value):
        return datetime.strptime(value, self.format).date()

    def to_url(self, value):
        return value.strftime(self.format)


def normalize_pk_for_model(model_class, object_pk_str):
    """Convert LogEntry.object_pk (string) to the type expected by the model's pk."""
    try:
        return uuid.UUID(object_pk_str)
    except (ValueError, TypeError, AttributeError):
        try:
            return int(object_pk_str)
        except (ValueError, TypeError):
            return object_pk_str


def safe_load_json(value):
    """Return a dict loaded from JSON string or dict-like value, or None on failure."""
    if value is None or value == "":
        return None

    if isinstance(value, dict):
        return value

    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def get_resource_label(content_type):
    """Return a user-friendly label for this content type."""
    if content_type is None:
        return ""

    key = f"{content_type.app_label}.{content_type.model}"
    return RESOURCE_LABELS.get(key, content_type.model.replace("_", " ").title())
