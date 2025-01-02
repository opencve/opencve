import uuid
from datetime import datetime


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
