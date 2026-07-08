import base64

import pytest

from tests.conftest import TEST_PASSWORD


def basic_auth_header(user):
    """Build a Basic auth header value for the given user."""
    credentials = base64.b64encode(f"{user.username}:{TEST_PASSWORD}".encode()).decode()
    return f"Basic {credentials}"
