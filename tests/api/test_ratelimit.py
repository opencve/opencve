import pytest

from flask import g

from opencve import create_app
from opencve.extensions import db


@pytest.fixture
def app():
    _app = create_app(
        "test",
        {
            "RATELIMIT_ENABLED": True,
            "RATELIMIT_VALUE": "2/minute",
            "RATELIMIT_STORAGE_URL": "memory://",
        },
    )
    ctx = _app.app_context()
    ctx.push()
    db.create_all()
    yield _app


def test_ratelimit(app, client, create_user, create_vendor):
    create_user("opencve")
    client.login("opencve")

    def _do_request(endpoint="/cve"):
        resp = client.get("/api{}".format(endpoint))

        # g._rate_limiting_complete must be set to False after each request
        # see https://github.com/alisaifee/flask-limiter/issues/147#issuecomment-642683820
        g._rate_limiting_complete = False

        return resp

    # Rate limit is disabled
    assert _do_request().status_code == 200
    assert _do_request().status_code == 200
    assert _do_request().status_code == 429

    # Ratelimit is shared between all routes
    assert _do_request("/reports").status_code == 429
    assert _do_request("/vendors").status_code == 429
    assert _do_request("/cwe").status_code == 429

    # Other user is not rate limited
    create_user("john")
    client.login("john")
    assert _do_request().status_code == 200
