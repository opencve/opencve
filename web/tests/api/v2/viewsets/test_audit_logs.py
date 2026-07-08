import json

import pytest
from auditlog.models import LogEntry

from tests.api.v2.conftest import audit_logs_url, bearer, org_url, write_token


@pytest.mark.django_db
def test_list_returns_entries_after_patch_org(client, write_token, api_context):
    """List returns audit log entries after an organization update."""
    _user, _organization, _create_token = api_context

    patch_response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme-corp"}),
        content_type="application/json",
        **bearer(write_token),
    )
    assert patch_response.status_code == 200

    response = client.get(audit_logs_url("acme-corp"), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 1
    org_updates = [
        entry
        for entry in data["results"]
        if entry.get("resource") == "Organization"
        and entry.get("action") == LogEntry.Action.UPDATE
    ]
    assert org_updates


@pytest.mark.django_db
def test_list_pagination_structure(client, write_token):
    """List returns the standard paginated response structure."""
    response = client.get(audit_logs_url(), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert set(data.keys()) == {"count", "next", "previous", "results"}
    assert isinstance(data["count"], int)
    assert isinstance(data["results"], list)
    assert data["next"] is None
    assert data["previous"] is None
