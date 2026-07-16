import json

import pytest
from django.test import override_settings

from opencve.api.v2.scopes import (
    APIScope,
    get_available_scopes,
    get_scope_choices,
    normalize_token_scopes,
)
from organizations.models import OrganizationAPIToken
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    org_url,
    project_cves_url,
    projects_url,
    subscriptions_url,
)


def test_get_available_scopes_returns_all_enum_values():
    """Return every defined APIScope value."""
    scopes = get_available_scopes()
    assert scopes == list(APIScope)
    assert APIScope.MEMBERS_READ in scopes


def test_get_scope_choices_returns_value_label_pairs():
    """Return UI-friendly value and label pairs for all scopes."""
    choices = get_scope_choices()
    assert ("members:read", "Members (read)") in choices
    assert len(choices) == len(APIScope)


def test_normalize_token_scopes_deduplicates_and_validates():
    """Deduplicate valid scopes while preserving order."""
    assert normalize_token_scopes(
        ["members:read", "projects:write", "members:read"]
    ) == ["members:read", "projects:write"]


def test_normalize_token_scopes_rejects_unknown_scope():
    """Reject unknown scope strings with ValueError."""
    with pytest.raises(ValueError, match="Unknown scope"):
        normalize_token_scopes(["members:read", "invalid:scope"])


@override_settings(API_SCOPES_ENABLED=True)
def test_normalize_token_scopes_accepts_all_defined_scopes():
    """Accept the full set of defined scopes when scopes are enabled."""
    scopes = [scope.value for scope in APIScope]
    assert normalize_token_scopes(scopes) == scopes


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_read_only_token_on_write_endpoint_returns_read_only_token(client, read_token):
    """Reject write operations for read-only tokens."""
    response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme"}),
        content_type="application/json",
        **bearer(read_token),
    )

    assert_v2_error(response, "read_only_token", status_code=403)


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_missing_scope_returns_missing_scope_with_required_scope(
    client, create_org_token
):
    """Reject requests when the token lacks the required scope."""
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["org:read"],
    )

    response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme"}),
        content_type="application/json",
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="org:write",
    )


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_projects_write_grants_projects_read(
    client, api_context, create_org_token, create_project
):
    """Allow project reads when the token has projects:write."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["projects:write"],
    )

    response = client.get(projects_url(), **bearer(token_string))

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["results"][0]["name"] == "prod"


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_subscriptions_write_grants_subscriptions_read(
    client, api_context, create_org_token, create_project
):
    """Allow subscription reads when the token has subscriptions:write."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization, vendors=["python"])
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["subscriptions:write"],
    )

    response = client.get(subscriptions_url(), **bearer(token_string))

    assert response.status_code == 200
    assert response.json() == {"vendors": ["python"], "products": {}}


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_tracker_write_grants_tracker_read(
    client, api_context, create_org_token, create_project
):
    """Allow tracker list when the token has tracker:write."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["tracker:write"],
    )

    response = client.get(project_cves_url(), **bearer(token_string))

    assert response.status_code == 200
    assert response.json()["count"] == 0


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_empty_scopes_grants_all_scopes(client, create_org_token):
    """Allow all operations when a token has no scopes configured."""
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=[],
    )

    response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme"}),
        content_type="application/json",
        **bearer(token_string),
    )

    assert response.status_code == 200
    assert response.json()["name"] == "acme"


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=False)
def test_scopes_disabled_allows_write_with_write_access_mode_only(
    client, create_org_token
):
    """Allow writes with write access mode when scope enforcement is disabled."""
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["org:read"],
    )

    response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme"}),
        content_type="application/json",
        **bearer(token_string),
    )

    assert response.status_code == 200
    assert response.json()["name"] == "acme"
