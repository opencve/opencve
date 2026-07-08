import json

import pytest

from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    org_list_url,
    org_url,
    write_token,
)


@pytest.mark.django_db
def test_list_returns_only_token_org(
    client, api_context, write_token, create_user, create_organization
):
    """List returns only the organization bound to the token."""
    _user, _organization, _create_token = api_context
    other_user = create_user(username="other-user")
    create_organization(name="other-org", user=other_user)

    response = client.get(org_list_url(), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["results"][0]["name"] == "acme"


@pytest.mark.django_db
def test_retrieve_success(client, write_token):
    """Retrieve returns the token organization details."""
    response = client.get(org_url(), **bearer(write_token))

    assert response.status_code == 200
    assert response.json()["name"] == "acme"


@pytest.mark.django_db
def test_patch_rename_success(client, write_token, api_context):
    """PATCH renames the organization successfully."""
    _user, organization, _create_token = api_context

    response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme-corp"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["name"] == "acme-corp"
    organization.refresh_from_db()
    assert organization.name == "acme-corp"


@pytest.mark.django_db
def test_patch_duplicate_name(client, write_token, create_user, create_organization):
    """PATCH rejects a name already used by another organization."""
    user2 = create_user(username="user2")
    create_organization(name="taken-name", user=user2)

    response = client.patch(
        org_url(),
        data=json.dumps({"name": "taken-name"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This organization name is not available."]},
    )


@pytest.mark.django_db
def test_patch_reserved_name(client, write_token):
    """PATCH rejects the reserved organization name 'add'."""
    response = client.patch(
        org_url(),
        data=json.dumps({"name": "add"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This organization is reserved."]},
    )


@pytest.mark.django_db
def test_patch_invalid_slug_chars(client, write_token):
    """PATCH rejects organization names with invalid slug characters."""
    response = client.patch(
        org_url(),
        data=json.dumps({"name": "foo|bar"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["Special characters (except dash) are not accepted"]},
    )


@pytest.mark.django_db
def test_patch_same_name_allowed(client, write_token):
    """PATCH allows keeping the current organization name."""
    response = client.patch(
        org_url(),
        data=json.dumps({"name": "acme"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["name"] == "acme"


@pytest.mark.django_db
def test_post_returns_405(client, write_token):
    """POST is not allowed on the organization endpoint."""
    response = client.post(
        org_list_url(),
        data=json.dumps({"name": "new-org"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 405


@pytest.mark.django_db
def test_delete_returns_405(client, write_token):
    """DELETE is not allowed on the organization endpoint."""
    response = client.delete(org_url(), **bearer(write_token))

    assert response.status_code == 405
