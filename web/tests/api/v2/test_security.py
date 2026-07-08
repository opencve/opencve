import pytest

from organizations.models import OrganizationAPIToken
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    members_url,
    notification_detail_url,
    notification_list_url,
    org_url,
    project_detail_url,
    projects_url,
)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "url",
    [
        pytest.param(lambda: org_url("other-org"), id="org_detail"),
        pytest.param(lambda: members_url("other-org"), id="members"),
        pytest.param(lambda: projects_url("other-org"), id="projects"),
    ],
)
def test_token_cannot_access_other_organization_resources(
    client, api_context, create_user, create_organization, url
):
    """Return 404 when a token tries to access another organization's resources."""
    _user, _organization, create_token = api_context
    other_user = create_user(username="other-user")
    create_organization(name="other-org", user=other_user)
    token_string = create_token()

    response = client.get(url(), **bearer(token_string))

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_token_cannot_access_project_from_another_organization(
    client, api_context, create_user, create_organization, create_project
):
    """Return 404 when a token tries to access a project in another organization."""
    _user, _organization, create_token = api_context
    other_user = create_user(username="other-user")
    other_org = create_organization(name="other-org", user=other_user)
    create_project(name="secret-proj", organization=other_org)
    token_string = create_token()

    response = client.get(
        project_detail_url("secret-proj", org_name="other-org"),
        **bearer(token_string),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_inactive_project_returns_404_on_nested_routes(
    client, api_context, create_project
):
    """Return 404 for nested routes when the project is inactive."""
    _user, organization, create_token = api_context
    create_project(name="inactive-proj", organization=organization, active=False)
    token_string = create_token()

    response = client.get(
        notification_list_url(project_name="inactive-proj"),
        **bearer(token_string),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_nonexistent_resource_in_organization_returns_404(
    client, api_context, create_project
):
    """Return 404 when a resource does not exist in the token's organization."""
    _user, organization, create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
    )

    response = client.get(
        notification_detail_url("missing-notification"),
        **bearer(token_string),
    )

    assert_v2_error(response, "not_found", status_code=404)
