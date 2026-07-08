import json

import pytest

from projects.models import Project
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    project_detail_url,
    projects_url,
    write_token,
)


@pytest.mark.django_db
def test_list_includes_subscriptions_count(
    client, api_context, write_token, create_project
):
    """List projects includes subscriptions_count for each project."""
    _user, organization, _create_token = api_context
    create_project(
        name="prod",
        organization=organization,
        vendors=["python"],
        products=["apache$airflow"],
    )

    response = client.get(projects_url(), **bearer(write_token))

    assert response.status_code == 200
    item = response.json()["results"][0]
    assert item["name"] == "prod"
    assert item["subscriptions_count"] == 2


@pytest.mark.django_db
def test_retrieve_includes_subscriptions_count(
    client, api_context, write_token, create_project
):
    """Retrieve a project includes subscriptions_count."""
    _user, organization, _create_token = api_context
    create_project(
        name="prod",
        organization=organization,
        vendors=["python", "linux"],
    )

    response = client.get(project_detail_url(), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "prod"
    assert data["subscriptions_count"] == 2


@pytest.mark.django_db
def test_create_project_returns_201_with_active_true(client, write_token):
    """POST create returns 201 and active defaults to true."""
    response = client.post(
        projects_url(),
        data=json.dumps({"name": "staging", "description": "Staging env"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "staging"
    assert data["active"] is True
    assert Project.objects.filter(name="staging").exists()


@pytest.mark.django_db
def test_create_duplicate_name_same_org_returns_400(
    client, api_context, write_token, create_project
):
    """POST rejects a project name already used in the same organization."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        projects_url(),
        data=json.dumps({"name": "prod"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This project already exists."]},
    )


@pytest.mark.django_db
def test_create_same_name_different_org_returns_201(
    client,
    api_context,
    write_token,
    create_user,
    create_organization,
):
    """POST allows the same project name in a different organization."""
    _user, _organization, _create_token = api_context
    other_user = create_user(username="other-user")
    other_org = create_organization(name="other-org", user=other_user)
    Project.objects.create(name="shared", organization=other_org)

    response = client.post(
        projects_url(),
        data=json.dumps({"name": "shared"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    assert response.json()["name"] == "shared"


@pytest.mark.django_db
def test_create_reserved_name_returns_400(client, write_token):
    """POST rejects the reserved project name 'add'."""
    response = client.post(
        projects_url(),
        data=json.dumps({"name": "add"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This project is reserved."]},
    )


@pytest.mark.django_db
def test_patch_rename_success(client, write_token, create_project, api_context):
    """PATCH renames a project successfully."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)

    response = client.patch(
        project_detail_url(),
        data=json.dumps({"name": "production"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json()["name"] == "production"
    project.refresh_from_db()
    assert project.name == "production"


@pytest.mark.django_db
def test_delete_project_returns_204(client, api_context, write_token, create_project):
    """DELETE removes a project and returns 204."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.delete(project_detail_url(), **bearer(write_token))

    assert response.status_code == 204
    assert not Project.objects.filter(name="prod", organization=organization).exists()
