import pytest
from django.core.exceptions import ValidationError

from projects.services.projects import (
    PROJECT_NAME_RESERVED_MESSAGE,
    PROJECT_NAME_TAKEN_MESSAGE,
    validate_project_name,
)


def test_validate_project_name_reserved():
    """Reject reserved project name 'add'."""
    with pytest.raises(ValidationError, match=PROJECT_NAME_RESERVED_MESSAGE):
        validate_project_name("add")


@pytest.mark.django_db
def test_validate_project_name_duplicate_same_org(
    create_user, create_organization, create_project
):
    """Reject duplicate project name within the same organization."""
    organization = create_organization(name="acme", user=create_user())
    create_project(name="prod", organization=organization)

    with pytest.raises(ValidationError, match=PROJECT_NAME_TAKEN_MESSAGE):
        validate_project_name("prod", organization=organization)


@pytest.mark.django_db
def test_validate_project_name_same_name_different_org_ok(
    create_user, create_organization, create_project
):
    """Allow the same project name in different organizations."""
    create_project(
        name="prod",
        organization=create_organization(name="acme", user=create_user(username="u1")),
    )
    other_org = create_organization(name="other", user=create_user(username="u2"))

    validate_project_name("prod", organization=other_org)


@pytest.mark.django_db
def test_validate_project_name_exclude_project_allows_same_name(
    create_user, create_organization, create_project
):
    """Allow renaming a project to its current name when excluded."""
    organization = create_organization(name="acme", user=create_user())
    project = create_project(name="prod", organization=organization)

    validate_project_name("prod", organization=organization, exclude_project=project)
