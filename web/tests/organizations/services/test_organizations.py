import pytest
from django.core.exceptions import ValidationError

from organizations.services.organizations import (
    ORGANIZATION_NAME_RESERVED_MESSAGE,
    ORGANIZATION_NAME_TAKEN_MESSAGE,
    validate_organization_name,
)


def test_validate_organization_name_reserved():
    """Reject reserved organization names such as 'add'."""
    with pytest.raises(ValidationError, match=ORGANIZATION_NAME_RESERVED_MESSAGE):
        validate_organization_name("add")


def test_validate_organization_name_taken(create_user, create_organization):
    """Reject a name that is already used by another organization."""
    create_organization(name="acme")
    with pytest.raises(ValidationError, match=ORGANIZATION_NAME_TAKEN_MESSAGE):
        validate_organization_name("acme")


def test_validate_organization_name_allows_same_organization(
    create_user, create_organization
):
    """Allow keeping the current name when updating an existing organization."""
    organization = create_organization(name="acme")
    validate_organization_name("acme", exclude_organization=organization)


def test_validate_organization_name_rejects_rename_to_existing_name(
    create_user, create_organization
):
    """Reject renaming an organization to a name already taken by another one."""
    organization = create_organization(name="acme")
    create_organization(name="other-org", user=create_user(username="other"))
    with pytest.raises(ValidationError, match=ORGANIZATION_NAME_TAKEN_MESSAGE):
        validate_organization_name("other-org", exclude_organization=organization)
