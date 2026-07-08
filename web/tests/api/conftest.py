import pytest

from organizations.models import OrganizationAPIToken


@pytest.fixture
def api_context(create_user, create_organization):
    """Return user, organization, and a create_token factory with org 'acme' by default."""
    user = create_user()
    organization = create_organization(name="acme", user=user)

    def _create_token(**kwargs):
        defaults = {
            "organization": organization,
            "name": "API Token",
            "description": None,
            "created_by": user,
        }
        defaults.update(kwargs)
        return OrganizationAPIToken.create_token(**defaults)

    return user, organization, _create_token


@pytest.fixture
def create_org_token(api_context):
    """Shortcut to create organization API tokens from api_context."""
    _user, _organization, create_token = api_context
    return create_token
