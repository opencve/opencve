from organizations.forms import (
    MembershipForm,
    OrganizationAPITokenForm,
    OrganizationForm,
    get_organization_token_form_class,
)
from organizations.models import Membership


class CustomTokenForm(OrganizationAPITokenForm):
    pass


def test_organization_form_valid(db):
    """Accept a valid organization name."""
    form = OrganizationForm(data={"name": "orga1"}, request=None)
    assert form.errors == {}


def test_organization_form_special_characters(db):
    """Reject organization names containing invalid special characters."""
    form = OrganizationForm(data={"name": "foo|bar"}, request=None)
    assert form.errors == {
        "name": ["Special characters (except dash) are not accepted"]
    }


def test_organization_form_reserved_names(db):
    """Reject reserved organization names such as 'add'."""
    form = OrganizationForm(data={"name": "add"}, request=None)
    assert form.errors == {"name": ["This organization is reserved."]}


def test_organization_form_update_instance(db, create_user, create_organization):
    """Allow renaming an organization when the new name is available."""
    user = create_user(username="user1")
    organization = create_organization(name="orga1", user=user)
    form = OrganizationForm(data={"name": "orga2"}, request=None, instance=organization)
    assert form.errors == {}


def test_organization_form_name_already_exists(db, create_user, create_organization):
    """Reject creating an organization with a name that is already taken."""
    user = create_user(username="user1")
    create_organization(name="orga1", user=user)
    form = OrganizationForm(data={"name": "orga1"}, request=None)
    assert form.errors == {"name": ["This organization name is not available."]}


def test_organization_form_rename_with_existing_name(
    db, create_user, create_organization
):
    """Reject renaming an organization to a name already used by another one."""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    organization1 = create_organization(name="orga1", user=user1)
    create_organization(name="orga2", user=user2)
    form = OrganizationForm(
        data={"name": "orga2"}, request=None, instance=organization1
    )
    assert form.errors == {"name": ["This organization name is not available."]}


def test_membership_form_invalid_fields():
    """Reject invalid email and role values, and accept valid member invitations."""
    form = MembershipForm(data={"email": "foo", "role": "bar"})
    assert form.errors == {
        "email": ["Enter a valid email address."],
        "role": ["Select a valid choice. bar is not one of the available choices."],
    }

    form = MembershipForm(data={"email": "foo@example.com", "role": Membership.OWNER})
    assert form.errors == {}


def test_organization_api_token_form_valid():
    """Accept a valid API token form with name and description."""
    form = OrganizationAPITokenForm(
        data={"name": "Production API", "description": "Token for production"}
    )
    assert form.errors == {}


def test_organization_api_token_form_valid_without_description():
    """Accept a valid API token form when description is omitted."""
    form = OrganizationAPITokenForm(data={"name": "CI/CD Pipeline"})
    assert form.errors == {}


def test_organization_api_token_form_missing_name():
    """Reject an API token form when the name field is missing."""
    form = OrganizationAPITokenForm(data={"description": "Some description"})
    assert form.errors == {"name": ["This field is required."]}


def test_organization_api_token_form_empty_name():
    """Reject an API token form when the name field is empty."""
    form = OrganizationAPITokenForm(
        data={"name": "", "description": "Some description"}
    )
    assert form.errors == {"name": ["This field is required."]}


def test_organization_api_token_form_name_too_long():
    """Reject an API token name longer than 100 characters."""
    long_name = "a" * 101  # 101 characters, max is 100
    form = OrganizationAPITokenForm(data={"name": long_name})
    assert form.errors == {
        "name": ["Ensure this value has at most 100 characters (it has 101)."]
    }


def test_organization_api_token_form_description_too_long():
    """Reject an API token description longer than 255 characters."""
    long_description = "a" * 256  # 256 characters, max is 255
    form = OrganizationAPITokenForm(
        data={"name": "Test Token", "description": long_description}
    )
    assert form.errors == {
        "description": ["Ensure this value has at most 255 characters (it has 256)."]
    }


def test_organization_api_token_form_handles_request_parameter():
    """Ignore the request parameter passed to the form constructor."""
    form = OrganizationAPITokenForm(
        data={"name": "Test Token"}, request="dummy_request"
    )
    assert form.errors == {}
    # The form should not have a request attribute since it's popped
    assert not hasattr(form, "request")


def test_organization_api_token_form_get_token_create_kwargs():
    """Return the kwargs expected by OrganizationAPIToken.create_token()."""
    form = OrganizationAPITokenForm(
        data={
            "name": "Production API",
            "description": "Token for production",
            "access_mode": "write",
        }
    )
    assert form.is_valid()
    assert form.get_token_create_kwargs() == {
        "name": "Production API",
        "description": "Token for production",
        "access_mode": "write",
        "scopes": [],
    }


def test_get_organization_token_form_class_default():
    """Return the default OrganizationAPITokenForm class."""
    assert get_organization_token_form_class() is OrganizationAPITokenForm


def test_get_organization_token_form_class_override(settings):
    """Return a custom token form class when configured in settings."""
    settings.ORGANIZATION_TOKEN_FORM_CLASS = (
        "tests.organizations.test_forms.CustomTokenForm"
    )
    assert get_organization_token_form_class() is CustomTokenForm
