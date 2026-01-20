from organizations.forms import (
    MembershipForm,
    OrganizationAPITokenForm,
    OrganizationForm,
)
from organizations.models import Membership


def test_organization_form_valid(db):
    form = OrganizationForm(data={"name": "orga1"}, request=None)
    assert form.errors == {}


def test_organization_form_special_characters(db):
    form = OrganizationForm(data={"name": "foo|bar"}, request=None)
    assert form.errors == {
        "name": ["Special characters (except dash) are not accepted"]
    }


def test_organization_form_reserved_names(db):
    form = OrganizationForm(data={"name": "add"}, request=None)
    assert form.errors == {"name": ["This organization is reserved."]}


def test_organization_form_update_instance(db, create_user, create_organization):
    user = create_user(username="user1")
    organization = create_organization(name="orga1", user=user)
    form = OrganizationForm(data={"name": "orga2"}, request=None, instance=organization)
    assert form.errors == {}


def test_organization_form_name_already_exists(db, create_user, create_organization):
    user = create_user(username="user1")
    create_organization(name="orga1", user=user)
    form = OrganizationForm(data={"name": "orga1"}, request=None)
    assert form.errors == {"name": ["This organization name is not available."]}


def test_organization_form_rename_with_existing_name(
    db, create_user, create_organization
):
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    organization1 = create_organization(name="orga1", user=user1)
    create_organization(name="orga2", user=user2)
    form = OrganizationForm(
        data={"name": "orga2"}, request=None, instance=organization1
    )
    assert form.errors == {"name": ["This organization name is not available."]}


def test_membership_form_invalid_fields():
    form = MembershipForm(data={"email": "foo", "role": "bar"})
    assert form.errors == {
        "email": ["Enter a valid email address."],
        "role": ["Select a valid choice. bar is not one of the available choices."],
    }

    form = MembershipForm(data={"email": "foo@example.com", "role": Membership.OWNER})
    assert form.errors == {}


def test_organization_api_token_form_valid():
    form = OrganizationAPITokenForm(
        data={"name": "Production API", "description": "Token for production"}
    )
    assert form.errors == {}


def test_organization_api_token_form_valid_without_description():
    form = OrganizationAPITokenForm(data={"name": "CI/CD Pipeline"})
    assert form.errors == {}


def test_organization_api_token_form_missing_name():
    form = OrganizationAPITokenForm(data={"description": "Some description"})
    assert form.errors == {"name": ["This field is required."]}


def test_organization_api_token_form_empty_name():
    form = OrganizationAPITokenForm(
        data={"name": "", "description": "Some description"}
    )
    assert form.errors == {"name": ["This field is required."]}


def test_organization_api_token_form_name_too_long():
    long_name = "a" * 101  # 101 characters, max is 100
    form = OrganizationAPITokenForm(data={"name": long_name})
    assert form.errors == {
        "name": ["Ensure this value has at most 100 characters (it has 101)."]
    }


def test_organization_api_token_form_description_too_long():
    long_description = "a" * 256  # 256 characters, max is 255
    form = OrganizationAPITokenForm(
        data={"name": "Test Token", "description": long_description}
    )
    assert form.errors == {
        "description": ["Ensure this value has at most 255 characters (it has 256)."]
    }


def test_organization_api_token_form_handles_request_parameter():
    """Test that the form correctly handles the request parameter in __init__."""
    form = OrganizationAPITokenForm(
        data={"name": "Test Token"}, request="dummy_request"
    )
    assert form.errors == {}
    # The form should not have a request attribute since it's popped
    assert not hasattr(form, "request")
