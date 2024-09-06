from organizations.forms import MembershipForm, OrganizationForm
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
    assert form.errors == {"name": ["Existing organizations can't be renamed."]}


def test_organization_form_name_already_exists(db, create_user, create_organization):
    user = create_user(username="user1")
    create_organization(name="orga1", user=user)
    form = OrganizationForm(data={"name": "orga1"}, request=None)
    assert form.errors == {"name": ["This organization name is not available."]}


def test_membership_form_invalid_fields():
    form = MembershipForm(data={"email": "foo", "role": "bar"})
    assert form.errors == {
        "email": ["Enter a valid email address."],
        "role": ["Select a valid choice. bar is not one of the available choices."],
    }

    form = MembershipForm(data={"email": "foo@example.com", "role": Membership.OWNER})
    assert form.errors == {}
