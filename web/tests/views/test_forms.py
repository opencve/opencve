import pytest
from views.forms import ViewForm

from organizations.models import Membership


@pytest.mark.django_db
def test_view_form_valid(rf, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test_org", user=user)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization

    form = ViewForm(
        data={
            "name": "my-view",
            "query": "my-query",
            "privacy": "public",
        },
        request=request,
    )
    assert form.errors == {}


@pytest.mark.django_db
def test_view_form_invalid_privacy(rf, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test_org", user=user)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization

    form = ViewForm(
        data={
            "name": "my-view",
            "query": "my-query",
            "privacy": "foobar",
        },
        request=request,
    )
    assert form.errors == {
        "privacy": [
            "Select a valid choice. foobar is not one of the available choices."
        ]
    }


@pytest.mark.django_db
def test_view_form_name_too_long(rf, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test_org", user=user)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization

    form = ViewForm(
        data={
            "name": "a" * 200,
            "query": "my-query",
            "privacy": "public",
        },
        request=request,
    )
    assert form.errors == {
        "name": ["Ensure this value has at most 100 characters (it has 200)."]
    }


@pytest.mark.django_db
def test_view_form_clean_name(rf, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test_org", user=user)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization

    form = ViewForm(
        data={
            "name": "add",
            "query": "my-query",
            "privacy": "public",
        },
        request=request,
    )
    assert form.errors == {"name": ["This view is reserved."]}


@pytest.mark.django_db
def test_view_form_clean_query(rf, create_user, create_organization):
    user = create_user()
    organization = create_organization(name="test_org", user=user)

    request = rf.get("/")
    request.user = user
    request.current_organization = organization

    form = ViewForm(
        data={
            "name": "my-view",
            "query": "/",
            "privacy": "public",
        },
        request=request,
    )
    assert form.errors == {
        "query": ["Expected 'OR' operations, found '/'  (at char 0), (line:1, col:1)"]
    }


@pytest.mark.django_db
def test_view_form_clean_unique_name(rf, create_user, create_organization, create_view):
    user1 = create_user()
    org1 = create_organization(name="test_org", user=user1)
    create_view(
        name="my-private-view",
        query="valid-query",
        organization=org1,
        privacy="private",
        user=user1,
    )

    # User1 can't create a private view with the same name
    request_user1 = rf.get("/")
    request_user1.user = user1
    request_user1.current_organization = org1

    form = ViewForm(
        data={
            "name": "my-private-view",
            "query": "valid-query",
            "privacy": "private",
        },
        request=request_user1,
    )
    assert form.errors == {
        "name": ["You already have a private view with this name in this organization."]
    }

    # But user2 is able to create a private view with the same name
    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org1,
        role=Membership.MEMBER,
    )

    request_user2 = rf.get("/")
    request_user2.user = user2
    request_user2.current_organization = org1

    form = ViewForm(
        data={
            "name": "my-private-view",
            "query": "valid-query",
            "privacy": "private",
        },
        request=request_user2,
    )
    assert form.errors == {}

    # If no public view exists, user1 succeeds to create a new one
    form = ViewForm(
        data={
            "name": "my-public-view",
            "query": "valid-query",
            "privacy": "public",
        },
        request=request_user1,
    )
    assert form.errors == {}

    # But if a public view already exists in the organization,
    # another user can't create a new one with the same name
    create_view(
        name="my-public-view",
        query="valid-query",
        organization=org1,
        privacy="public",
        user=user1,
    )

    form = ViewForm(
        data={
            "name": "my-public-view",
            "query": "valid-query",
            "privacy": "public",
        },
        request=request_user2,
    )
    assert form.errors == {
        "name": ["A public view with this name already exists in this organization."]
    }

    # Another user from another organization can create the views
    user3 = create_user()
    org3 = create_organization(name="test_another_org", user=user3)
    request_user3 = rf.get("/")
    request_user3.user = user3
    request_user3.current_organization = org3

    form = ViewForm(
        data={
            "name": "my-private-view",
            "query": "valid-query",
            "privacy": "private",
        },
        request=request_user3,
    )
    assert form.errors == {}

    form = ViewForm(
        data={
            "name": "my-public-view",
            "query": "valid-query",
            "privacy": "public",
        },
        request=request_user3,
    )
    assert form.errors == {}
