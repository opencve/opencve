import uuid

from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now
from bs4 import BeautifulSoup

from organizations.models import Membership
from views.models import View


def test_views_is_org_members(
    create_organization, create_user, create_view, auth_client
):
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    user2 = create_user()
    create_organization(name="org2", user=user2)
    view = create_view(
        name="view1",
        query="my-query",
        organization=org1,
        privacy="public",
    )

    # User1 is member of the organization, so 200
    client = auth_client(user1)
    response = client.get(reverse("list_views", kwargs={"org_name": "org1"}))
    assert response.status_code == 200
    response = client.get(reverse("create_view", kwargs={"org_name": "org1"}))
    assert response.status_code == 200
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 200
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 200

    # User2 is not member of the organization, so 404
    client = auth_client(user2)
    response = client.get(reverse("list_views", kwargs={"org_name": "org1"}))
    assert response.status_code == 404
    response = client.get(reverse("create_view", kwargs={"org_name": "org1"}))
    assert response.status_code == 404
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 404
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 404


def test_views_not_found(create_organization, create_user, create_view, auth_client):
    user = create_user()
    org = create_organization(name="org", user=user)
    create_view(
        name="my-view",
        query="my-query",
        organization=org,
        privacy="public",
    )

    client = auth_client(user)
    response = client.get(reverse("list_views", kwargs={"org_name": "404"}))
    assert response.status_code == 404
    response = client.get(reverse("create_view", kwargs={"org_name": "404"}))
    assert response.status_code == 404
    response = client.get(
        reverse("update_view", kwargs={"org_name": "404", "view_id": str(uuid.uuid4())})
    )
    assert response.status_code == 404
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org", "view_id": str(uuid.uuid4())})
    )
    assert response.status_code == 404
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "404", "view_id": str(uuid.uuid4())})
    )
    assert response.status_code == 404
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org", "view_id": str(uuid.uuid4())})
    )
    assert response.status_code == 404


def test_list_views(create_organization, create_user, create_view, auth_client):
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org1,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    user3 = create_user()
    create_organization(name="org3", user=user3)

    def _find_views(org, user, privacy):
        client = auth_client(user)
        response = client.get(reverse("list_views", kwargs={"org_name": org}))
        soup = BeautifulSoup(response.content, features="html.parser")

        return [
            s.find("span", {"class": "product-description"}).text.strip()
            for s in soup.find("ul", {"id": f"{privacy}-views"}).find_all("li")
        ]

    # User1 has two public and 1 private views, he can see everything
    create_view(
        name="view1",
        query="query1",
        organization=org1,
        privacy="private",
        user=user1,
    )
    create_view(
        name="view2",
        query="query2",
        organization=org1,
        privacy="public",
    )
    create_view(
        name="view3",
        query="query3",
        organization=org1,
        privacy="public",
    )

    assert _find_views("org1", user1, "private") == ["query1"]
    assert _find_views("org1", user1, "public") == ["query2", "query3"]

    # User2 has no private view, he can only see the public views of the same org
    assert _find_views("org1", user2, "private") == []
    assert _find_views("org1", user2, "public") == ["query2", "query3"]

    # User3 can't see the public views of org1
    assert _find_views("org3", user3, "private") == []
    assert _find_views("org3", user3, "public") == []


def test_create_public_view(create_organization, create_user, auth_client):
    user = create_user()
    create_organization(name="org", user=user)
    client = auth_client(user)

    response = client.post(
        reverse("create_view", kwargs={"org_name": "org"}),
        data={"name": "my-view", "query": "my-query", "privacy": "public"},
        follow=True,
    )
    assert b"The view has been successfully created." in response.content

    views = View.objects.all()
    assert len(views) == 1
    assert views[0].name == "my-view"
    assert views[0].query == "my-query"
    assert views[0].privacy == "public"
    assert views[0].user is None


def test_create_private_view(create_organization, create_user, auth_client):
    user = create_user()
    create_organization(name="org", user=user)
    client = auth_client(user)

    response = client.post(
        reverse("create_view", kwargs={"org_name": "org"}),
        data={"name": "my-view", "query": "my-query", "privacy": "private"},
        follow=True,
    )
    assert b"The view has been successfully created." in response.content

    views = View.objects.all()
    assert len(views) == 1
    assert views[0].name == "my-view"
    assert views[0].query == "my-query"
    assert views[0].privacy == "private"
    assert views[0].user == user


def test_create_view_invalid_form(create_organization, create_user, auth_client):
    user = create_user()
    create_organization(name="org", user=user)
    client = auth_client(user)

    response = client.post(
        reverse("create_view", kwargs={"org_name": "org"}),
        data={},
        follow=True,
    )
    soup = BeautifulSoup(response.content, features="html.parser")

    content = soup.find("span", {"id": "error_1_id_name"}).text
    assert content == "This field is required."
    content = soup.find("span", {"id": "error_1_id_query"}).text
    assert content == "This field is required."
    content = soup.find("span", {"id": "error_1_id_privacy"}).text
    assert content == "This field is required."


def test_update_view(create_organization, create_user, create_view, auth_client):
    user = create_user()
    org = create_organization(name="org", user=user)
    view = create_view(
        name="my-view",
        query="my-query",
        organization=org,
        privacy="private",
        user=user,
    )

    client = auth_client(user)
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org", "view_id": view.id})
    )
    assert response.status_code == 200

    response = client.post(
        reverse("update_view", kwargs={"org_name": "org", "view_id": view.id}),
        data={"name": "edited-view", "query": "edited-query"},
        follow=True,
    )
    assert b"The view has been successfully updated." in response.content

    view = View.objects.first()
    assert view.name == "edited-view"
    assert view.query == "edited-query"


def test_update_view_permissions(
    create_organization, create_user, create_view, auth_client
):
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    user2 = create_user()
    create_organization(name="org2", user=user2)
    user3 = create_user()
    Membership.objects.create(
        user=user3,
        organization=org1,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    view = create_view(
        name="view1",
        query="my-query",
        organization=org1,
        privacy="private",
        user=user1,
    )

    # User1 can update the view
    client = auth_client(user1)
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 200

    # User2 is not member of the org, so it can't update the view
    client = auth_client(user2)
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 404

    # User3 is member of the org, but the view is private, so he can't update it
    client = auth_client(user3)
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 404

    # A public view can be updated by another member of the org
    view = create_view(
        name="view2",
        query="my-query",
        organization=org1,
        privacy="public",
    )
    client = auth_client(user3)
    response = client.get(
        reverse("update_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 200


def test_delete_view(create_organization, create_user, create_view, auth_client):
    user = create_user()
    org = create_organization(name="org", user=user)
    view = create_view(
        name="my-view",
        query="my-query",
        organization=org,
        privacy="private",
        user=user,
    )
    client = auth_client(user)

    assert View.objects.count() == 1
    client.delete(
        reverse("delete_view", kwargs={"org_name": "org", "view_id": view.id}),
        follow=True,
    )
    assert View.objects.count() == 0


def test_delete_view_permissions(
    create_organization, create_user, create_view, auth_client
):
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    user2 = create_user()
    create_organization(name="org2", user=user2)
    user3 = create_user()
    Membership.objects.create(
        user=user3,
        organization=org1,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    view = create_view(
        name="view1",
        query="my-query",
        organization=org1,
        privacy="private",
        user=user1,
    )

    # User1 can delete the view
    client = auth_client(user1)
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 200

    # User2 is not member of the org, so it can't delete the view
    client = auth_client(user2)
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 404

    # User3 is member of the org, but the view is private, so he can't delete it
    client = auth_client(user3)
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 404

    # A public view can be updated by another member of the org
    view = create_view(
        name="view2",
        query="my-query",
        organization=org1,
        privacy="public",
    )
    client = auth_client(user3)
    response = client.get(
        reverse("delete_view", kwargs={"org_name": "org1", "view_id": view.id})
    )
    assert response.status_code == 200
