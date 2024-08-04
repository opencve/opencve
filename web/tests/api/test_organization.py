import pytest
from django.urls import reverse


def test_unauthenticated_user(client, user_client):
    response = client.get(reverse("organization-list"))
    assert response.status_code == 403

    user, auth_client = user_client()
    response = auth_client.get(reverse("organization-list"))
    assert response.status_code == 200


def test_list_organizations(user_client, create_organization):
    user, organization = create_organization(name="Orga1")
    _, client = user_client(user)

    response = client.get(reverse("organization-list"))
    assert response.status_code == 200
    organizations = response.json()
    assert organizations["count"] == 1
    assert organizations["results"][0]["name"] == "Orga1"

    _, organization = create_organization(name="Orga2", user=user)
    response = client.get(reverse("organization-list"))
    organizations = response.json()
    assert response.status_code == 200
    assert organizations["count"] == 2
    assert sorted([o["name"] for o in organizations["results"]]) == ["Orga1", "Orga2"]


def test_list_organizations_by_users(user_client, create_user, create_organization):
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    create_organization(name="Orga1", user=user1)
    create_organization(name="Orga2", user=user2)
    create_organization(name="Orga3", user=user2)

    # User1 has 1 organization
    _, client = user_client(user1)
    response = client.get(reverse("organization-list"))
    organizations = response.json()
    assert organizations["count"] == 1
    assert sorted([o["name"] for o in organizations["results"]]) == ["Orga1"]

    # User2 has 2 organizations
    _, client = user_client(user2)
    response = client.get(reverse("organization-list"))
    organizations = response.json()
    assert organizations["count"] == 2
    assert sorted([o["name"] for o in organizations["results"]]) == ["Orga2", "Orga3"]


def test_get_organization(user_client, create_user, create_organization):
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    create_organization(name="Orga1", user=user1)
    create_organization(name="Orga2", user=user2)

    # User1 can access his organization
    _, client = user_client(user1)
    response = client.get(reverse("organization-detail", kwargs={"name": "Orga1"}))
    assert response.status_code == 200
    assert response.json()["name"] == "Orga1"

    # User2 can't access User1 organization
    _, client = user_client(user2)
    response = client.get(reverse("organization-detail", kwargs={"name": "Orga1"}))
    assert response.status_code == 404
    assert response.json() == {"detail": "No Organization matches the given query."}

    response = client.get(reverse("organization-detail", kwargs={"name": "Orga2"}))
    assert response.status_code == 200
    assert response.json()["name"] == "Orga2"
