from datetime import date
from unittest.mock import patch

from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now
from freezegun import freeze_time

from organizations.models import Membership, Organization


# List Organizations


@override_settings(ENABLE_ONBOARDING=False)
def test_list_organizations(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    client = auth_client(user1)
    url = reverse("list_organizations")

    # No organization
    response = client.get(url)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-organizations"}).text
    assert "No organization yet" in content

    # User can see his own organization
    create_organization(name="organization1", user=user1, owner=True)
    response = client.get(url)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-organizations"}).text
    assert "organization1" in content

    # But not those of others
    user2 = create_user(username="user2")
    create_organization(name="organization2", user=user2, owner=True)
    response = client.get(url)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-organizations"}).text
    assert "organization2" not in content


# Create Organizations


@override_settings(ENABLE_ONBOARDING=False)
def test_create_organization(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    client = auth_client(user1)
    url = reverse("create_organization")

    response = client.post(url, data={"name": "orga1"}, follow=True)
    assert b"The organization has been successfully created." in response.content

    organization = Organization.objects.first()
    assert organization.name == "orga1"
    assert organization.members.first() == user1
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]


@override_settings(ENABLE_ONBOARDING=False)
def test_create_existing_organization(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    create_organization(name="orga1", user=user1)

    user2 = create_user(username="user2")
    client = auth_client(user2)
    url = reverse("create_organization")

    response = client.post(url, data={"name": "orga1"}, follow=True)
    assert b"This organization name is not available." in response.content
    assert Organization.objects.count() == 1


# Edit Organizations


def test_edit_organization_is_owner(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    create_organization(name="orga1", user=user1)
    user2 = create_user(username="user2")
    create_organization(name="orga2", user=user2)

    # User1 can access his organization
    client = auth_client(user1)
    url = reverse("edit_organization", kwargs={"org_name": "orga1"})
    assert client.get(url).status_code == 200

    # User2 can not access User1's org
    client = auth_client(user2)
    url = reverse("edit_organization", kwargs={"org_name": "orga2"})
    assert client.get(url).status_code == 200
    url = reverse("edit_organization", kwargs={"org_name": "orga1"})
    assert client.get(url).status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_edit_organization_not_found(auth_client, create_user):
    user1 = create_user(username="user1")
    client = auth_client(user1)
    url = reverse("edit_organization", kwargs={"org_name": "orga1"})

    response = client.get(url)
    assert response.status_code == 404


def test_edit_organization(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    client = auth_client(user1)
    create_organization(name="orga1", user=user1, owner=True)
    url = reverse("edit_organization", kwargs={"org_name": "orga1"})

    response = client.post(url, data={}, follow=True)
    assert b"The organization has been successfully updated." in response.content


# Delete Organizations


@override_settings(ENABLE_ONBOARDING=False)
def test_delete_organization_is_owner(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    create_organization(name="orga1", user=user1)
    user2 = create_user(username="user2")
    create_organization(name="orga2", user=user2)

    # User1 can delete his organization
    client = auth_client(user1)
    url = reverse("delete_organization", kwargs={"org_name": "orga1"})
    assert client.get(url).status_code == 200

    # User2 can not delete User1's org
    client = auth_client(user2)
    url = reverse("delete_organization", kwargs={"org_name": "orga2"})
    assert client.get(url).status_code == 200
    assert client.post(url).status_code == 302

    url = reverse("delete_organization", kwargs={"org_name": "orga1"})
    assert client.get(url).status_code == 404
    assert client.post(url).status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_delete_organization(auth_client, create_user, create_organization):
    user = create_user(username="user1")
    client = auth_client(user)
    create_organization(name="orga1", user=user, owner=True)

    url = reverse("delete_organization", kwargs={"org_name": "orga1"})
    response = client.get(url)
    assert response.status_code == 200

    response = client.post(url, follow=True)
    assert response.status_code == 200
    assert response.redirect_chain == [(reverse("list_organizations"), 302)]

    response = client.get(url)
    assert response.status_code == 404


# List Memberships


def test_list_memberships(auth_client, create_user, create_organization):
    user = create_user(username="user1", email="user1@example.com")
    client = auth_client(user)
    create_organization(name="orga1", user=user, owner=True)
    url = reverse("edit_organization", kwargs={"org_name": "orga1"})

    response = client.get(url)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-members"}).find_all("td")
    assert content[0].text == "user1"
    assert content[1].text == "user1@example.com"
    assert content[2].text == "owner"


# Create Memberships


@override_settings(ENABLE_ONBOARDING=False)
def test_create_memberships_is_owner(auth_client, create_user, create_organization):
    user1 = create_user(username="user1", email="user1@example.com")
    create_organization(name="orga1", user=user1)
    user2 = create_user(username="user2", email="user2@example.com")
    create_user(username="user3", email="user3@example.com")
    url = reverse("list_organization_members", kwargs={"org_name": "orga1"})

    # User2 can not add new member
    client = auth_client(user2)
    response = client.post(
        url, data={"email": "user3@example.com", "role": "member"}, follow=True
    )
    assert response.status_code == 404

    # User1 can create new member
    client = auth_client(user1)
    response = client.post(
        url, data={"email": "user3@example.com", "role": "member"}, follow=True
    )
    assert response.status_code == 200


@patch("organizations.views.get_random_string")
def test_create_memberships(
    mock_random_string, auth_client, create_user, create_organization
):
    mock_random_string.return_value = "foobar"

    user = create_user(username="user1", email="user1@example.com")
    client = auth_client(user)
    organization = create_organization(name="orga1", user=user, owner=True)
    create_user(username="member1", email="member1@example.com")
    url = reverse("list_organization_members", kwargs={"org_name": "orga1"})

    with freeze_time("2024-01-01"):
        response = client.post(
            url, data={"email": "member1@example.com", "role": "member"}, follow=True
        )

    soup = BeautifulSoup(response.content, features="html.parser")
    assert (
        "The new member has been added."
        in soup.find("div", {"class": "alert-success"}).text
    )
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]

    membership = Membership.objects.filter(user__email="member1@example.com").first()
    assert membership.role == "member"
    assert membership.organization == organization
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined is None
    assert membership.key == "foobar"
    assert membership.is_owner is False
    assert membership.is_invited is True


def test_create_memberships_invalid_payload(
    auth_client, create_user, create_organization
):
    user = create_user(username="user1", email="user1@example.com")
    client = auth_client(user)
    create_organization(name="orga1", user=user, owner=True)
    url = reverse("list_organization_members", kwargs={"org_name": "orga1"})

    response = client.post(url, data={"foo": "bar"}, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    assert "Error in the form" in soup.find("div", {"class": "alert-error"}).text
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]

    response = client.post(
        url, data={"email": "user@doesnotexist.com", "role": "owner"}, follow=True
    )
    soup = BeautifulSoup(response.content, features="html.parser")
    assert "User not found" in soup.find("div", {"class": "alert-error"}).text
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]

    response = client.post(
        url, data={"email": "user1@example.com", "role": "owner"}, follow=True
    )
    soup = BeautifulSoup(response.content, features="html.parser")
    assert "Member already exist" in soup.find("div", {"class": "alert-error"}).text
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]


# Delete Memberships


@override_settings(ENABLE_ONBOARDING=False)
def test_delete_memberships_is_owner(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    member = create_user(username="member")
    organization = create_organization(name="orga1", user=user1, owner=True)
    membership = Membership.objects.create(
        organization=organization, user=member, role=Membership.MEMBER
    )
    url = reverse(
        "delete_organization_member",
        kwargs={"org_name": "orga1", "member_id": membership.id},
    )

    # User2 can not delete members
    user2 = create_user(username="user2", email="user2@example.com")
    client = auth_client(user2)
    response = client.post(url, data={})
    assert response.status_code == 404

    # User1 can delete member
    client = auth_client(user1)
    response = client.post(url, data={}, follow=True)
    assert response.status_code == 200
    assert not Membership.objects.filter(user=member).exists()


def test_delete_memberships(auth_client, create_user, create_organization):
    user1 = create_user(username="user1")
    member = create_user(username="member")
    organization = create_organization(name="orga1", user=user1, owner=True)
    membership = Membership.objects.create(
        organization=organization, user=member, role=Membership.MEMBER
    )
    url = reverse(
        "delete_organization_member",
        kwargs={"org_name": "orga1", "member_id": membership.id},
    )

    client = auth_client(user1)
    response = client.post(url, data={}, follow=True)
    assert response.status_code == 200
    assert not Membership.objects.filter(user=member).exists()


def test_delete_memberships_without_owners(
    auth_client, create_user, create_organization
):
    user1 = create_user(username="user1")
    organization = create_organization(name="orga1", user=user1, owner=True)
    membership = Membership.objects.first()
    url = reverse(
        "delete_organization_member",
        kwargs={"org_name": "orga1", "member_id": membership.id},
    )

    # User1 is the only owner, he can't remove himself
    client = auth_client(user1)
    response = client.post(url, data={}, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")

    assert (
        "You cannot leave this organization as you are the only owner"
        in soup.find("div", {"class": "alert-error"}).text
    )
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]

    # Another owner can do it
    user2 = create_user(username="user2")
    Membership.objects.create(
        organization=organization, user=user2, role=Membership.OWNER, date_joined=now()
    )
    client = auth_client(user2)
    response = client.post(url, data={}, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    assert (
        "The member has been removed."
        in soup.find("div", {"class": "alert-success"}).text
    )
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]


@override_settings(ENABLE_ONBOARDING=False)
def test_delete_membership_success_url(auth_client, create_user, create_organization):
    user1 = create_user(username="user1", email="user1@example.com")
    organization = create_organization(name="orga1", user=user1, owner=True)
    member1 = Membership.objects.first()
    user2 = create_user(username="user2", email="user2@example.com")
    member2 = Membership.objects.create(
        organization=organization, user=user2, role=Membership.OWNER, date_joined=now()
    )
    user3 = create_user(username="user3", email="user3@example.com")
    Membership.objects.create(
        organization=organization, user=user3, role=Membership.OWNER, date_joined=now()
    )
    client = auth_client(user1)

    # Removing another user redirects to the edit_organization url
    url = reverse(
        "delete_organization_member",
        kwargs={"org_name": "orga1", "member_id": member2.id},
    )
    response = client.post(url, data={}, follow=True)
    assert response.redirect_chain == [
        (reverse("edit_organization", kwargs={"org_name": "orga1"}), 302)
    ]

    # Removing the current user redirects to the list_organizations url
    url = reverse(
        "delete_organization_member",
        kwargs={"org_name": "orga1", "member_id": member1.id},
    )
    response = client.post(url, data={}, follow=True)
    assert response.redirect_chain == [(reverse("list_organizations"), 302)]


# Memberships Invitation


@override_settings(ENABLE_ONBOARDING=False)
def test_organization_invitation(auth_client, create_user, create_organization):
    user1 = create_user(username="user1", email="user1@example.com")
    organization = create_organization(name="orga1", user=user1, owner=True)
    user2 = create_user(username="user2", email="user2@example.com")
    member = Membership.objects.create(
        organization=organization, user=user2, role=Membership.MEMBER, key="foobar"
    )

    # User1 can see that User2 is invited
    client = auth_client(user1)
    url = reverse("edit_organization", kwargs={"org_name": "orga1"})
    response = client.get(url, data={}, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-members"}).find_all("td")
    assert content[4].text == "user2"
    assert content[5].text == "user2@example.com"
    assert content[6].text == "invited"

    # User2 can accept invitation
    client = auth_client(user2)
    url = reverse("list_organizations")
    response = client.get(url, data={}, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-organizations"}).find_all("td")
    assert "Accept Invitation" in content[2].text

    url = reverse(
        "accept_organization_invitation", kwargs={"org_name": "orga1", "key": "foobar"}
    )
    with freeze_time("2024-01-01"):
        response = client.get(url, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")
    assert (
        "The invitation has been accepted"
        in soup.find("div", {"class": "alert-success"}).text
    )
    updated_membership = Membership.objects.filter(user=user2).first()
    assert updated_membership.key is None
    assert updated_membership.date_joined.date() == date(2024, 1, 1)
