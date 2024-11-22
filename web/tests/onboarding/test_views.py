from datetime import date

import pytest
from bs4 import BeautifulSoup
from django.urls import reverse
from freezegun import freeze_time

from cves.constants import PRODUCT_SEPARATOR
from organizations.models import Membership, Organization
from projects.models import Notification, Project
from users.models import CveTag, UserTag


def test_onboarding_dispatch(client, auth_client, create_user, create_organization):
    url = reverse("onboarding")

    # Unauthenticated user can not access the onboarding
    response = client.get(url, follow=True)
    assert response.redirect_chain == [
        (f"{reverse('account_login')}?next={reverse('onboarding')}", 302)
    ]

    # User without organization can access the onboarding
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("onboarding"))
    assert response.status_code == 200
    assert b"Welcome to OpenCVE john" in response.content

    # User with an organization is redirected to the homepage
    create_organization(name="orga", user=user)
    response = client.get(reverse("onboarding"), follow=True)
    assert response.redirect_chain == [(reverse("home"), 302)]


def test_onboarding_access_settings(auth_client, create_user):
    user = create_user(username="john")
    client = auth_client(user)

    response = client.get(reverse("cves"), follow=True)
    assert response.redirect_chain == [(reverse("onboarding"), 302)]

    response = client.get(reverse("account_logout"))
    assert response.status_code == 200


def test_onboarding_invalid_form(auth_client, create_user, create_organization):
    user = create_user(username="john")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(url, data={}, follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")

    content = soup.find("span", {"id": "error_1_id_organization"}).text
    assert content == "This field is required."
    content = soup.find("span", {"id": "error_1_id_project"}).text
    assert content == "This field is required."


@freeze_time("2024-01-01")
def test_onboarding_valid_form(auth_client, create_user, create_organization):
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")

    response = client.post(
        url, data={"organization": "myorga", "project": "myproject"}, follow=True
    )
    assert response.redirect_chain == [(reverse("home"), 302)]

    soup = BeautifulSoup(response.content, features="html.parser")
    assert "Welcome to OpenCVE" in soup.find("div", {"class": "alert-success"}).text

    orga = Organization.objects.first()
    assert orga.name == "myorga"
    assert [o for o in orga.members.all()] == [user]

    membership = Membership.objects.first()
    assert membership.user == user
    assert membership.organization == orga
    assert membership.role == Membership.OWNER
    assert membership.date_invited.date() == date(2024, 1, 1)
    assert membership.date_joined.date() == date(2024, 1, 1)
    assert not membership.key

    project = Project.objects.first()
    assert project.name == "myproject"
    assert project.organization == orga
    assert project.subscriptions == {
        "vendors": ["linux", "microsoft"],
        "products": [f"djangoproject{PRODUCT_SEPARATOR}django"],
    }

    notification = Notification.objects.first()
    assert notification.name == "Critical Vulnerabilities"
    assert notification.type == "email"
    assert notification.configuration == {
        "types": [
            "created",
            "first_time",
            "weaknesses",
            "cpes",
            "vendors",
            "metrics",
        ],
        "extras": {"email": "john@doe.com"},
        "metrics": {"cvss31": "9"},
    }

    user_tag = user.tags.first()
    assert user_tag.name == "log4j"
    assert user_tag.color == "#0A0031"
    assert user_tag.description == "This is an example tag"


@pytest.mark.parametrize(
    "tag,count,result",
    [
        ("log4j", 1, ["log4j"]),
        ("example", 2, ["example", "log4j"]),
    ],
)
def test_onboarding_user_tag(
    auth_client, create_user, create_organization, create_cve, tag, count, result
):
    url = reverse("onboarding")
    user = create_user()
    UserTag.objects.create(
        name=tag, color="#FFFFFF", description="Already existing", user=user
    )
    client = auth_client(user)

    client.post(url, data={"organization": "orga1", "project": "myproject"})

    user_tags = user.tags.all()
    assert len(user_tags) == count
    assert [t.name for t in user_tags] == result


def test_onboarding_without_cve(auth_client, create_user, create_organization):
    user = create_user(username="john", email="john@doe.com")
    client = auth_client(user)
    url = reverse("onboarding")
    client.post(url, data={"organization": "myorga", "project": "myproject"})

    # Tag has been created but not associated to the CVE
    user_tag = user.tags.first()
    assert user_tag.name == "log4j"
    assert CveTag.objects.count() == 0


def test_onboarding_cve_tag(auth_client, create_user, create_organization, create_cve):
    url = reverse("onboarding")
    cve = create_cve("CVE-2021-44228")
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")

    # User1 has no tag associated to the CVE
    client = auth_client(user1)
    client.post(url, data={"organization": "orga1", "project": "myproject"})

    cve_tag = CveTag.objects.filter(user=user1).all()
    assert len(cve_tag[0].tags) == 1
    assert cve_tag[0].tags == ["log4j"]
    assert cve_tag[0].cve == cve

    # User2 already has a tag associated to the CVE
    tag = UserTag.objects.create(name="existing_tag", user=user2)
    CveTag.objects.create(tags=[tag.name], cve=cve, user=user2)
    client = auth_client(user2)
    client.post(url, data={"organization": "orga2", "project": "myproject"})

    cve_tag = CveTag.objects.filter(user=user2).all()
    assert len(cve_tag[0].tags) == 2
    assert cve_tag[0].tags == ["existing_tag", "log4j"]
    assert cve_tag[0].cve == cve
