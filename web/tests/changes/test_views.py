import pytest
from bs4 import BeautifulSoup
from django.urls import reverse

from users.models import User


@pytest.mark.django_db
def test_list_dashboard_changes_no_activity(
    create_user, create_organization, create_project, auth_client
):
    user = create_user()
    organization = create_organization("myorga", user)
    client = auth_client(user)
    create_project(name="myproject", organization=organization, vendors=["google"])

    response = client.get(reverse("home"), follow=True)
    assert b"No activity." in response.content


@pytest.mark.django_db
def test_list_dashboard_changes(
    create_user, create_organization, create_project, create_cve, auth_client
):
    user = create_user()
    organization = create_organization("myorga", user)
    client = auth_client(user)
    create_project(name="myproject", organization=organization, vendors=["google"])
    create_cve("CVE-2024-31331")

    response = client.get(reverse("home"), follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")

    assert response.status_code == 200

    # 2 changes for the same CVE
    headers = soup.find_all("h3", {"class": "timeline-header"})
    assert [h.find("a").text for h in headers] == ["CVE-2024-31331", "CVE-2024-31331"]

    # Last change
    change_id = "c8b1dcac-1137-4d07-b045-1903de09c7d9"
    boxes = soup.find("div", {"id": change_id}).find_all("h4", {"class": "box-title"})
    assert [b.text.split("\n")[0] for b in boxes] == ["Weaknesses"]

    # First change
    change_id = "17d98772-fcde-469c-9694-7f9080da3747"
    boxes = soup.find("div", {"id": change_id}).find_all("h4", {"class": "box-title"})
    assert [b.text.split("\n")[0] for b in boxes] == [
        "First Time",
        "Cpes",
        "Vendors",
        "Metrics",
    ]


@pytest.mark.django_db
def test_dashboard_settings(
    create_user, create_organization, create_project, create_cve, auth_client
):
    user = create_user()
    organization = create_organization("myorga", user)
    client = auth_client(user)
    create_project(name="myproject", organization=organization, vendors=["google"])
    create_cve("CVE-2022-20698")
    create_cve("CVE-2024-31331")

    # The dashboard displays all changes by default
    assert user.settings.get("activities_view") == "all"

    response = client.get(reverse("home"), follow=True)
    soup = BeautifulSoup(response.content, features="html.parser")

    headers = soup.find_all("h3", {"class": "timeline-header"})
    assert [h.find("a").text for h in headers] == [
        "CVE-2022-20698",
        "CVE-2024-31331",
        "CVE-2024-31331",
    ]

    # We change the `activities_view` setting (from `all` to `subscriptions`)
    response = client.post(reverse("home"), data={"view": "subscriptions"}, follow=True)
    assert b"Your dashboard settings have been updated." in response.content

    # The user setting has been updated
    user = User.objects.first()
    assert user.settings.get("activities_view") == "subscriptions"

    # The user only subscribed to google, which is included in a single CVE
    soup = BeautifulSoup(response.content, features="html.parser")
    headers = soup.find_all("h3", {"class": "timeline-header"})
    assert [h.find("a").text for h in headers] == ["CVE-2024-31331", "CVE-2024-31331"]
