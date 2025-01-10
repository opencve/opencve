from unittest.mock import patch, PropertyMock

import pytest
from django.test import override_settings
from django.urls import reverse
from bs4 import BeautifulSoup

from users.models import User, UserTag, CveTag


@override_settings(ENABLE_ONBOARDING=False)
def test_list_cves_by_case_insensitive_vendors(db, create_cve, auth_client):
    create_cve("CVE-2022-22965")
    client = auth_client()
    response = client.get(f"{reverse('cves')}?vendor=foobar")
    assert response.status_code == 404

    response = client.get(f"{reverse('cves')}?vendor=oracle")
    assert response.status_code == 200

    response = client.get(f"{reverse('cves')}?vendor=Oracle")
    assert response.status_code == 200

    response = client.get(f"{reverse('cves')}?vendor=Oracle&product=Commerce_Platform")
    assert response.status_code == 200


@override_settings(ENABLE_ONBOARDING=False)
def test_list_vendors_case_insensitive(db, create_cve, auth_client):
    create_cve("CVE-2023-22490")
    client = auth_client()

    response = client.get(f"{reverse('vendors')}?search=Git-scm")
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-vendors"}).find_all("td")
    assert content[0].text == "Git-scm"

    response = client.get(f"{reverse('vendors')}?search=GIT")
    soup = BeautifulSoup(response.content, features="html.parser")
    content = soup.find("table", {"id": "table-vendors"}).find_all("td")
    assert content[0].text == "Git-scm"
    content = soup.find("table", {"id": "table-products"}).find_all("td")
    assert content[0].text == "Git"
    assert content[1].text == "Git-scm"


@override_settings(ENABLE_ONBOARDING=False)
def test_list_cves_with_sensitive_tags(create_cve, create_user, auth_client):
    user = create_user()
    client = auth_client(user)

    # tag is in lower case
    tag = UserTag.objects.create(name="foo", user=user)
    cve = create_cve("CVE-2023-22490")
    CveTag.objects.create(user=user, cve=cve, tags=[tag.name])

    # tag starts with a capital letter
    tag = UserTag.objects.create(name="BAR", user=user)
    cve = create_cve("CVE-2024-31331")
    CveTag.objects.create(user=user, cve=cve, tags=[tag.name])

    def find_cves(url):
        response = client.get(url, follow=True)
        soup = BeautifulSoup(response.content, features="html.parser")
        return [s.find("a").text for s in soup.find_all("tr", {"class": "cve-header"})]

    assert find_cves(reverse("cves")) == ["CVE-2024-31331", "CVE-2023-22490"]
    assert find_cves(f"{reverse('cves')}?tag=foo") == ["CVE-2023-22490"]
    assert find_cves(f"{reverse('cves')}?tag=BAR") == ["CVE-2024-31331"]


@override_settings(ENABLE_ONBOARDING=False)
def test_list_cves_with_null_characters(db, create_cve, client):
    create_cve("CVE-2022-22965")

    response = client.get(f"{reverse('cves')}?vendor=oracle")
    assert response.status_code == 200

    response = client.get(f"{reverse('cves')}?vendor=oracle%00")
    assert response.status_code == 404

    response = client.get(f"{reverse('cves')}?search=foo%00bar")
    assert response.status_code == 404

    response = client.get(f"{reverse('cves')}?weakness%00=cwe-1234")
    assert response.status_code == 404


urls_to_check = {
    "cves": [
        reverse("cves"),
        "CVEs and Security Vulnerabilities - OpenCVE",
        "Explore the latest vulnerabilities and security issues in the CVE database",
    ],
    "cves-vendor-filtred": [
        f"{reverse('cves')}?vendor=google",
        "Google CVEs and Security Vulnerabilities - OpenCVE",
        "Explore the latest vulnerabilities and security issues of Google in the CVE database",
    ],
    "cves-product-filtred": [
        f"{reverse('cves')}?vendor=google&product=android",
        "Android CVEs and Security Vulnerabilities - OpenCVE",
        "Explore the latest vulnerabilities and security issues of Android in the CVE database",
    ],
    "cves-weakness-filtred": [
        f"{reverse('cves')}?weakness=CWE-783",
        "CWE-783 CVEs and Security Vulnerabilities - OpenCVE",
        "Explore the latest vulnerabilities and security issues of CWE-783 in the CVE database",
    ],
}


@pytest.mark.parametrize("url_to_check", list(urls_to_check.keys()))
@override_settings(ENABLE_ONBOARDING=False)
def test_cves_list_title(db, create_cve, client, url_to_check):
    url, title, description = urls_to_check[url_to_check]
    create_cve("CVE-2023-22490")
    create_cve("CVE-2024-31331")

    response = client.get(url)
    soup = BeautifulSoup(response.content, features="html.parser")

    assert soup.find("title").text == title
    assert soup.find("meta", {"name": "description"})["content"] == description


@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_title(
    mock_nvd, mock_mitre, mock_vulnrichment, db, create_cve, client
):
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_vulnrichment.return_value = {}
    create_cve("CVE-2024-31331")

    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    soup = BeautifulSoup(response.content, features="html.parser")

    assert soup.find("title").text == "CVE-2024-31331 - Vulnerability Details - OpenCVE"
    assert (
        soup.find("meta", {"name": "description"})["content"]
        == "In setMimeGroup of PackageManagerService.java, there is a possible way to hide the service from Settings due to a logic error in the code. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation."
    )


def test_statistics(create_variable, client):
    create_variable("statistics_one", {"foo": 1000})
    create_variable("statistics_two", {"bar": 2000})
    create_variable("statistics_cves_count_last_days", {"7_days": {}})

    response = client.get(reverse("statistics"))
    assert response.status_code == 200
    assert b'STATISTICS_ONE = {"foo": 1000};' in response.content
    assert b'STATISTICS_TWO = {"bar": 2000};' in response.content
    assert b"STATISTICS_CVES_COUNT_LAST_DAYS" not in response.content


@override_settings(ENABLE_ONBOARDING=False)
def test_advanced_search_link_unauthenticated(client, auth_client):
    def get_soup(c):
        response = c.get(reverse("cves"))
        return BeautifulSoup(response.content, features="html.parser")

    # Unauthenticated user
    soup = get_soup(client)
    link = soup.find("a", {"class": "advanced-search-link"})
    assert link["href"] == reverse("account_login")
    assert (
        link["title"] == "You must be authenticated to use the advanced search feature"
    )

    # Authenticated user
    client = auth_client()
    soup = get_soup(client)
    link = soup.find("button", {"class": "advanced-search-link"})
    assert link.text.strip() == "Switch to Advanced Search (Beta)"


@override_settings(ENABLE_ONBOARDING=False)
def test_switch_search_mode(create_user, auth_client):
    url = reverse("cves")
    user = create_user()
    client = auth_client(user)
    assert user.settings == {"activities_view": "all"}

    # Switch to advanced mode
    client.post(url, data={}, follow=True)
    user = User.objects.first()
    assert user.settings == {"activities_view": "all", "search_mode": "advanced"}

    # Back to basic mode
    client.post(url, data={}, follow=True)
    user = User.objects.first()
    assert user.settings == {"activities_view": "all", "search_mode": "basic"}


@pytest.mark.parametrize(
    "query, results",
    [
        ("foobarbaz", []),
        ("git", ["CVE-2023-22490"]),
        ("CVE-2021-44228", ["CVE-2021-44228"]),
        ("CVE-2021-44228 OR CVE-2023-22490", ["CVE-2021-44228", "CVE-2023-22490"]),
        ("cve=CVE-2023-22490", ["CVE-2023-22490"]),
        ("cve:CVE-2022", ["CVE-2022-20698", "CVE-2022-22965"]),
        ("description:git", ["CVE-2023-22490"]),
        ("title:ldap", ["CVE-2021-44228"]),
        (
            "title:ldap OR title:log4j OR title:git",
            ["CVE-2021-44228", "CVE-2023-22490"],
        ),
        (
            "title:LDAP OR title:Log4J OR title:Git",
            ["CVE-2021-44228", "CVE-2023-22490"],
        ),
        ("title:LDAP AND title:Log4J AND title:Git", []),
        ("vendor:cisco", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor:cisco AND cvss31>=9", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor:cisco AND cvss31=10", ["CVE-2021-44228"]),
        (
            "vendor:cisco AND (cvss31=10 OR cvss20>7)",
            ["CVE-2021-44228", "CVE-2022-22965"],
        ),
        ("product:jboss_fuse", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("product:jboss_fuse AND cvss31=10", ["CVE-2021-44228"]),
    ],
)
@override_settings(ENABLE_ONBOARDING=False)
def test_advanced_search(create_cve, auth_client, query, results):
    client = auth_client()
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-20698")
    create_cve("CVE-2022-22965")
    create_cve("CVE-2023-22490")
    create_cve("CVE-2024-31331")

    response = client.get(f"{reverse('cves')}?q={query}")
    soup = BeautifulSoup(response.content, features="html.parser")
    cves = [s.find("a").text for s in soup.find_all("tr", {"class": "cve-header"})]

    assert response.status_code == 200
    assert sorted(cves) == sorted(results)


@override_settings(ENABLE_ONBOARDING=False)
def test_advanced_search_with_usertag(create_cve, create_user, auth_client):
    user = create_user()
    client = auth_client(user)

    # UserTag not found
    response = client.get(f"{reverse('cves')}?q=userTag:test")
    assert response.status_code == 404

    # Create a UserTag and assign it to 1 CVE
    create_cve("CVE-2021-44228")
    cve = create_cve("CVE-2022-22965")
    tag = UserTag.objects.create(name="test", user=user)
    CveTag.objects.create(user=user, cve=cve, tags=[tag.name])

    response = client.get(f"{reverse('cves')}?q=userTag:test")
    soup = BeautifulSoup(response.content, features="html.parser")
    cves = [s.find("a").text for s in soup.find_all("tr", {"class": "cve-header"})]

    assert response.status_code == 200
    assert cves == ["CVE-2022-22965"]
