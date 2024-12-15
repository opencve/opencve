from unittest.mock import patch, PropertyMock

import pytest
from django.test import override_settings
from django.urls import reverse
from bs4 import BeautifulSoup

from users.models import UserTag, CveTag


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
