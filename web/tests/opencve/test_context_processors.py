from unittest.mock import patch, PropertyMock

import pytest
from bs4 import BeautifulSoup
from django.test import RequestFactory, override_settings
from django.urls import reverse

from opencve.context_processors import feature_flags, opencve_version


@pytest.mark.parametrize(
    "full_url,canonical_url",
    [
        (reverse("vendors"), "/vendors/"),
        (reverse("weaknesses"), "/weaknesses/"),
        (reverse("cves"), "/cve/"),
        (f"{reverse('cves')}?search=foo", "/cve/?search=foo"),
        (
            f"{reverse('cves')}?vendor=google&search=foo",
            "/cve/?search=foo&vendor=google",
        ),
        (
            f"{reverse('cves')}?vendor=google&cvss=medium&product=android",
            "/cve/?cvss=medium&product=android&vendor=google",
        ),
        (f"{reverse('cves')}?vendor=debian", "/cve/?vendor=debian"),
        (f"{reverse('cves')}?vendor=debian&page=1", "/cve/?vendor=debian"),
        (f"{reverse('cves')}?vendor=debian&page=2", "/cve/?page=2&vendor=debian"),
        (f"{reverse('vendors')}?search=firepower", "/vendors/?search=firepower"),
        (
            f"{reverse('vendors')}?search=firepower&page=1&product_page=1",
            "/vendors/?search=firepower",
        ),
        (
            f"{reverse('vendors')}?search=firepower&product_page=2",
            "/vendors/?search=firepower",
        ),
    ],
)
@patch("cves.views.CveListView.paginate_by", new_callable=PropertyMock)
def test_canonical_url_context(
    mock_cves, db, create_cve, client, full_url, canonical_url
):
    mock_cves.return_value = 1

    create_cve("CVE-2024-31331")
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-20698")

    response = client.get(full_url)
    soup = BeautifulSoup(response.content, features="html.parser")
    assert (
        soup.find("link", {"rel": "canonical"})["href"]
        == f"http://testserver{canonical_url}"
    )


@override_settings(ENABLE_REGISTER=True)
def test_feature_flags_enable_register_true():
    request = RequestFactory().get("/")
    context = feature_flags(request)
    assert context["ENABLE_REGISTER"] is True


@override_settings(ENABLE_REGISTER=False)
def test_feature_flags_enable_register_false():
    request = RequestFactory().get("/")
    context = feature_flags(request)
    assert context["ENABLE_REGISTER"] is False


@override_settings(OPENCVE_VERSION="3.1.0")
def test_opencve_version():
    request = RequestFactory().get("/")
    context = opencve_version(request)
    assert context["OPENCVE_VERSION"] == "3.1.0"


def get_footer_version(response):
    soup = BeautifulSoup(response.content, features="html.parser")
    version = soup.find("footer", class_="main-footer").find("div", class_="pull-right")
    return " ".join(version.text.split()) if version else None


@override_settings(OPENCVE_VERSION="3.1.0", ENABLE_ONBOARDING=False)
def test_opencve_version_displayed_to_authenticated_users(auth_client):
    response = auth_client().get(reverse("cves"))
    assert get_footer_version(response) == "Version 3.1.0"


@override_settings(OPENCVE_VERSION="3.1.0")
def test_opencve_version_hidden_from_anonymous_users(db, client):
    response = client.get(reverse("cves"))
    assert response.status_code == 200
    assert get_footer_version(response) is None


@override_settings(OPENCVE_VERSION="", ENABLE_ONBOARDING=False)
def test_opencve_version_hidden_when_unknown(auth_client):
    response = auth_client().get(reverse("cves"))
    assert response.status_code == 200
    assert get_footer_version(response) is None
