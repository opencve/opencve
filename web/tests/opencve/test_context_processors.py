from unittest.mock import patch, PropertyMock

import pytest
from bs4 import BeautifulSoup
from django.urls import reverse


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
            "/vendors/?product_page=2&search=firepower",
        ),
    ],
)
@patch("cves.views.CveListView.paginate_by", new_callable=PropertyMock)
@patch("cves.views.VendorListView.paginate_by", new_callable=PropertyMock)
def test_canonical_url_context(
    mock_vendors, mock_cves, db, create_cve, client, full_url, canonical_url
):
    mock_vendors.return_value = 1
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
