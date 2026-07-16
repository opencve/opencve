from unittest.mock import PropertyMock, patch

import pytest
from django.test import override_settings
from django.urls import reverse

from changes.models import Change
from organizations.models import OrganizationAPIToken
from tests.api.v2.conftest import assert_v2_error, bearer, read_token


def cve_list_url():
    """Return the v2 CVE list URL."""
    return reverse("v2-cve-list")


def cve_detail_url(cve_id):
    """Return the v2 CVE detail URL."""
    return reverse("v2-cve-detail", kwargs={"cve_id": cve_id})


def cve_changes_url(cve_id):
    """Return the v2 CVE changes list URL."""
    return reverse("v2-cve-changes", kwargs={"cve_id": cve_id})


def cve_change_detail_url(cve_id, change_id):
    """Return the v2 CVE change detail URL."""
    return reverse(
        "v2-cve-change-detail",
        kwargs={"cve_id": cve_id, "change_id": change_id},
    )


def weakness_list_url():
    """Return the v2 weakness list URL."""
    return reverse("v2-weakness-list")


def weakness_detail_url(cwe_id):
    """Return the v2 weakness detail URL."""
    return reverse("v2-weakness-detail", kwargs={"cwe_id": cwe_id})


def weakness_cves_url(cwe_id):
    """Return the v2 weakness CVEs list URL."""
    return reverse("v2-weakness-cves", kwargs={"cwe_id": cwe_id})


def vendor_list_url():
    """Return the v2 vendor list URL."""
    return reverse("v2-vendor-list")


def vendor_detail_url(name):
    """Return the v2 vendor detail URL."""
    return reverse("v2-vendor-detail", kwargs={"name": name})


def vendor_cves_url(vendor_name):
    """Return the v2 vendor CVEs list URL."""
    return reverse("v2-vendor-cves", kwargs={"vendor_name": vendor_name})


def product_list_url(vendor_name):
    """Return the v2 product list URL."""
    return reverse("v2-vendor-product-list", kwargs={"vendor_name": vendor_name})


def product_detail_url(vendor_name, name):
    """Return the v2 product detail URL."""
    return reverse(
        "v2-vendor-product-detail",
        kwargs={"vendor_name": vendor_name, "name": name},
    )


def product_cves_url(vendor_name, product_name):
    """Return the v2 product CVEs list URL."""
    return reverse(
        "v2-product-cves",
        kwargs={"vendor_name": vendor_name, "product_name": product_name},
    )


@pytest.mark.django_db
def test_cve_list_without_filter(client, read_token, create_cve):
    """List CVEs without a search filter."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(cve_list_url(), **bearer(read_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    assert [item["cve_id"] for item in data["results"]] == [
        "CVE-2022-22965",
        "CVE-2021-44228",
    ]


@pytest.mark.django_db
def test_cve_retrieve_detail(client, read_token, create_cve, open_file):
    """Retrieve a single CVE with full detail fields."""
    create_cve("CVE-2021-44228")

    response = client.get(cve_detail_url("CVE-2021-44228"), **bearer(read_token))

    assert response.status_code == 200
    assert response.json() == open_file("serialized_cves/CVE-2021-44228.json")


@pytest.mark.django_db
def test_cve_list_with_valid_q_filter(client, read_token, create_cve):
    """Filter CVE list with a valid advanced search query."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(
        f"{cve_list_url()}?q=cve:CVE-2021-44228",
        **bearer(read_token),
    )

    assert response.status_code == 200
    assert [item["cve_id"] for item in response.json()["results"]] == ["CVE-2021-44228"]


@pytest.mark.django_db
def test_cve_list_with_invalid_q_filter(client, read_token, create_cve):
    """Reject CVE list requests with an invalid search query."""
    create_cve("CVE-2021-44228")

    response = client.get(f"{cve_list_url()}?q=invalid query", **bearer(read_token))

    assert_v2_error(response, "validation_error")
    assert "q" in response.json()["error"]["details"]


@pytest.mark.django_db
@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
def test_cve_retrieve_with_nvd_cpe_configurations_include(
    mock_nvd_json, client, read_token, create_cve
):
    """Include NVD CPE configurations when requested."""
    mock_nvd_json.return_value = {
        "configurations": [{"operator": "AND", "nodes": [{"operator": "OR"}]}]
    }
    create_cve("CVE-2021-44228")

    response = client.get(
        f"{cve_detail_url('CVE-2021-44228')}?include=nvd_cpe_configurations",
        **bearer(read_token),
    )

    assert response.status_code == 200
    assert response.json()["nvd_cpe_configurations"] == [
        {"operator": "AND", "nodes": [{"operator": "OR"}]}
    ]
    assert mock_nvd_json.call_count == 1


@pytest.mark.django_db
def test_cve_retrieve_rejects_unknown_include(client, read_token, create_cve):
    """Reject unknown include values on CVE detail."""
    create_cve("CVE-2021-44228")

    response = client.get(
        f"{cve_detail_url('CVE-2021-44228')}?include=unknown_field",
        **bearer(read_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={
            "include": (
                "Unknown include value(s): unknown_field. "
                "Allowed values: nvd_cpe_configurations, references."
            )
        },
    )


@pytest.mark.django_db
def test_cve_changes_list(client, read_token, create_cve):
    """List changes recorded for a CVE."""
    create_cve("CVE-2024-31331")

    response = client.get(cve_changes_url("CVE-2024-31331"), **bearer(read_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    change_ids = {item["id"] for item in data["results"]}
    assert change_ids == {
        "17d98772-fcde-469c-9694-7f9080da3747",
        "c8b1dcac-1137-4d07-b045-1903de09c7d9",
    }
    assert all(item["cve_id"] == "CVE-2024-31331" for item in data["results"])


@pytest.mark.django_db
def test_cve_change_detail(client, read_token, create_cve):
    """Retrieve a single CVE change with its change data."""
    create_cve("CVE-2024-31331")
    change = Change.objects.get(id="17d98772-fcde-469c-9694-7f9080da3747")

    response = client.get(
        cve_change_detail_url("CVE-2024-31331", change.id),
        **bearer(read_token),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(change.id)
    assert data["cve_id"] == "CVE-2024-31331"
    assert data["types"] == change.types
    assert data["change_data"]["id"] == str(change.id)


@pytest.mark.django_db
def test_cve_list_requires_authentication(client):
    """Reject unauthenticated CVE list requests."""
    response = client.get(cve_list_url())

    assert response.status_code == 401


@pytest.mark.django_db
def test_weakness_list(client, read_token, create_cve):
    """List CWE weaknesses from imported CVE data."""
    create_cve("CVE-2021-44228")

    response = client.get(weakness_list_url(), **bearer(read_token))

    assert response.status_code == 200
    cwe_ids = {item["cwe_id"] for item in response.json()["results"]}
    assert {"CWE-20", "CWE-400", "CWE-502", "CWE-917"}.issubset(cwe_ids)


@pytest.mark.django_db
def test_weakness_retrieve(client, read_token, create_cve):
    """Retrieve a single CWE weakness."""
    create_cve("CVE-2021-44228")

    response = client.get(weakness_detail_url("CWE-400"), **bearer(read_token))

    assert response.status_code == 200
    assert response.json()["cwe_id"] == "CWE-400"


@pytest.mark.django_db
def test_weakness_cves(client, read_token, create_cve):
    """List CVEs associated with a weakness."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(weakness_cves_url("CWE-400"), **bearer(read_token))

    assert response.status_code == 200
    assert [item["cve_id"] for item in response.json()["results"]] == ["CVE-2021-44228"]


@pytest.mark.django_db
def test_vendor_list(client, read_token, create_cve):
    """List vendors from imported CVE data."""
    create_cve("CVE-2021-44228")

    response = client.get(vendor_list_url(), **bearer(read_token))

    assert response.status_code == 200
    vendor_names = {item["name"] for item in response.json()["results"]}
    assert "apache" in vendor_names


@pytest.mark.django_db
def test_vendor_retrieve(client, read_token, create_cve):
    """Retrieve a single vendor."""
    create_cve("CVE-2021-44228")

    response = client.get(vendor_detail_url("apache"), **bearer(read_token))

    assert response.status_code == 200
    assert response.json()["name"] == "apache"


@pytest.mark.django_db
def test_product_list(client, read_token, create_cve):
    """List products for a vendor."""
    create_cve("CVE-2021-44228")

    response = client.get(product_list_url("apache"), **bearer(read_token))

    assert response.status_code == 200
    product_names = {item["name"] for item in response.json()["results"]}
    assert "log4j" in product_names


@pytest.mark.django_db
def test_product_retrieve(client, read_token, create_cve):
    """Retrieve a single product."""
    create_cve("CVE-2021-44228")

    response = client.get(
        product_detail_url("apache", "log4j"),
        **bearer(read_token),
    )

    assert response.status_code == 200
    assert response.json()["name"] == "log4j"


@pytest.mark.django_db
def test_vendor_cves(client, read_token, create_cve):
    """List CVEs associated with a vendor."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(vendor_cves_url("apache"), **bearer(read_token))

    assert response.status_code == 200
    assert [item["cve_id"] for item in response.json()["results"]] == ["CVE-2021-44228"]


@pytest.mark.django_db
def test_product_cves(client, read_token, create_cve):
    """List CVEs associated with a product."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(
        product_cves_url("apache", "log4j"),
        **bearer(read_token),
    )

    assert response.status_code == 200
    assert [item["cve_id"] for item in response.json()["results"]] == ["CVE-2021-44228"]


@pytest.mark.django_db
def test_vendor_retrieve_not_found(client, read_token):
    """Return 404 when retrieving a missing vendor."""
    response = client.get(vendor_detail_url("missing-vendor"), **bearer(read_token))

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_product_retrieve_not_found(client, read_token, create_cve):
    """Return 404 when retrieving a missing product."""
    create_cve("CVE-2021-44228")

    response = client.get(
        product_detail_url("apache", "missing-product"),
        **bearer(read_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_missing_catalog_read_scope_returns_403(client, create_org_token):
    """List rejects tokens missing the catalog:read scope."""
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["projects:write"],
    )

    response = client.get(cve_list_url(), **bearer(token_string))

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="catalog:read",
    )
