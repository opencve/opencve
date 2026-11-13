import pytest
from django.test import override_settings
from django.urls import reverse

CVE_ID = "CVE-2024-31331"
CHANGE_ID = "c8b1dcac-1137-4d07-b045-1903de09c7d9"

PUBLIC_URLS = [
    ("cves", {}),
    ("cves_export_csv", {}),
    ("cve", {"cve_id": CVE_ID}),
    ("change", {"cve_id": CVE_ID, "id": CHANGE_ID}),
    ("vendors", {}),
    ("vendors_load_more", {"list_type": "vendors"}),
    ("weaknesses", {}),
    ("statistics", {}),
]


@pytest.fixture
def public_data(create_cve, create_variable):
    create_cve(CVE_ID)
    create_variable("statistics_cves_count_last_days", {"7_days": {}})


@pytest.mark.parametrize("url_name,kwargs", PUBLIC_URLS)
def test_anonymous_access_enabled_by_default(db, client, public_data, url_name, kwargs):
    response = client.get(reverse(url_name, kwargs=kwargs))
    assert response.status_code == 200


@override_settings(ENABLE_ANONYMOUS_ACCESS=False)
@pytest.mark.parametrize("url_name,kwargs", PUBLIC_URLS)
def test_anonymous_access_disabled_redirects_to_login(
    db, client, public_data, url_name, kwargs
):
    url = reverse(url_name, kwargs=kwargs)
    response = client.get(url)
    assert response.status_code == 302
    assert response.url == f"{reverse('account_login')}?next={url}"


@override_settings(ENABLE_ANONYMOUS_ACCESS=False, ENABLE_ONBOARDING=False)
@pytest.mark.parametrize("url_name,kwargs", PUBLIC_URLS)
def test_anonymous_access_disabled_allows_authenticated_users(
    db, auth_client, public_data, url_name, kwargs
):
    response = auth_client().get(reverse(url_name, kwargs=kwargs))
    assert response.status_code == 200


@override_settings(ENABLE_ANONYMOUS_ACCESS=False)
def test_anonymous_access_disabled_keeps_query_string_in_next(db, client):
    response = client.get(f"{reverse('cves')}?q=vendor:google")
    assert response.status_code == 302
    assert response.url == (
        f"{reverse('account_login')}?next=/cve/%3Fq%3Dvendor%3Agoogle"
    )


@override_settings(ENABLE_ANONYMOUS_ACCESS=False)
def test_anonymous_access_disabled_keeps_login_page_available(db, client):
    response = client.get(reverse("account_login"))
    assert response.status_code == 200
