import json
from unittest.mock import patch, PropertyMock

import pytest
from django.contrib.messages import get_messages
from django.test import override_settings
from django.urls import reverse
from bs4 import BeautifulSoup
from django.test.client import RequestFactory
from django.contrib.auth.models import AnonymousUser

from cves.constants import PRODUCT_SEPARATOR
from cves.views import CveListView, CveDetailView
from cves.models import Vendor, Product, Cve
from users.models import UserTag, CveTag
from projects.models import CveTracker


@override_settings(ENABLE_ONBOARDING=False)
def test_list_cves_by_case_insensitive_vendors(db, create_cve, auth_client):
    create_cve("CVE-2022-22965")
    client = auth_client()
    response = client.get(f"{reverse('cves')}?vendor=foobar")
    assert response.status_code == 200

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
    assert content[0].text.strip() == "Git"
    assert content[1].text.strip() == "Git-scm"


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


# Tests for CveDetailView


@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.redhat_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_page_basic_rendering(
    mock_enrichment,
    mock_vulnrichment,
    mock_redhat,
    mock_mitre,
    mock_nvd,
    db,
    create_cve,
    client,
):
    """Test that the CVE detail page renders correctly."""
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_redhat.return_value = {}
    mock_vulnrichment.return_value = {}
    mock_enrichment.return_value = {}

    cve = create_cve("CVE-2024-31331")

    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    soup = BeautifulSoup(response.content, features="html.parser")

    # Check title
    assert soup.find("title").text == "CVE-2024-31331 - Vulnerability Details - OpenCVE"

    # Check meta description
    assert soup.find("meta", {"name": "description"})["content"].startswith(
        "In setMimeGroup of PackageManagerService.java"
    )

    # Check CVE ID is present in navbar
    navbar_title = soup.find("h1", {"class": "navbar-title"})
    assert navbar_title is not None
    assert "CVE-2024-31331" in navbar_title.text

    # Check CVE description is present in content
    description_box = soup.find("div", {"class": "box box-primary"})
    assert description_box is not None
    box_body = description_box.find("div", {"class": "box-body"})
    assert box_body is not None
    assert "setMimeGroup" in box_body.text
    assert "PackageManagerService" in box_body.text

    # Check that main content sections are present
    assert soup.find("section", {"class": "content"}) is not None
    assert len(soup.find_all("div", {"class": "box box-primary"})) > 0


@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.redhat_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_build_json_context(
    mock_enrichment,
    mock_vulnrichment,
    mock_redhat,
    mock_mitre,
    mock_nvd,
    db,
    create_cve,
):
    """Test that build_json_context correctly serializes all JSON properties."""
    mock_nvd.return_value = {"foo": "bar"}
    mock_mitre.return_value = {"baz": "qux"}
    mock_redhat.return_value = {"red": "hat"}
    mock_vulnrichment.return_value = {"vuln": "richment"}
    mock_enrichment.return_value = {"enrich": "ment"}

    cve = create_cve("CVE-2024-31331")
    rf = RequestFactory()
    request = rf.get("/")
    view = CveDetailView()
    view.request = request

    context = view.build_json_context(cve)

    assert context["nvd_json"] == '{"foo": "bar"}'
    assert context["mitre_json"] == '{"baz": "qux"}'
    assert context["redhat_json"] == '{"red": "hat"}'
    assert context["vulnrichment_json"] == '{"vuln": "richment"}'
    assert context["enrichment_json"] == '{"enrich": "ment"}'


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_build_tags_context_unauthenticated(db, create_cve):
    """Test that build_tags_context returns empty tags for unauthenticated users."""
    cve = create_cve("CVE-2024-31331")
    rf = RequestFactory()
    request = rf.get("/")
    request.user = AnonymousUser()
    view = CveDetailView()
    view.request = request

    context = view.build_tags_context(cve)

    assert context["user_tags"] == []
    assert context["tags"] == []
    assert "cve_tags_encoded" not in context


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_build_tags_context_authenticated_no_tags(
    db, create_cve, create_user
):
    """Test that build_tags_context returns empty tags for authenticated users."""
    user = create_user()
    cve = create_cve("CVE-2024-31331")
    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    context = view.build_tags_context(cve)

    assert list(context["user_tags"]) == []
    assert context["tags"] == []
    assert context["cve_tags_encoded"] == "[]"


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_build_tags_context_authenticated_with_tags(
    db, create_cve, create_user
):
    """Test that build_tags_context correctly returns tags for authenticated users."""
    user = create_user()
    cve = create_cve("CVE-2024-31331")
    UserTag.objects.create(name="tag1", user=user, color="#ff0000")
    UserTag.objects.create(name="tag2", user=user, color="#00ff00")
    CveTag.objects.create(user=user, cve=cve, tags=["tag1", "tag2"])

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    context = view.build_tags_context(cve)

    assert set(context["user_tags"]) == {"tag1", "tag2"}
    assert sorted([tag["name"] for tag in context["tags"]]) == ["tag1", "tag2"]
    assert context["cve_tags_encoded"] == '["tag1", "tag2"]'


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_get_projects(db, create_user, create_organization, create_project):
    """Test that get_projects returns only projects from the current organization."""
    user = create_user()
    org1 = create_organization(name="org1", user=user)
    org2 = create_organization(name="org2", user=user)
    project1 = create_project(name="project1", organization=org1)
    project2 = create_project(name="project2", organization=org1)
    project3 = create_project(name="project3", organization=org2)

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    request.current_organization = org1
    view = CveDetailView()
    view.request = request

    projects = view.get_projects()

    assert list(projects) == [project1, project2]
    assert project3 not in projects


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_serialize_projects(
    db, create_user, create_organization, create_project
):
    """Test that serialize_projects correctly converts project objects to JSON."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project1 = create_project(
        name="project1",
        organization=org,
        vendors=["vendor1"],
        products=["vendor1$PRODUCT$product1"],
    )
    project2 = create_project(
        name="project2", organization=org, vendors=["vendor2"], products=[]
    )

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    projects = [project1, project2]
    serialized = view.serialize_projects(projects)
    data = json.loads(serialized)
    assert data[0] == {
        "id": str(project1.id),
        "name": "project1",
        "subscriptions": {
            "vendors": ["vendor1"],
            "products": ["vendor1$PRODUCT$product1"],
        },
    }
    assert data[1] == {
        "id": str(project2.id),
        "name": "project2",
        "subscriptions": {
            "vendors": ["vendor2"],
            "products": [],
        },
    }


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_compute_subscription_counts(
    db, create_user, create_organization, create_project
):
    """Test that compute_subscription_counts correctly counts projects subscriptions."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project1 = create_project(
        name="project1",
        organization=org,
        vendors=["vendor1", "vendor2"],
        products=[f"vendor1{PRODUCT_SEPARATOR}product1"],
    )
    project2 = create_project(
        name="project2",
        organization=org,
        vendors=["vendor1"],
        products=[
            f"vendor1{PRODUCT_SEPARATOR}product1",
            f"vendor2{PRODUCT_SEPARATOR}product2",
        ],
    )

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    projects = [project1, project2]
    counts = view.compute_subscription_counts(projects)

    assert counts["vendor1"] == 2
    assert counts["vendor2"] == 1
    assert counts[f"vendor1{PRODUCT_SEPARATOR}product1"] == 2
    assert counts[f"vendor2{PRODUCT_SEPARATOR}product2"] == 1


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_build_vendors_data_empty(db, create_user):
    """Test that build_vendors_data returns an empty dictionary when given no vendors."""
    user = create_user()
    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    result = view.build_vendors_data({}, {})

    assert result == {}


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_build_vendors_data(
    db, create_user, create_organization, create_project
):
    """Test that build_vendors_data correctly builds vendors data structure."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    vendor1 = Vendor.objects.create(name="vendor1")
    vendor2 = Vendor.objects.create(name="vendor2")
    product1 = Product.objects.create(name="product1", vendor=vendor1)
    product2 = Product.objects.create(name="product2", vendor=vendor1)
    product3 = Product.objects.create(name="product3", vendor=vendor2)

    project1 = create_project(
        name="project1",
        organization=org,
        vendors=["vendor1"],
        products=[f"vendor1{PRODUCT_SEPARATOR}product1"],
    )
    project2 = create_project(
        name="project2",
        organization=org,
        vendors=["vendor1", "vendor2"],
        products=[
            f"vendor1{PRODUCT_SEPARATOR}product1",
            f"vendor2{PRODUCT_SEPARATOR}product3",
        ],
    )

    vendors_dict = {
        "vendor1": ["product1", "product2"],
        "vendor2": ["product3"],
    }

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    projects = [project1, project2]
    subscription_counts = view.compute_subscription_counts(projects)
    result = view.build_vendors_data(vendors_dict, subscription_counts)

    assert result["vendor1"] == {
        "vendor": vendor1,
        "subscription_count": 2,
        "products": {
            "product1": {
                "product": product1,
                "subscription_count": 2,
            },
            "product2": {
                "product": product2,
                "subscription_count": 0,
            },
        },
    }
    assert result["vendor2"] == {
        "vendor": vendor2,
        "subscription_count": 1,
        "products": {
            "product3": {
                "product": product3,
                "subscription_count": 1,
            },
        },
    }


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_list_cve_projects(
    db, create_user, create_organization, create_project
):
    """Test that list_cve_projects correctly filters projects and returns trackers."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    cve = Cve.objects.create(
        cve_id="CVE-2024-99999",
        title="Test CVE",
        description="Test description",
        vendors=["vendor1", f"vendor1{PRODUCT_SEPARATOR}product1", "vendor2"],
        weaknesses=[],
        metrics={},
    )

    # Project 1: subscribed to vendor1 (should be included)
    project1 = create_project(
        name="project1",
        organization=org,
        vendors=["vendor1"],
        products=[],
    )

    # Project 2: subscribed to vendor1/product1 (should be included)
    project2 = create_project(
        name="project2",
        organization=org,
        vendors=[],
        products=[f"vendor1{PRODUCT_SEPARATOR}product1"],
    )

    # Project 3: subscribed to vendor2 (should be included)
    project3 = create_project(
        name="project3",
        organization=org,
        vendors=["vendor2"],
        products=[],
    )

    # Project 4: subscribed to vendor3 (should NOT be included)
    project4 = create_project(
        name="project4",
        organization=org,
        vendors=["vendor3"],
        products=[],
    )

    # Project 5: subscribed to vendor1/product2 (should NOT be included)
    project5 = create_project(
        name="project5",
        organization=org,
        vendors=[],
        products=[f"vendor1{PRODUCT_SEPARATOR}product2"],
    )

    # Create trackers for some projects (no tracker for project3)
    tracker1 = CveTracker.objects.create(
        cve=cve, project=project1, assignee=user, status="to_evaluate"
    )
    tracker2 = CveTracker.objects.create(
        cve=cve, project=project2, assignee=None, status="resolved"
    )

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user
    view = CveDetailView()
    view.request = request

    all_projects = [project1, project2, project3, project4, project5]
    result = view.list_cve_projects(cve, all_projects)

    # Should return only projects 1, 2, and 3 (matching subscriptions)
    assert len(result) == 3

    # Check project1 has a tracker
    result_project1 = next((r for r in result if r["project"] == project1), None)
    assert result_project1 is not None
    assert result_project1["project"] == project1
    assert result_project1["tracker"] == tracker1

    # Check project2 has a tracker
    result_project2 = next((r for r in result if r["project"] == project2), None)
    assert result_project2 is not None
    assert result_project2["project"] == project2
    assert result_project2["tracker"] == tracker2

    # Check project3 has no tracker
    result_project3 = next((r for r in result if r["project"] == project3), None)
    assert result_project3 is not None
    assert result_project3["project"] == project3
    assert result_project3["tracker"] is None

    # Check project4 and project5 are not in results
    result_project_ids = {r["project"].id for r in result}
    assert project4.id not in result_project_ids
    assert project5.id not in result_project_ids


@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.redhat_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_get_context_data_unauthenticated(
    mock_enrichment,
    mock_vulnrichment,
    mock_redhat,
    mock_mitre,
    mock_nvd,
    db,
    create_cve,
    client,
):
    """Test that get_context_data returns correct context for unauthenticated users."""
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_redhat.return_value = {}
    mock_vulnrichment.return_value = {}
    mock_enrichment.return_value = {}

    cve = create_cve("CVE-2024-31331")

    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    context = response.context

    assert context["cve"] == cve
    assert "nvd_json" in context
    assert "mitre_json" in context
    assert "redhat_json" in context
    assert "vulnrichment_json" in context
    assert "enrichment_json" in context
    assert "vendors" in context
    assert "weaknesses" in context
    assert "enrichment_vendors" in context
    assert context["user_tags"] == []
    assert context["tags"] == []
    assert "projects" not in context
    assert "projects_json" not in context
    assert "vendors_data" not in context
    assert "enrichment_vendors_data" not in context


@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.redhat_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_get_context_data_authenticated(
    mock_enrichment,
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    db,
    create_cve,
    create_user,
    create_organization,
    create_project,
    auth_client,
):
    """Test that get_context_data returns correct context for authenticated users."""
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_redhat.return_value = {}
    mock_vulnrichment.return_value = {}
    mock_enrichment.return_value = {}

    user = create_user()
    org = create_organization(name="org1", user=user)
    vendor1 = Vendor.objects.create(name="vendor1")
    Product.objects.create(name="product1", vendor=vendor1)
    project = create_project(
        name="project1",
        organization=org,
        vendors=["vendor1"],
        products=[f"vendor1{PRODUCT_SEPARATOR}product1"],
    )

    cve = create_cve("CVE-2024-31331")
    client = auth_client(user)
    session = client.session
    session["current_organization_id"] = str(org.id)
    session.save()

    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    context = response.context

    assert context["cve"] == cve
    assert list(context["projects"]) == [project]
    assert "projects_json" in context
    assert "vendors_data" in context
    assert "enrichment_vendors_data" in context
    assert "filtered_projects" in context
    assert "filtered_projects" in context
    assert "organization_members" in context
    assert "status_choices" in context


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_post_unauthenticated(db, create_cve, client):
    """Test that POST request to update CVE tags returns 404 for unauthenticated users."""
    cve = create_cve("CVE-2024-31331")

    response = client.post(
        reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}),
        data={"tags": ["tag1"]},
    )

    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_post_invalid_tag(db, create_cve, create_user, auth_client):
    """Test that POST request with invalid tags returns 404."""
    user = create_user()
    cve = create_cve("CVE-2024-31331")
    client = auth_client(user)

    response = client.post(
        reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}),
        data={"tags": ["invalid_tag"]},
    )

    assert response.status_code == 404
    assert not CveTag.objects.filter(user=user, cve=cve).exists()


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_post_valid_tags_new(db, create_cve, create_user, auth_client):
    """Test that POST request with valid tags creates a new CveTag entry."""
    user = create_user()
    cve = create_cve("CVE-2024-31331")
    UserTag.objects.create(name="tag1", user=user)
    UserTag.objects.create(name="tag2", user=user)
    client = auth_client(user)

    response = client.post(
        reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}),
        data={"tags": ["tag1", "tag2"]},
    )

    assert response.status_code == 302
    assert response.url == reverse("cve", kwargs={"cve_id": "CVE-2024-31331"})
    cve_tag = CveTag.objects.filter(user=user, cve=cve).first()
    assert cve_tag is not None
    assert cve_tag.tags == ["tag1", "tag2"]


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_post_valid_tags_update(db, create_cve, create_user, auth_client):
    """Test that POST request with valid tags updates an existing CveTag entry."""
    user = create_user()
    cve = create_cve("CVE-2024-31331")
    UserTag.objects.create(name="tag1", user=user)
    UserTag.objects.create(name="tag2", user=user)
    UserTag.objects.create(name="tag3", user=user)
    CveTag.objects.create(user=user, cve=cve, tags=["tag1"])
    client = auth_client(user)

    response = client.post(
        reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}),
        data={"tags": ["tag2", "tag3"]},
    )

    assert response.status_code == 302
    assert response.url == reverse("cve", kwargs={"cve_id": "CVE-2024-31331"})
    cve_tag = CveTag.objects.filter(user=user, cve=cve).first()
    assert cve_tag is not None
    assert cve_tag.tags == ["tag2", "tag3"]
    assert "tag1" not in cve_tag.tags


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_post_empty_tags(db, create_cve, create_user, auth_client):
    """Test that POST request with empty tags list removes all tags from a CVE."""
    user = create_user()
    cve = create_cve("CVE-2024-31331")
    CveTag.objects.create(user=user, cve=cve, tags=["tag1"])
    client = auth_client(user)

    response = client.post(
        reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}),
        data={"tags": []},
    )

    assert response.status_code == 302
    assert response.url == reverse("cve", kwargs={"cve_id": "CVE-2024-31331"})
    cve_tag = CveTag.objects.filter(user=user, cve=cve).first()
    assert cve_tag is not None
    assert cve_tag.tags == []


def test_statistics(create_variable, client):
    create_variable("statistics_one", {"foo": 1000})
    create_variable("statistics_two", {"bar": 2000})
    create_variable("statistics_cves_count_last_days", {"7_days": {}})

    response = client.get(reverse("statistics"))
    assert response.status_code == 200
    assert b'STATISTICS_ONE = {"foo": 1000};' in response.content
    assert b'STATISTICS_TWO = {"bar": 2000};' in response.content
    assert b"STATISTICS_CVES_COUNT_LAST_DAYS" not in response.content


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
        ("vendor:cisco AND description!:log4j", ["CVE-2022-22965"]),
        ("vendor:cisco AND title!:spring", ["CVE-2021-44228"]),
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
    soup = BeautifulSoup(response.content, "html.parser")
    assert response.status_code == 200
    assert "The tag 'test' does not exist." in soup.text

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


@override_settings(ENABLE_ONBOARDING=False)
def test_cve_with_views(create_organization, create_user, create_view, auth_client):
    user = create_user()
    org = create_organization(name="my-org", user=user)
    create_view(
        name="view1",
        query="userTag:foobar",
        organization=org,
        privacy="private",
        user=user,
    )
    create_view(
        name="view2", query="description:python", organization=org, privacy="public"
    )
    client = auth_client(user)

    response = client.get(reverse("cves"))
    soup = BeautifulSoup(response.content, features="html.parser")
    codes = soup.find("div", {"id": "modal-load-views"}).find_all(
        "span", {"class": "view-title"}
    )
    assert sorted([c.text.strip() for c in codes]) == ["view1", "view2"]
    titles = soup.find("div", {"id": "modal-load-views"}).find_all("code")
    assert sorted([t.text for t in titles]) == ["description:python", "userTag:foobar"]


@pytest.mark.django_db
@override_settings(ENABLE_ONBOARDING=False)
def test_cvelist_get_queryset_scenarios(create_cve, create_user, auth_client):
    """
    Tests various scenarios within CveListView.get_queryset:
    - Invalid initial form (parsing error in 'q')
    - Valid form, no 'q', simple param conversion ('vendor')
    - Valid form, 'q' provided, raises BadQueryException (non-existent tag)
    - Valid form, 'q' provided, raises ParseException (handled by view)
    - Valid form, 'q' provided, successful search
    - Valid form, empty 'q' and no simple params
    """
    user = create_user()
    client = auth_client(user)

    cve_log4j = create_cve("CVE-2021-44228")  # apache, redhat
    cve_git = create_cve("CVE-2023-22490")  # git-scm
    cve_spring = create_cve("CVE-2022-22965")  # vmware
    all_cve_ids = sorted([cve_log4j.cve_id, cve_git.cve_id, cve_spring.cve_id])

    valid_tag = UserTag.objects.create(user=user, name="validtag")
    CveTag.objects.create(user=user, cve=cve_log4j, tags=[valid_tag.name])

    def get_cve_ids_from_response(response):
        soup = BeautifulSoup(response.content, features="html.parser")
        return sorted(
            [s.find("a").text for s in soup.find_all("tr", {"class": "cve-header"})]
        )

    # Invalid Form (initial 'q' parsing error)
    response = client.get(reverse("cves"), data={"q": "invalid(syntax"})
    assert response.status_code == 200
    assert get_cve_ids_from_response(response) == all_cve_ids
    form_errors = response.context["search_form"].errors
    assert "q" in form_errors
    assert "Expected end of text" in form_errors["q"][0]

    # Valid Form, vendor only
    response = client.get(reverse("cves"), data={"vendor": "git-scm"})
    assert response.status_code == 200
    assert get_cve_ids_from_response(response) == [cve_git.cve_id]
    form = response.context["search_form"]
    assert not form.errors
    assert form["q"].value() == "vendor:git-scm"

    # Valid Form, raises BadQueryException
    response = client.get(reverse("cves"), data={"q": "userTag:nonexistent"})
    assert response.status_code == 200
    assert get_cve_ids_from_response(response) == all_cve_ids
    form_errors = response.context["search_form"].errors
    assert "q" in form_errors
    assert "The tag 'nonexistent' does not exist." in form_errors["q"][0]

    # Valid Form, raises ParseException
    response = client.get(reverse("cves"), data={"q": "another:invalid(syntax"})
    assert response.status_code == 200
    assert get_cve_ids_from_response(response) == all_cve_ids
    form_errors = response.context["search_form"].errors
    assert "q" in form_errors

    # Valid Form, successful search
    response = client.get(reverse("cves"), data={"q": f"cve:{cve_log4j.cve_id}"})
    assert response.status_code == 200
    assert get_cve_ids_from_response(response) == [cve_log4j.cve_id]
    form = response.context["search_form"]
    assert not form.errors
    assert form["q"].value() == f"cve:{cve_log4j.cve_id}"

    # Empty query (no params)
    response = client.get(reverse("cves"))
    assert response.status_code == 200
    assert get_cve_ids_from_response(response) == all_cve_ids
    form = response.context["search_form"]
    assert not form.errors
    assert form["q"].value() == ""


@pytest.mark.parametrize(
    "params, expected_query",
    [
        ({}, ""),
        ({"vendor": "testvendor"}, "vendor:testvendor"),
        (
            {"vendor": "testv", "product": "testp"},
            "vendor:testv AND product:testp",
        ),
        ({"product": "testp"}, ""),
        ({"weakness": "CWE-123"}, "cwe:CWE-123"),
        ({"tag": "mytag"}, "userTag:mytag"),
        ({"search": "oneword"}, "oneword"),
        ({"search": "two words"}, 'description:"two words"'),
        (
            {"vendor": "v", "tag": "t", "search": "multi word search"},
            'vendor:v AND userTag:t AND description:"multi word search"',
        ),
        (
            {
                "vendor": "v",
                "product": "p",
                "weakness": "CWE-1",
                "tag": "t",
                "search": "word",
            },
            "vendor:v AND product:p AND cwe:CWE-1 AND userTag:t AND word",
        ),
    ],
)
@pytest.mark.django_db
def test_cvelist_convert_to_advanced_search_authenticated(
    create_user, params, expected_query
):
    """
    Test convert_to_advanced_search for authenticated user.
    """
    user = create_user()

    # Simulate request using RequestFactory
    rf = RequestFactory()
    request = rf.get(reverse("cves"), data=params)
    request.user = user

    # Instantiate the view and attach the request
    view = CveListView()
    view.request = request

    assert view.convert_to_advanced_search() == expected_query


@pytest.mark.parametrize(
    "params, expected_query",
    [
        # Test with special characters requiring quotes
        ({"vendor": "vendor:special"}, "vendor:'vendor:special'"),
        ({"vendor": "vendor with space"}, "vendor:'vendor with space'"),
        ({"vendor": "vendor'quote"}, "vendor:'vendor'quote'"),
        ({"vendor": "vendor(parentheses)"}, "vendor:'vendor(parentheses)'"),
        ({"vendor": "vendor[brackets]"}, "vendor:'vendor[brackets]'"),
        ({"vendor": "vendor{braces}"}, "vendor:'vendor{braces}'"),
        ({"vendor": "vendor&ampersand"}, "vendor:'vendor&ampersand'"),
        ({"vendor": "vendor|pipe"}, "vendor:'vendor|pipe'"),
        ({"vendor": "vendor=equals"}, "vendor:'vendor=equals'"),
        ({"vendor": "vendor!bang"}, "vendor:'vendor!bang'"),
        ({"vendor": "vendor\\backslash"}, "vendor:'vendor\\backslash'"),
        ({"vendor": "vendor<less>"}, "vendor:'vendor<less>'"),
        ({"vendor": "vendor+plus"}, "vendor:'vendor+plus'"),
        ({"vendor": "vendor*star"}, "vendor:'vendor*star'"),
        ({"vendor": "vendor?question"}, "vendor:'vendor?question'"),
        ({"vendor": "vendor^caret"}, "vendor:'vendor^caret'"),
        ({"vendor": "vendor~tilde"}, "vendor:'vendor~tilde'"),
        # Test with product and vendor both having special characters
        (
            {"vendor": "vendor:special", "product": "product with space"},
            "vendor:'vendor:special' AND product:'product with space'",
        ),
        # Test normal values without special characters (should not be quoted)
        ({"vendor": "normalvendor"}, "vendor:normalvendor"),
        ({"vendor": "normal-vendor"}, "vendor:normal-vendor"),
        ({"vendor": "normal_vendor"}, "vendor:normal_vendor"),
        ({"vendor": "normalvendor123"}, "vendor:normalvendor123"),
        # Test product with special characters (vendor must be provided)
        (
            {"vendor": "normalvendor", "product": "product:special"},
            "vendor:normalvendor AND product:'product:special'",
        ),
    ],
)
@pytest.mark.django_db
def test_cvelist_convert_to_advanced_search_special_characters(
    create_user, params, expected_query
):
    """
    Test convert_to_advanced_search properly quotes vendor and product values
    containing special characters.
    """
    user = create_user()

    # Simulate request using RequestFactory
    rf = RequestFactory()
    request = rf.get(reverse("cves"), data=params)
    request.user = user

    # Instantiate the view and attach the request
    view = CveListView()
    view.request = request

    assert view.convert_to_advanced_search() == expected_query


@pytest.mark.django_db
def test_cvelist_convert_to_advanced_search_unauthenticated(rf):
    """
    Test convert_to_advanced_search ignores tag for unauthenticated user.
    """
    rf = RequestFactory()
    params = {"vendor": "v", "tag": "t"}
    request = rf.get(reverse("cves"), data=params)
    request.user = AnonymousUser()

    # Instantiate the view and attach the request
    view = CveListView()
    view.request = request

    # Tag should be ignored
    assert view.convert_to_advanced_search() == "vendor:v"


@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_enrichment_panel(
    mock_vulnrichment, mock_mitre, mock_nvd, mock_enrichment, db, create_cve, client
):
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_vulnrichment.return_value = {}
    create_cve("CVE-2024-31331")

    # Find the Enrichment box specifically
    def get_enrichment_box(soup):
        enrichment_box = None
        for box in soup.find_all("div", {"class": "box box-primary"}):
            box_title = box.find("div", {"class": "box-title"})
            if box_title and "Enrichment" in box_title.text:
                enrichment_box = box
                break
        return enrichment_box

    # No enrichment data
    mock_enrichment.return_value = {}
    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    soup = BeautifulSoup(response.content, features="html.parser")
    enrichment_box = get_enrichment_box(soup)
    box_body = enrichment_box.find("div", {"class": "box-body"})
    assert box_body.text.strip() == "No data."

    # Enrichment data
    mock_enrichment.return_value = {
        "updated": "2025-07-23T20:19:23.982630+00:00",
    }
    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    soup = BeautifulSoup(response.content, features="html.parser")
    enrichment_box = get_enrichment_box(soup)
    box_body = enrichment_box.find("div", {"class": "box-body"})
    assert box_body.text.strip() == "Updated: 2025-07-23T20:19:23Z"


@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.redhat_json", new_callable=PropertyMock)
def test_cve_detail_advisories_panel(
    mock_vulnrichment,
    mock_mitre,
    mock_nvd,
    mock_enrichment,
    mock_redhat,
    db,
    create_cve,
    client,
):
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_vulnrichment.return_value = {}
    mock_enrichment.return_value = {}
    mock_redhat.return_value = {}

    # No advisories
    create_cve("CVE-2024-31331")
    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2024-31331"}))
    soup = BeautifulSoup(response.content, features="html.parser")
    assert soup.find("title").text == "CVE-2024-31331 - Vulnerability Details - OpenCVE"
    assert (
        soup.find("div", {"id": "advisories-box"})
        .find("div", {"class": "box-body"})
        .text.strip()
        == "No advisories yet."
    )

    # Advisories
    create_cve("CVE-2022-48703")
    response = client.get(reverse("cve", kwargs={"cve_id": "CVE-2022-48703"}))
    soup = BeautifulSoup(response.content, features="html.parser")
    output = (
        soup.find("div", {"id": "advisories-box"})
        .find("div", {"class": "box-body"})
        .text.strip()
    )
    assert "USN-7774-1" in output
    assert "USN-7774-2" in output
    assert "USN-7774-3" in output
    assert "USN-7775-1" in output
    assert "USN-7775-2" in output
    assert "USN-7776-1" in output
    assert "USN-7775-3" in output
    assert "USN-7774-4" in output
    assert "USN-7774-5" in output


# --- CVE CSV Export ---


@override_settings(ENABLE_ONBOARDING=False)
def test_cves_export_csv_returns_csv_with_headers_and_data(create_cve, auth_client):
    """Export CSV returns 200, text/csv, and contains header + CVE rows."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2023-22490")
    client = auth_client()
    response = client.get(reverse("cves_export_csv"))
    assert response.status_code == 200
    assert "text/csv" in response["Content-Type"]
    content = b"".join(response.streaming_content).decode("utf-8")
    lines = content.strip().split("\r\n")
    assert len(lines) == 3  # header + 2 CVEs
    assert (
        lines[0]
        == "cve_id,title,description,vendors,weaknesses,created_at,updated_at,kev,epss,cvss_v4_0,cvss_v3_1,cvss_v3_0,cvss_v2_0"
    )
    assert (
        lines[1]
        == 'CVE-2023-22490,Git vulnerable to local clone-based data exfiltration with non-local transports,"Git is a revision control system. Using a specially-crafted repository, Git prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8 can be tricked into using its local clone optimization even when using a non-local transport. Though Git will abort local clones whose source `$GIT_DIR/objects` directory contains symbolic links, the `objects` directory itself may still be a symbolic link. These two may be combined to include arbitrary files based on known paths on the victim\'s filesystem within the malicious repository\'s working copy, allowing for data exfiltration in a similar manner as CVE-2022-39253. A fix has been prepared and will appear in v2.39.2 v2.38.4 v2.37.6 v2.36.5 v2.35.7 v2.34.7 v2.33.7 v2.32.6, v2.31.7 and v2.30.8. If upgrading is impractical, two short-term workarounds are available. Avoid cloning repositories from untrusted sources with `--recurse-submodules`. Instead, consider cloning repositories without recursively cloning their submodules, and instead run `git submodule update` at each layer. Before doing so, inspect each new `.gitmodules` file to ensure that it does not contain suspicious module URLs.","git-scm (git), redhat (enterprise_linux, rhel_eus)","CWE-402, CWE-59",2023-02-14T00:00:00Z,2024-08-02T10:13:48Z,false,,,5.5,,'
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_cves_export_csv_preserves_query_params(create_cve, auth_client):
    """Export CSV with query params returns filtered results."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2023-22490")  # git-scm
    client = auth_client()
    response = client.get(f"{reverse('cves_export_csv')}?q=vendor:git-scm")
    assert response.status_code == 200
    content = b"".join(response.streaming_content).decode("utf-8")
    assert "CVE-2023-22490" in content
    assert "CVE-2021-44228" not in content


@override_settings(ENABLE_ONBOARDING=False)
def test_cves_export_csv_redirects_when_over_limit(create_cve, auth_client):
    """When result count exceeds limit, redirect to list with error message."""
    create_cve("CVE-2021-44228")
    client = auth_client()
    with patch("cves.views.CVE_CSV_EXPORT_MAX_ROWS", 0):
        response = client.get(reverse("cves_export_csv"), follow=False)
    assert response.status_code == 302
    assert reverse("cves") in response.url
    # Follow redirect and check message
    response = client.get(reverse("cves_export_csv"), follow=True)
    messages_list = list(get_messages(response.wsgi_request))
    assert (
        messages_list[0].message
        == "Export limit exceeded: 1 CVEs match your query. Please refine your search to export 10,000 CVEs or fewer."
    )
