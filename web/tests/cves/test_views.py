from unittest.mock import patch, PropertyMock

import pytest
from django.test import override_settings
from django.urls import reverse
from bs4 import BeautifulSoup
from django.test.client import RequestFactory
from cves.views import CveListView

from users.models import User, UserTag, CveTag
from django.contrib.auth.models import AnonymousUser


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
