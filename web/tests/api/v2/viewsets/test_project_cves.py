import json

import pytest
from django.test import override_settings

from organizations.models import OrganizationAPIToken
from projects.models import CveTracker
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    project_cve_detail_url,
    project_cves_url,
    read_token,
    write_token,
)


@pytest.mark.django_db
def test_empty_subscriptions_returns_empty_list(
    client, api_context, write_token, create_project
):
    """List returns an empty result set when the project has no subscriptions."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.get(project_cves_url(), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert data["results"] == []


@pytest.mark.django_db
def test_list_filters_cves_by_subscriptions(
    client, api_context, write_token, create_project, create_cve
):
    """List returns only CVEs matching the project's subscriptions."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization, vendors=["cisco"])
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")
    create_cve("CVE-2021-34181")

    response = client.get(project_cves_url(), **bearer(write_token))

    assert response.status_code == 200
    cve_ids = [item["cve_id"] for item in response.json()["results"]]
    assert set(cve_ids) == {"CVE-2021-44228", "CVE-2022-22965"}


@pytest.mark.django_db
def test_retrieve_cve_not_in_subscriptions_returns_404(
    client, api_context, write_token, create_project, create_cve
):
    """Retrieve returns 404 for CVEs outside the project's subscriptions."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization, vendors=["cisco"])
    create_cve("CVE-2021-34181")

    response = client.get(
        project_cve_detail_url("CVE-2021-34181"),
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
def test_patch_status_and_assignee_then_clear_tracker(
    client, api_context, write_token, create_project, create_cve
):
    """Patch can set tracker fields and clearing them removes the tracker."""
    user, organization, _create_token = api_context
    user.email = "owner@example.com"
    user.save(update_fields=["email"])
    create_project(name="prod", organization=organization, vendors=["cisco"])
    create_cve("CVE-2021-44228")

    set_response = client.patch(
        project_cve_detail_url("CVE-2021-44228"),
        data=json.dumps(
            {
                "status": "to_evaluate",
                "assignee": "owner@example.com",
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert set_response.status_code == 200
    tracker = set_response.json()["tracker"]
    assert tracker["status"] == "to_evaluate"
    assert tracker["assignee"]["email"] == "owner@example.com"
    assert CveTracker.objects.filter(
        project__name="prod",
        cve__cve_id="CVE-2021-44228",
    ).exists()

    clear_response = client.patch(
        project_cve_detail_url("CVE-2021-44228"),
        data=json.dumps({"status": None, "assignee": None}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert clear_response.status_code == 200
    assert clear_response.json()["tracker"] is None
    assert not CveTracker.objects.filter(
        project__name="prod",
        cve__cve_id="CVE-2021-44228",
    ).exists()


@pytest.mark.django_db
def test_patch_invalid_assignee_returns_404(
    client, api_context, write_token, create_project, create_cve
):
    """Patch returns 404 when the assignee is not an organization member."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization, vendors=["cisco"])
    create_cve("CVE-2021-44228")

    response = client.patch(
        project_cve_detail_url("CVE-2021-44228"),
        data=json.dumps({"assignee": "unknown@example.com"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_read_only_token_on_patch_returns_403(
    client, api_context, read_token, create_project, create_cve
):
    """Patch rejects read-only tokens with 403."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization, vendors=["cisco"])
    create_cve("CVE-2021-44228")

    response = client.patch(
        project_cve_detail_url("CVE-2021-44228"),
        data=json.dumps({"status": "to_evaluate"}),
        content_type="application/json",
        **bearer(read_token),
    )

    assert_v2_error(response, "read_only_token", status_code=403)


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_missing_tracker_read_scope_returns_403(
    client, api_context, create_org_token, create_project
):
    """List rejects tokens missing the tracker:read scope."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["projects:write"],
    )

    response = client.get(project_cves_url(), **bearer(token_string))

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="tracker:read",
    )
