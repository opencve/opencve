from datetime import date

import pytest
from django.test import override_settings

from changes.models import Change, Report
from organizations.models import OrganizationAPIToken
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    report_detail_url,
    report_list_url,
    write_token,
)


@pytest.mark.django_db
def test_list_excludes_ai_summary(client, api_context, write_token, create_project):
    """List excludes ai_summary and CVE payloads from report items."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    report = Report.objects.create(
        project=project,
        day=date.today(),
        ai_summary="Secret summary",
    )

    response = client.get(report_list_url(), **bearer(write_token))

    assert response.status_code == 200
    item = response.json()["results"][0]
    assert item["id"] == str(report.id)
    assert item["cves_count"] == 0
    assert "ai_summary" not in item
    assert "cves" not in item


@pytest.mark.django_db
def test_detail_includes_cves_and_ai_summary(
    client, api_context, write_token, create_project, create_cve
):
    """Retrieve includes CVE details and the AI summary."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    cve1 = create_cve("CVE-2021-44228")
    cve2 = create_cve("CVE-2022-22965")
    report = Report.objects.create(
        project=project,
        day=date.today(),
        ai_summary="Two CVEs changed during this period.",
    )
    change1 = Change.objects.create(
        cve=cve1,
        path="2021/CVE-2021-44228.json",
        commit="a" * 40,
        types=["created"],
    )
    change2 = Change.objects.create(
        cve=cve2,
        path="2022/CVE-2022-22965.json",
        commit="b" * 40,
        types=["updated"],
    )
    duplicate_change = Change.objects.create(
        cve=cve1,
        path="2021/CVE-2021-44228.json",
        commit="c" * 40,
        types=["updated"],
    )
    report.changes.add(change1, change2, duplicate_change)

    response = client.get(report_detail_url(report.id), **bearer(write_token))

    assert response.status_code == 200
    data = response.json()
    assert data["ai_summary"] == {
        "html": "Two CVEs changed during this period.",
    }
    assert data["cves_count"] == 2
    assert "seen" not in data
    assert [cve["cve_id"] for cve in data["cves"]] == [
        "CVE-2022-22965",
        "CVE-2021-44228",
    ]
    assert set(data["cves"][0]) == {
        "created_at",
        "updated_at",
        "cve_id",
        "description",
        "title",
    }


@pytest.mark.django_db
def test_detail_ai_summary_null_when_missing(
    client, api_context, write_token, create_project
):
    """Retrieve returns null ai_summary when the report has none."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    report = Report.objects.create(project=project, day=date.today())

    response = client.get(report_detail_url(report.id), **bearer(write_token))

    assert response.status_code == 200
    assert response.json()["ai_summary"] is None


@pytest.mark.django_db
def test_list_filters_by_period_type_daily(
    client, api_context, write_token, create_project
):
    """List can be filtered to daily reports only."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    daily_report = Report.objects.create(
        project=project,
        day=date.today(),
        period_type=Report.PERIOD_DAILY,
    )
    Report.objects.create(
        project=project,
        day=date.today(),
        period_type=Report.PERIOD_WEEKLY,
    )

    response = client.get(
        f"{report_list_url()}?period_type=daily",
        **bearer(write_token),
    )

    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["results"]]
    assert ids == [str(daily_report.id)]


@pytest.mark.django_db
def test_list_filters_by_period_type_weekly(
    client, api_context, write_token, create_project
):
    """List can be filtered to weekly reports only."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    Report.objects.create(
        project=project,
        day=date.today(),
        period_type=Report.PERIOD_DAILY,
    )
    weekly_report = Report.objects.create(
        project=project,
        day=date.today(),
        period_type=Report.PERIOD_WEEKLY,
    )

    response = client.get(
        f"{report_list_url()}?period_type=weekly",
        **bearer(write_token),
    )

    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["results"]]
    assert ids == [str(weekly_report.id)]


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_missing_reports_read_scope_returns_403(
    client, api_context, create_org_token, create_project
):
    """List rejects tokens missing the reports:read scope."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["projects:write"],
    )

    response = client.get(report_list_url(), **bearer(token_string))

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="reports:read",
    )


@pytest.mark.django_db
def test_report_from_wrong_project_returns_404(
    client, api_context, write_token, create_project
):
    """Retrieve returns 404 when the report belongs to another project."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    staging = create_project(name="staging", organization=organization)
    report = Report.objects.create(project=staging, day=date.today())

    response = client.get(
        report_detail_url(report.id, project_name="prod"),
        **bearer(write_token),
    )

    assert_v2_error(response, "not_found", status_code=404)
