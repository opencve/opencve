from unittest.mock import PropertyMock, patch

import pytest
from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now

from authorization.roles import PROJECT_ADMIN, PROJECT_CONTRIBUTOR, PROJECT_VIEWER
from cves.models import Vendor
from organizations.models import Membership
from projects.models import CveComment, ProjectMembership


@patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
@patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
@patch("cves.models.Cve.redhat_json", new_callable=PropertyMock)
@patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
@patch("cves.models.Cve.enrichment_json", new_callable=PropertyMock)
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_tracking_viewer_sees_comments_without_comment_form(
    mock_enrichment,
    mock_vulnrichment,
    mock_redhat,
    mock_mitre,
    mock_nvd,
    create_cve,
    create_user,
    create_organization,
    create_project,
    auth_client,
    set_current_org,
):
    """Viewer reads tracker comments on CVE detail but cannot see comment forms."""
    mock_nvd.return_value = {}
    mock_mitre.return_value = {}
    mock_redhat.return_value = {}
    mock_vulnrichment.return_value = {}
    mock_enrichment.return_value = {}

    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_membership = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    ProjectMembership.objects.create(
        project=project,
        membership=viewer_membership,
        role=ProjectMembership.VIEWER,
    )
    cve = create_cve("CVE-2023-22490")
    CveComment.objects.create(
        cve=cve,
        project=project,
        author=owner,
        body="Existing tracker comment",
    )

    client = set_current_org(auth_client(viewer), org)
    response = client.get(reverse("cve", kwargs={"cve_id": cve.cve_id}))
    content = response.content.decode()

    assert response.status_code == 200
    assert "Existing tracker comment" in content
    assert "project-comment-textarea" not in content
    assert "project-comment-reply-textarea" not in content
    assert "project-comment-reply-toggle" not in content
    assert "project-comment-edit-btn" not in content


@override_settings(ENABLE_ONBOARDING=False)
def test_vendor_subscribe_lists_active_manageable_projects_only(
    create_organization,
    create_user,
    create_project,
    auth_client,
    set_current_org,
):
    """Vendor subscribe lists only active projects the user may manage subscriptions on."""
    owner = create_user(username="owner")
    contributor = create_user(username="contributor")
    org = create_organization(name="org1", user=owner)
    contributor_membership = Membership.objects.create(
        user=contributor,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    active_admin = create_project(name="active-admin", organization=org, active=True)
    create_project(name="inactive-admin", organization=org, active=False)
    active_contributor = create_project(
        name="active-contributor", organization=org, active=True
    )
    ProjectMembership.objects.create(
        project=active_admin,
        membership=contributor_membership,
        role=PROJECT_ADMIN,
    )
    ProjectMembership.objects.create(
        project=active_contributor,
        membership=contributor_membership,
        role=PROJECT_CONTRIBUTOR,
    )
    Vendor.objects.create(name="acme")

    owner_client = set_current_org(auth_client(owner), org)
    owner_response = owner_client.get(reverse("subscribe") + "?vendor=acme")
    owner_soup = BeautifulSoup(owner_response.content, features="html.parser")
    owner_projects = [
        row.find_all("td")[0].text.strip()
        for row in owner_soup.select(".subscribed-projects tbody tr")
    ]
    assert set(owner_projects) == {"active-admin", "active-contributor"}

    contributor_client = set_current_org(auth_client(contributor), org)
    contributor_response = contributor_client.get(
        reverse("subscribe") + "?vendor=acme",
    )
    contributor_soup = BeautifulSoup(
        contributor_response.content, features="html.parser"
    )
    contributor_projects = [
        row.find_all("td")[0].text.strip()
        for row in contributor_soup.select(".subscribed-projects tbody tr")
    ]
    assert contributor_projects == ["active-admin"]


@override_settings(ENABLE_ONBOARDING=False)
def test_vendor_subscribe_post_rejects_unmanageable_project(
    create_organization,
    create_user,
    create_project,
    auth_client,
    set_current_org,
):
    """Viewer cannot subscribe a vendor to a project via POST."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_membership = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="alpha", organization=org)
    ProjectMembership.objects.create(
        project=project,
        membership=viewer_membership,
        role=PROJECT_VIEWER,
    )
    vendor = Vendor.objects.create(name="acme")

    client = set_current_org(auth_client(viewer), org)
    response = client.post(
        reverse("subscribe") + "?vendor=acme",
        data={
            "action": "subscribe",
            "obj_type": "vendor",
            "obj_id": str(vendor.id),
            "project_id": str(project.id),
        },
    )
    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_vendor_subscribe_viewer_sees_no_manageable_projects(
    create_organization,
    create_user,
    create_project,
    create_project_membership,
    auth_client,
    set_current_org,
):
    """Viewer and contributor without project admin role see no manageable projects."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_m = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="alpha", organization=org)
    create_project_membership(project=project, membership=viewer_m, role=PROJECT_VIEWER)
    Vendor.objects.create(name="acme")

    client = set_current_org(auth_client(viewer), org)
    response = client.get(reverse("subscribe") + "?vendor=acme")
    soup = BeautifulSoup(response.content, features="html.parser")
    rows = soup.select(".subscribed-projects tbody tr")
    assert rows == []
