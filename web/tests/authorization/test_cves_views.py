from types import SimpleNamespace
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


def _patch_cve_kb(func):
    """Apply CVE KB PropertyMock patches (args: enrichment → … → nvd)."""
    # Applied bottom-up: enrichment is the first injected mock argument.
    for attr in (
        "nvd_json",
        "mitre_json",
        "redhat_json",
        "vulnrichment_json",
        "enrichment_json",
    ):
        func = patch(f"cves.models.Cve.{attr}", new_callable=PropertyMock)(func)
    return func


def _empty_kb_mocks(*mocks):
    for mock in mocks:
        mock.return_value = {}


@pytest.fixture
def cve_detail_acl_scenario(
    create_user, create_organization, create_project, create_cve
):
    """
    Shared org layout for CVE detail ACL checks.

    Projects:
    - alpha, beta, delta: subscribed to git-scm (CVE-2023-22490)
    - unsubscribed: not subscribed
    - gamma: subscribed but inactive
    """
    owner = create_user(username="owner")
    org = create_organization(name="org1", user=owner)
    alpha = create_project(name="alpha", organization=org, vendors=["git-scm"])
    beta = create_project(name="beta", organization=org, vendors=["git-scm"])
    delta = create_project(name="delta", organization=org, vendors=["git-scm"])
    unsubscribed = create_project(name="unsubscribed", organization=org, vendors=[])
    gamma = create_project(
        name="gamma", organization=org, vendors=["git-scm"], active=False
    )
    cve = create_cve("CVE-2023-22490")
    return SimpleNamespace(
        owner=owner,
        org=org,
        alpha=alpha,
        beta=beta,
        delta=delta,
        unsubscribed=unsubscribed,
        gamma=gamma,
        cve=cve,
    )


def _create_org_member(scenario, create_user, *, username, org_role=Membership.MEMBER):
    user = create_user(username=username)
    membership = Membership.objects.create(
        user=user,
        organization=scenario.org,
        role=org_role,
        date_invited=now(),
        date_joined=now(),
    )
    return user, membership


def _assign_project_role(membership, project, role):
    ProjectMembership.objects.create(
        project=project,
        membership=membership,
        role=role,
    )


def _tracking_names(response):
    return [item["project"].name for item in response.context["filtered_projects"]]


def _subscription_names(response):
    return [p.name for p in response.context["projects"]]


def _assert_cve_detail_acl(
    response,
    *,
    tracking,
    subscriptions,
    can_subscribe,
    can_edit_tracker,
):
    assert response.status_code == 200
    assert _tracking_names(response) == tracking
    assert _subscription_names(response) == subscriptions

    content = response.content.decode()
    for name in tracking:
        assert f'data-project-name="{name}"' in content
    for name in ("alpha", "beta", "delta", "unsubscribed", "gamma"):
        if name not in tracking:
            assert f'data-project-name="{name}"' not in content

    if can_subscribe:
        assert "subscribe-vendor" in content
        assert "subscribe-product" in content
        assert "subscription-grid-readonly" not in content
        for name in subscriptions:
            assert name in response.context["projects_json"]
    else:
        assert "subscribe-vendor" not in content
        assert "subscribe-product" not in content
        assert response.context["projects_json"] == "[]"
        if response.context.get("vendors"):
            assert "subscription-grid-readonly" in content

    if tracking and can_edit_tracker:
        assert "editable-assignee" in content
        assert "editable-status" in content
        assert "project-comment-textarea" in content
    else:
        assert "editable-assignee" not in content
        assert "editable-status" not in content
        assert "project-comment-textarea" not in content


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_tracking_viewer_sees_comments_without_comment_form(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    create_cve,
    create_user,
    create_organization,
    create_project,
    auth_client,
    set_current_org,
):
    """Viewer reads tracker comments on CVE detail but cannot see comment forms."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )

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


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_org_owner_sees_all_accessible_and_manageable_projects(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    auth_client,
    set_current_org,
):
    """Org owner has Project Admin on every project (implicit)."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    client = set_current_org(auth_client(scenario.owner), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        # Inactive gamma remains accessible and subscribed.
        tracking=["alpha", "beta", "delta", "gamma"],
        # Subscription management excludes inactive projects.
        subscriptions=["alpha", "beta", "delta", "unsubscribed"],
        can_subscribe=True,
        can_edit_tracker=True,
    )


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_org_admin_sees_all_accessible_and_manageable_projects(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Org admin has the same implicit Project Admin access as owner."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    admin, _ = _create_org_member(
        scenario, create_user, username="admin", org_role=Membership.ADMIN
    )
    client = set_current_org(auth_client(admin), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=["alpha", "beta", "delta", "gamma"],
        subscriptions=["alpha", "beta", "delta", "unsubscribed"],
        can_subscribe=True,
        can_edit_tracker=True,
    )


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_org_member_without_project_sees_nothing(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Org member with no project membership sees no tracking and cannot subscribe."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    member, _ = _create_org_member(scenario, create_user, username="lonely-member")
    client = set_current_org(auth_client(member), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=[],
        subscriptions=[],
        can_subscribe=False,
        can_edit_tracker=False,
    )
    assert "No projects match this CVE" in response.content.decode()


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_project_viewer_sees_only_own_projects_read_only(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Project viewer sees only accessible subscribed projects, read-only, no subscribe."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    viewer, membership = _create_org_member(scenario, create_user, username="viewer")
    _assign_project_role(membership, scenario.alpha, PROJECT_VIEWER)
    _assign_project_role(membership, scenario.beta, PROJECT_VIEWER)

    client = set_current_org(auth_client(viewer), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=["alpha", "beta"],
        subscriptions=[],
        can_subscribe=False,
        can_edit_tracker=False,
    )


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_project_contributor_sees_only_own_projects_editable(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Contributor sees only own subscribed projects, can edit tracker, cannot subscribe."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    contributor, membership = _create_org_member(
        scenario, create_user, username="contributor"
    )
    _assign_project_role(membership, scenario.alpha, PROJECT_CONTRIBUTOR)
    _assign_project_role(membership, scenario.beta, PROJECT_CONTRIBUTOR)

    client = set_current_org(auth_client(contributor), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=["alpha", "beta"],
        subscriptions=[],
        can_subscribe=False,
        can_edit_tracker=True,
    )


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_project_admin_sees_own_projects_and_can_subscribe(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Project admin tracks accessible projects and can manage subscriptions on admin ones."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    project_admin, membership = _create_org_member(
        scenario, create_user, username="project-admin"
    )
    _assign_project_role(membership, scenario.alpha, PROJECT_ADMIN)
    # Contributor on beta: visible in tracking, not in subscription management.
    _assign_project_role(membership, scenario.beta, PROJECT_CONTRIBUTOR)

    client = set_current_org(auth_client(project_admin), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=["alpha", "beta"],
        subscriptions=["alpha"],
        can_subscribe=True,
        can_edit_tracker=True,
    )
    assert str(scenario.delta.id) not in response.context["projects_json"]
    assert str(scenario.beta.id) not in response.context["projects_json"]


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
def test_cve_detail_project_admin_inactive_project_not_in_subscriptions(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Inactive projects stay in tracking when accessible but are not subscription-manageable."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    project_admin, membership = _create_org_member(
        scenario, create_user, username="project-admin-inactive"
    )
    _assign_project_role(membership, scenario.gamma, PROJECT_ADMIN)

    client = set_current_org(auth_client(project_admin), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=["gamma"],
        subscriptions=[],
        can_subscribe=False,
        can_edit_tracker=True,
    )


@_patch_cve_kb
@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.parametrize(
    "project_role, can_edit_tracker, can_subscribe",
    [
        (PROJECT_VIEWER, False, False),
        (PROJECT_CONTRIBUTOR, True, False),
        (PROJECT_ADMIN, True, True),
    ],
    ids=["viewer", "contributor", "project_admin"],
)
def test_cve_detail_project_role_matrix_single_membership(
    mock_nvd,
    mock_mitre,
    mock_redhat,
    mock_vulnrichment,
    mock_enrichment,
    project_role,
    can_edit_tracker,
    can_subscribe,
    cve_detail_acl_scenario,
    create_user,
    auth_client,
    set_current_org,
):
    """Matrix: each project role only sees its membership; edit/subscribe match ACL."""
    _empty_kb_mocks(
        mock_nvd, mock_mitre, mock_redhat, mock_vulnrichment, mock_enrichment
    )
    scenario = cve_detail_acl_scenario
    user, membership = _create_org_member(
        scenario, create_user, username=f"user-{project_role}"
    )
    _assign_project_role(membership, scenario.alpha, project_role)

    client = set_current_org(auth_client(user), scenario.org)
    response = client.get(reverse("cve", kwargs={"cve_id": scenario.cve.cve_id}))

    _assert_cve_detail_acl(
        response,
        tracking=["alpha"],
        subscriptions=["alpha"] if can_subscribe else [],
        can_subscribe=can_subscribe,
        can_edit_tracker=can_edit_tracker,
    )
