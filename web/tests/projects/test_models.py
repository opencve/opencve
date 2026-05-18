import pytest
from datetime import time

from django.db import IntegrityError
from django.utils.timezone import now

from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    CveTracker,
    count_conditions_tree,
    get_default_automation_config,
)


def test_project_model(create_user, create_organization, create_project):
    user = create_user(username="user1")
    org = create_organization(name="organization1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        description="my description",
        vendors=["vendor1", "vendor2"],
        products=["product1", "product2"],
    )

    assert project.name == "project1"
    assert project.description == "my description"
    assert project.active is True
    assert project.subscriptions == {
        "vendors": ["vendor1", "vendor2"],
        "products": ["product1", "product2"],
    }
    assert project.organization == org
    assert project.get_absolute_url() == "/org/organization1/projects/project1"
    assert project.subscriptions_count == 4


def test_cve_tracker_model(
    create_user, create_organization, create_project, create_cve
):
    """Test basic CveTracker model creation and relationships"""
    user = create_user(username="user1")
    org = create_organization(name="organization1", user=user)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")

    tracker = CveTracker.objects.create(
        cve=cve,
        project=project,
        assignee=user,
        status="to_evaluate",
    )

    assert tracker.cve == cve
    assert tracker.project == project
    assert tracker.assignee == user
    assert tracker.status == "to_evaluate"
    assert tracker.assigned_at is not None
    assert str(tracker) == f"{cve.cve_id} ({project.name})"


def test_cve_tracker_unique_constraint(create_organization, create_project, create_cve):
    """Test that CVE-project combination must be unique"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")

    # Create first tracker
    CveTracker.objects.create(cve=cve, project=project)

    # Try to create duplicate
    with pytest.raises(IntegrityError):
        CveTracker.objects.create(cve=cve, project=project)


def test_cve_tracker_update_tracker_create_new(
    create_organization, create_project, create_cve
):
    """Test update_tracker creates a new tracker when it doesn't exist"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")

    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=None,
        status="to_evaluate",
    )

    assert tracker is not None
    assert tracker.cve == cve
    assert tracker.project == project
    assert tracker.assignee is None
    assert tracker.status == "to_evaluate"


def test_cve_tracker_update_tracker_update_assignee(
    create_organization, create_project, create_cve, create_user
):
    """Test update_tracker updates assignee"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")

    # Create tracker with user1
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user1,
        status="to_evaluate",
    )
    assert tracker.assignee == user1

    # Update assignee to user2
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user2,
    )
    assert tracker.assignee == user2
    assert tracker.status == "to_evaluate"  # Status should remain unchanged


def test_cve_tracker_update_tracker_update_status(
    create_organization, create_project, create_cve
):
    """Test update_tracker updates status"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")

    # Create tracker with initial status
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status="to_evaluate",
    )
    assert tracker.status == "to_evaluate"

    # Update status
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status="resolved",
    )
    assert tracker.status == "resolved"


def test_cve_tracker_update_tracker_clear_assignee(
    create_organization, create_project, create_cve, create_user
):
    """Test update_tracker clears assignee when None is provided"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user = create_user(username="user1")

    # Create tracker with assignee
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user,
        status="to_evaluate",
    )
    assert tracker.assignee == user

    # Clear assignee
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=None,
    )
    assert tracker.assignee is None
    assert tracker.status == "to_evaluate"  # Status should remain unchanged


def test_cve_tracker_update_tracker_clear_status(
    create_organization, create_project, create_cve, create_user
):
    """Test update_tracker clears status when empty string or None is provided"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user = create_user(username="user1")

    # Create tracker with status and assignee
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user,
        status="to_evaluate",
    )
    assert tracker.status == "to_evaluate"
    assert tracker.assignee == user

    # Clear status with empty string
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status="",
    )
    assert tracker.status is None
    assert tracker.assignee == user  # Assignee should remain

    # Set status again
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status="resolved",
    )
    assert tracker.status == "resolved"
    assert tracker.assignee == user

    # Clear status with None
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status=None,
    )
    assert tracker.status is None
    assert tracker.assignee == user  # Assignee should remain


def test_cve_tracker_update_tracker_skip_with_ellipsis(
    create_organization, create_project, create_cve, create_user
):
    """Test update_tracker skips updates when Ellipsis is provided"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user = create_user(username="user1")

    # Create tracker with initial values
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user,
        status="to_evaluate",
    )
    original_assignee = tracker.assignee
    original_status = tracker.status

    # Update with Ellipsis - should skip both
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=Ellipsis,
        status=Ellipsis,
    )
    assert tracker.assignee == original_assignee
    assert tracker.status == original_status


def test_cve_tracker_update_tracker_delete_when_empty(
    create_organization, create_project, create_cve
):
    """Test update_tracker deletes tracker when both assignee and status are empty"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")

    # Create tracker with only status
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status="to_evaluate",
    )
    assert tracker is not None

    # Clear status - tracker should be deleted
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status=None,
    )
    assert tracker is None
    assert not CveTracker.objects.filter(cve=cve, project=project).exists()


def test_cve_tracker_update_tracker_delete_when_both_empty(
    create_organization, create_project, create_cve, create_user
):
    """Test update_tracker deletes tracker when both assignee and status are cleared"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user = create_user(username="user1")

    # Create tracker with both assignee and status
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user,
        status="to_evaluate",
    )
    assert tracker is not None

    # Clear both - tracker should be deleted
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=None,
        status=None,
    )
    assert tracker is None
    assert not CveTracker.objects.filter(cve=cve, project=project).exists()


def test_cve_tracker_update_tracker_keeps_one_when_other_cleared(
    create_organization, create_project, create_cve, create_user
):
    """Test update_tracker keeps tracker if at least one of assignee or status exists"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user = create_user(username="user1")

    # Create tracker with both
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=user,
        status="to_evaluate",
    )
    assert tracker is not None

    # Clear status but keep assignee
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        status=None,
    )
    assert tracker is not None
    assert tracker.assignee == user
    assert tracker.status is None

    # Clear assignee but keep status
    tracker = CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=None,
        status="resolved",
    )
    assert tracker is not None
    assert tracker.assignee is None
    assert tracker.status == "resolved"


def test_cve_tracker_status_choices(create_organization, create_project, create_cve):
    """Test that all status choices are valid"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)

    valid_statuses = [
        "to_evaluate",
        "pending_review",
        "analysis_in_progress",
        "remediation_in_progress",
        "evaluated",
        "resolved",
        "not_applicable",
        "risk_accepted",
    ]

    # Use different CVEs for each status to avoid unique constraint violation
    cve_ids = [
        "CVE-2021-34181",
        "CVE-2021-44228",
        "CVE-2022-20698",
        "CVE-2022-22965",
        "CVE-2022-48703",
        "CVE-2023-22490",
        "CVE-2024-31331",
        "CVE-2025-2239",
    ]

    for status, cve_id in zip(valid_statuses, cve_ids):
        cve = create_cve(cve_id)
        tracker = CveTracker.update_tracker(
            project=project,
            cve=cve,
            status=status,
        )
        assert tracker.status == status


def test_cve_tracker_relationships(
    create_organization, create_project, create_cve, create_user
):
    """Test CveTracker relationships (reverse lookups)"""
    org = create_organization(name="organization1")
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2021-34181")
    user = create_user(username="user1")

    tracker = CveTracker.objects.create(
        cve=cve,
        project=project,
        assignee=user,
        status="to_evaluate",
    )

    # Test reverse lookup from CVE
    assert tracker in cve.trackers.all()

    # Test reverse lookup from Project
    assert tracker in project.cve_trackers.all()

    # Test reverse lookup from User
    assert tracker in user.assigned_cves.all()


def test_notification_is_pending_email_confirmation(
    create_organization, create_project, create_notification
):
    """is_pending_email_confirmation is True only for email type with confirmation_token in extras."""
    org = create_organization(name="org1")
    project = create_project(name="project1", organization=org)

    email_pending = create_notification(
        name="pending",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {"email": "a@b.com", "confirmation_token": "abc123"},
        },
    )
    assert email_pending.is_pending_email_confirmation is True

    email_confirmed = create_notification(
        name="confirmed",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {"email": "b@c.com", "unsubscribe_token": "xyz"},
        },
    )
    assert email_confirmed.is_pending_email_confirmation is False

    webhook_notif = create_notification(
        name="webhook",
        project=project,
        type="webhook",
        configuration={"types": [], "metrics": {}, "extras": {"url": "https://x.com"}},
    )
    assert webhook_notif.is_pending_email_confirmation is False


# --- Automation tests ---


def test_get_default_automation_config():
    """Return a dict with empty conditions tree and empty actions list."""
    config = get_default_automation_config()
    assert config == {"conditions": {"operator": "OR", "children": []}, "actions": []}


@pytest.mark.parametrize(
    "node,expected",
    [
        (None, 0),
        ({}, 0),
        ({"operator": "OR", "children": []}, 0),
        ({"type": "cvss_gte", "value": 7}, 1),
        (
            {
                "operator": "OR",
                "children": [
                    {"type": "cvss_gte", "value": 7},
                    {"type": "kev_present", "value": True},
                ],
            },
            2,
        ),
        (
            {
                "operator": "OR",
                "children": [
                    {
                        "operator": "AND",
                        "children": [
                            {"type": "cvss_gte", "value": 7},
                            {"type": "kev_present", "value": True},
                        ],
                    },
                    {
                        "operator": "AND",
                        "children": [
                            {"type": "cvss_gte", "value": 9},
                        ],
                    },
                ],
            },
            3,
        ),
    ],
)
def test_count_conditions_tree(node, expected):
    """Count leaf conditions in various tree shapes."""
    assert count_conditions_tree(node) == expected


def test_automation_model(create_user, create_organization, create_project):
    """Create an alert automation and verify all fields."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    automation = Automation.objects.create(
        name="My Alert",
        project=project,
        trigger_type=Automation.TRIGGER_ALERT,
        is_enabled=True,
        configuration={
            "conditions": {"operator": "OR", "children": []},
            "actions": [{"type": "send_notification", "value": "abc"}],
        },
    )

    assert automation.name == "My Alert"
    assert automation.project == project
    assert automation.trigger_type == Automation.TRIGGER_ALERT
    assert automation.is_enabled is True
    assert str(automation) == "My Alert"
    assert automation.frequency is None
    assert automation.schedule_timezone is None
    assert automation.schedule_time is None
    assert automation.schedule_weekday is None


def test_automation_get_absolute_url(
    create_user, create_organization, create_project, create_automation
):
    """Return the overview URL for the automation."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(name="my-alert", project=project)

    assert automation.get_absolute_url() == (
        "/org/org1/projects/project1/automations/my-alert"
    )


def test_automation_conditions_count(create_user, create_organization, create_project):
    """conditions_count returns the number of leaf conditions in the configuration tree."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    automation = Automation.objects.create(
        name="complex",
        project=project,
        configuration={
            "conditions": {
                "operator": "OR",
                "children": [
                    {
                        "operator": "AND",
                        "children": [
                            {
                                "type": "cvss_gte",
                                "value": {"version": "v3.1", "value": 7},
                            },
                            {"type": "kev_present", "value": True},
                        ],
                    },
                ],
            },
            "actions": [],
        },
    )
    assert automation.conditions_count == 2

    empty = Automation.objects.create(
        name="empty",
        project=project,
    )
    assert empty.conditions_count == 0


def test_automation_report_trigger(create_user, create_organization, create_project):
    """Create a report automation with schedule fields."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    automation = Automation.objects.create(
        name="Daily Report",
        project=project,
        trigger_type=Automation.TRIGGER_REPORT,
        frequency=Automation.FREQUENCY_DAILY,
        schedule_timezone="Europe/Paris",
        schedule_time=time(9, 0),
    )

    assert automation.trigger_type == Automation.TRIGGER_REPORT
    assert automation.frequency == Automation.FREQUENCY_DAILY
    assert automation.schedule_timezone == "Europe/Paris"
    assert automation.schedule_time == time(9, 0)
    assert automation.schedule_weekday is None


def test_automation_execution_model(
    create_user,
    create_organization,
    create_project,
    create_automation,
    create_automation_execution,
):
    """Create an execution and verify fields and slug property."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(name="my-alert", project=project)

    ts = now()
    execution = create_automation_execution(
        automation=automation,
        executed_at=ts,
        matched_cves_count=5,
    )

    assert execution.automation == automation
    assert execution.matched_cves_count == 5
    assert execution.slug == ts.strftime("%Y-%m-%d-%H-%M")
    assert str(execution) == f"my-alert - {ts}"


def test_automation_execution_ordering(
    create_user,
    create_organization,
    create_project,
    create_automation,
    create_automation_execution,
):
    """Executions are ordered by most recent first."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(name="my-alert", project=project)

    from datetime import timedelta

    ts = now()
    old = create_automation_execution(
        automation=automation, executed_at=ts - timedelta(hours=2)
    )
    recent = create_automation_execution(automation=automation, executed_at=ts)

    executions = list(AutomationExecution.objects.filter(automation=automation))
    assert executions[0] == recent
    assert executions[1] == old


def test_automation_run_result_model(
    create_user,
    create_organization,
    create_project,
    create_automation,
    create_automation_execution,
    create_automation_run_result,
):
    """Create a run result and verify fields."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(name="my-alert", project=project)
    execution = create_automation_execution(automation=automation, matched_cves_count=3)

    result = create_automation_run_result(
        automation_execution=execution,
        output_type="notification_sent",
        label="Slack #security",
        status=AutomationRunResult.STATUS_SUCCESS,
        details={"channel": "Slack #security", "status": "sent"},
    )

    assert result.automation_execution == execution
    assert result.output_type == "notification_sent"
    assert result.label == "Slack #security"
    assert result.status == AutomationRunResult.STATUS_SUCCESS
    assert str(result) == f"Slack #security ({execution.id})"


@pytest.mark.parametrize(
    "output_type,details,expected",
    [
        (
            "notification_sent",
            {"channel": "Slack #infra", "status": "sent"},
            "Slack #infra (sent)",
        ),
        ("notification_sent", {"channel": "Slack #infra"}, "Slack #infra"),
        ("notification_sent", {}, "fallback"),
        ("report", {"cve_count": 12}, "12 CVE(s) included"),
        ("report", {}, "fallback"),
        ("assignment", {"summary": "3 CVEs assigned"}, "3 CVEs assigned"),
        (
            "assignment",
            {"assigned_count": 5, "assignee": "alice"},
            '5 CVEs assigned to "alice"',
        ),
        ("status_change", {"summary": "2 moved"}, "2 moved"),
        (
            "status_change",
            {"from_status": "New", "to_status": "Resolved", "updated_count": 4},
            '4 CVEs moved from "New" → "Resolved"',
        ),
        ("status_change", {"updated_count": 3}, "3 CVE(s) updated"),
        ("unknown_type", {"summary": "custom"}, "custom"),
        ("unknown_type", {}, "—"),
    ],
)
def test_automation_run_result_summary_display(
    output_type,
    details,
    expected,
    create_user,
    create_organization,
    create_project,
    create_automation,
    create_automation_execution,
):
    """summary_display returns a human-readable line based on output_type and details."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(name="a", project=project)
    execution = create_automation_execution(automation=automation)

    result = AutomationRunResult.objects.create(
        automation_execution=execution,
        output_type=output_type,
        label="fallback",
        details=details,
    )
    assert result.summary_display == expected


def test_automation_cascade_delete(
    create_user,
    create_organization,
    create_project,
    create_automation,
    create_automation_execution,
    create_automation_run_result,
):
    """Deleting an automation cascades to executions and results."""
    user = create_user(username="user1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(name="my-alert", project=project)
    execution = create_automation_execution(automation=automation)
    create_automation_run_result(automation_execution=execution)

    automation.delete()

    assert AutomationExecution.objects.count() == 0
    assert AutomationRunResult.objects.count() == 0
