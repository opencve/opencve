import pytest

from projects.automations import (
    AutomationLookups,
    build_automation_flow_graph,
    format_action,
    format_action_short,
    format_condition_short,
    format_trigger,
)
from projects.models import Automation

TEST_USER_ID = "d7b162c7-2d2c-4687-8be4-c61cd8b0106c"
TEST_USERNAME = "alice.martin"


@pytest.fixture
def lookups():
    return AutomationLookups(
        users_by_id={TEST_USER_ID: TEST_USERNAME},
        notifications_by_id={"notif-1": "Slack alerts"},
        status_labels={"to_evaluate": "To evaluate"},
    )


def test_format_trigger_known_type():
    assert format_trigger("cve_enters_project") == "A CVE enters this project"


def test_format_condition_short_cvss():
    node = {"type": "cvss_gte", "value": {"value": 8, "version": "v3.1"}}
    assert format_condition_short(node, AutomationLookups()) == "CVSS v3.1 ≥ 8"


def test_format_action_assign_user_with_username(lookups):
    action = {
        "type": "assign_user",
        "value": TEST_USER_ID,
        "username": TEST_USERNAME,
    }
    assert (
        format_action(action, lookups) == f"Assign the CVE to the user {TEST_USERNAME}"
    )
    assert format_action_short(action, lookups) == f"Assign user: {TEST_USERNAME}"


def test_format_action_change_status_with_label(lookups):
    action = {"type": "change_status", "label": "To evaluate", "value": "to_evaluate"}
    assert format_action(action, lookups) == "Change the CVE status to To evaluate"
    assert format_action_short(action, lookups) == "Change status: To evaluate"


def _node_titles(graph):
    return {n["title"] for n in graph["nodes"]}


def test_build_automation_flow_graph_alert_complex(
    create_organization, create_user, create_project, create_automation, lookups
):
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(
        name="complex-alert",
        project=project,
        configuration={
            "triggers": ["cve_enters_project"],
            "conditions": {
                "operator": "OR",
                "children": [
                    {
                        "operator": "AND",
                        "children": [
                            {
                                "type": "cvss_gte",
                                "value": {"value": 8, "version": "v3.1"},
                            },
                            {"type": "kev_present", "value": True},
                        ],
                    },
                    {
                        "operator": "AND",
                        "children": [
                            {
                                "type": "cvss_gte",
                                "value": {"value": 7.7, "version": "v4.0"},
                            },
                            {"type": "kev_present", "value": True},
                        ],
                    },
                ],
            },
            "actions": [
                {
                    "type": "assign_user",
                    "value": TEST_USER_ID,
                    "username": TEST_USERNAME,
                },
                {
                    "type": "change_status",
                    "label": "To evaluate",
                    "value": "to_evaluate",
                },
            ],
        },
    )
    graph = build_automation_flow_graph(automation, lookups)
    assert graph["trigger_type"] == Automation.TRIGGER_ALERT
    titles = _node_titles(graph)
    assert "A CVE enters this project" in titles
    assert "OR" not in titles
    assert "AND" not in titles
    assert "CVSS v3.1 ≥ 8" in titles
    assert "CVSS v4.0 ≥ 7.7" in titles
    assert "KEV present" in titles
    assert f"Assign user: {TEST_USERNAME}" in titles
    assert "Change status: To evaluate" in titles
    group_titles = [g["title"] for g in graph["groups"]]
    assert group_titles == ["Triggers", "Conditions", "Conditions", "Actions"]
    conditions_groups = [g for g in graph["groups"] if g["title"] == "Conditions"]
    assert len(conditions_groups) == 2
    assert len(conditions_groups[0]["children"]) == 2
    assert len(conditions_groups[1]["children"]) == 2
    assert len(graph["edges"]) > 0


def test_build_automation_flow_graph_alert_empty_conditions(
    create_organization, create_user, create_project, create_automation, lookups
):
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(
        name="empty-conditions",
        project=project,
        configuration={
            "triggers": ["kev_added"],
            "conditions": {"operator": "OR", "children": []},
            "actions": [{"type": "send_notification", "value": "notif-1"}],
        },
    )
    graph = build_automation_flow_graph(automation, lookups)
    titles = _node_titles(graph)
    assert "(none)" in titles
    assert "Notify: Slack alerts" in titles


def test_build_automation_flow_graph_alert_multiple_triggers(
    create_organization, create_user, create_project, create_automation, lookups
):
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(
        name="multi-trigger",
        project=project,
        configuration={
            "triggers": ["cve_enters_project", "description_changed"],
            "conditions": {"operator": "OR", "children": []},
            "actions": [],
        },
    )
    graph = build_automation_flow_graph(automation, lookups)
    triggers_group = next(g for g in graph["groups"] if g["title"] == "Triggers")
    assert len(triggers_group["children"]) == 2
    titles = _node_titles(graph)
    assert "A CVE enters this project" in titles
    assert "The description changes" in titles


def test_build_automation_flow_graph_report_weekly(
    create_organization, create_user, create_project, create_automation, lookups
):
    from datetime import time

    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    automation = create_automation(
        name="weekly-report",
        project=project,
        trigger_type=Automation.TRIGGER_REPORT,
        frequency=Automation.FREQUENCY_WEEKLY,
        schedule_timezone="Europe/Paris",
        schedule_time=time(9, 0),
        schedule_weekday=Automation.WEEKDAY_MONDAY,
        configuration={
            "conditions": {
                "operator": "OR",
                "children": [
                    {
                        "operator": "AND",
                        "children": [{"type": "kev_present", "value": True}],
                    }
                ],
            },
            "actions": [{"type": "send_notification", "value": "notif-1"}],
        },
    )
    graph = build_automation_flow_graph(automation, lookups)
    assert graph["trigger_type"] == Automation.TRIGGER_REPORT
    titles = _node_titles(graph)
    assert "Schedule" in titles
    assert "KEV present" in titles
    assert "Run every Monday at 09:00" in titles
    assert "Notify: Slack alerts" in titles
    group_titles = [g["title"] for g in graph["groups"]]
    assert group_titles == ["Triggers", "Conditions", "Actions"]
