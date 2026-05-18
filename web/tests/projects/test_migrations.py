import datetime
import importlib.util
import os

import pytest
from django.apps import apps

from projects.models import Automation, Notification


def _load_migration_function():
    """Load migrate_notification_rules_to_automations from migration 0009."""
    from projects import migrations as proj_migrations

    proj_migrations_dir = os.path.dirname(proj_migrations.__file__)
    path = os.path.join(
        proj_migrations_dir,
        "0009_migrate_notification_rules_to_automations.py",
    )
    spec = importlib.util.spec_from_file_location("migration_0009", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.migrate_notification_rules_to_automations


# ---------------------------------------------------------------------------
# Alert automations (one per notification)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_alert_automation_created_for_each_notification(
    create_organization, create_project, create_notification
):
    """Each notification produces exactly one alert automation with matching name and project."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif-a", project, configuration={"types": ["created"]})
    create_notification("notif-b", project, configuration={"types": ["description"]})

    migrate(apps, None)

    alerts = Automation.objects.filter(trigger_type="alert").order_by("name")
    assert alerts.count() == 2
    assert list(alerts.values_list("name", flat=True)) == ["notif-a", "notif-b"]
    assert all(a.project_id == project.id for a in alerts)


@pytest.mark.django_db
def test_alert_automation_trigger_mapping(
    create_organization, create_project, create_notification
):
    """Legacy notification types are mapped to the correct trigger identifiers."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "notif", project, configuration={"types": ["created", "metrics", "references"]}
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    triggers = auto.configuration["triggers"]
    assert triggers == [
        "cve_enters_project",
        "cvss_increased",
        "cvss_decreased",
        "new_reference",
    ]


@pytest.mark.django_db
def test_alert_automation_triggers_deduplicated(
    create_organization, create_project, create_notification
):
    """Duplicate triggers from overlapping legacy types are kept unique."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif", project, configuration={"types": ["cpes", "vendors"]})

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["triggers"] == ["new_vendor", "new_product"]


@pytest.mark.django_db
def test_alert_automation_with_cvss31_condition(
    create_organization, create_project, create_notification
):
    """A notification with metrics.cvss31 gets a cvss_gte condition."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "notif",
        project,
        configuration={"types": ["created"], "metrics": {"cvss31": "7.5"}},
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    conditions = auto.configuration["conditions"]
    assert conditions == {
        "operator": "OR",
        "children": [
            {
                "operator": "AND",
                "children": [
                    {"type": "cvss_gte", "value": {"value": 7.5, "version": "v3.1"}}
                ],
            }
        ],
    }


@pytest.mark.django_db
def test_alert_automation_without_cvss31_condition(
    create_organization, create_project, create_notification
):
    """A notification without metrics.cvss31 gets an empty AND group."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif", project, configuration={"types": ["created"]})

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    conditions = auto.configuration["conditions"]
    assert conditions == {
        "operator": "OR",
        "children": [{"operator": "AND", "children": []}],
    }


@pytest.mark.django_db
def test_alert_automation_with_invalid_cvss31(
    create_organization, create_project, create_notification
):
    """A non-numeric cvss31 value is silently ignored (empty conditions)."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "notif",
        project,
        configuration={"types": ["created"], "metrics": {"cvss31": "not-a-number"}},
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    and_children = auto.configuration["conditions"]["children"][0]["children"]
    assert and_children == []


@pytest.mark.django_db
def test_alert_automation_send_notification_action(
    create_organization, create_project, create_notification
):
    """The alert automation action references the original notification id."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    notif = create_notification("notif", project, configuration={"types": ["created"]})

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["actions"] == [
        {"type": "send_notification", "value": str(notif.id)}
    ]


@pytest.mark.django_db
def test_alert_automation_preserves_enabled_state(
    create_organization, create_project, create_notification
):
    """A disabled notification produces a disabled alert automation."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "disabled-notif",
        project,
        configuration={"types": ["created"]},
        is_enabled=False,
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.is_enabled is False


@pytest.mark.django_db
def test_notification_configuration_cleaned_after_migration(
    create_organization, create_project, create_notification
):
    """After migration, notification.configuration only retains the extras key."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    notif = create_notification(
        "notif",
        project,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5.0"},
            "extras": {"foo": "bar"},
        },
    )

    migrate(apps, None)

    notif.refresh_from_db()
    assert notif.configuration == {"extras": {"foo": "bar"}}


@pytest.mark.django_db
def test_notification_extras_default_to_empty_dict(
    create_organization, create_project, create_notification
):
    """When notification has no extras key, configuration is set to an empty extras dict."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    notif = create_notification("notif", project, configuration={"types": ["created"]})

    migrate(apps, None)

    notif.refresh_from_db()
    assert notif.configuration == {"extras": {}}


@pytest.mark.django_db
def test_notification_non_dict_extras_replaced(
    create_organization, create_project, create_notification
):
    """When extras is not a dict, it is replaced with an empty dict."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    notif = create_notification(
        "notif", project, configuration={"types": [], "extras": "invalid"}
    )

    migrate(apps, None)

    notif.refresh_from_db()
    assert notif.configuration == {"extras": {}}


@pytest.mark.django_db
def test_alert_automation_with_empty_configuration(
    create_organization, create_project, create_notification
):
    """A notification with empty configuration still produces a valid alert automation."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif", project, configuration={})

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["triggers"] == []
    assert auto.configuration["conditions"]["children"][0]["children"] == []


@pytest.mark.django_db
def test_alert_automation_with_irrelevant_configuration_keys(
    create_organization, create_project, create_notification
):
    """A notification whose configuration has no types/metrics still produces a valid automation."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    notif = create_notification(
        "notif", project, configuration={"unrelated_key": "value"}
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["triggers"] == []
    assert auto.configuration["conditions"]["children"][0]["children"] == []
    assert auto.configuration["actions"][0]["value"] == str(notif.id)


@pytest.mark.django_db
def test_alert_automation_with_non_list_types(
    create_organization, create_project, create_notification
):
    """When types is not a list, triggers fallback to an empty list."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif", project, configuration={"types": "not-a-list"})

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["triggers"] == []


@pytest.mark.django_db
def test_alert_automation_with_non_dict_metrics(
    create_organization, create_project, create_notification
):
    """When metrics is not a dict, conditions fallback to an empty AND group."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "notif", project, configuration={"types": ["created"], "metrics": "bad"}
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["conditions"]["children"][0]["children"] == []


@pytest.mark.django_db
def test_alert_automation_with_unknown_type(
    create_organization, create_project, create_notification
):
    """An unknown legacy type is silently ignored (no trigger added)."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "notif", project, configuration={"types": ["unknown_type", "created"]}
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    assert auto.configuration["triggers"] == ["cve_enters_project"]


# ---------------------------------------------------------------------------
# Report automations (one per project)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_report_automation_created_for_each_project(
    create_organization, create_project, create_notification
):
    """Each project gets exactly one report automation."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    p1 = create_project("proj1", org)
    p2 = create_project("proj2", org)
    create_notification("notif1", p1, configuration={"types": ["created"]})
    create_notification("notif2", p2, configuration={"types": ["created"]})

    migrate(apps, None)

    reports = Automation.objects.filter(trigger_type="report")
    assert reports.count() == 2
    assert set(reports.values_list("project_id", flat=True)) == {p1.id, p2.id}


@pytest.mark.django_db
def test_report_automation_named_daily_report(
    create_organization, create_project, create_notification
):
    """Report automations are named 'Daily report'."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    create_project("proj1", org)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.name == "Daily report"


@pytest.mark.django_db
def test_report_automation_is_always_enabled(
    create_organization, create_project, create_notification
):
    """Report automations are always enabled regardless of notification states."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif", project, configuration={"types": []}, is_enabled=False)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.is_enabled is True


@pytest.mark.django_db
def test_report_automation_has_daily_frequency(create_organization, create_project):
    """Report automations have frequency set to 'daily'."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    create_project("proj1", org)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.frequency == "daily"


@pytest.mark.django_db
def test_report_automation_schedule_time_is_nine_am(
    create_organization, create_project
):
    """Report automations are scheduled at 09:00."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    create_project("proj1", org)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.schedule_time == datetime.time(9, 0)


@pytest.mark.django_db
def test_report_automation_timezone_is_utc(create_organization, create_project):
    """Report automations use the UTC timezone."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    create_project("proj1", org)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.schedule_timezone == "UTC"


@pytest.mark.django_db
def test_report_automation_has_no_conditions(create_organization, create_project):
    """Report automations have an empty condition tree."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    create_project("proj1", org)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.configuration["conditions"] == {
        "operator": "OR",
        "children": [],
    }


@pytest.mark.django_db
def test_report_automation_has_no_actions(create_organization, create_project):
    """Report automations have an empty actions list."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    create_project("proj1", org)

    migrate(apps, None)

    report = Automation.objects.get(trigger_type="report")
    assert report.configuration["actions"] == []


@pytest.mark.django_db
def test_one_report_per_project_even_with_multiple_notifications(
    create_organization, create_project, create_notification
):
    """A project with several notifications still gets exactly one report automation."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification("notif1", project, configuration={"types": ["created"]})
    create_notification("notif2", project, configuration={"types": ["metrics"]})
    create_notification("notif3", project, configuration={"types": ["references"]})

    migrate(apps, None)

    assert Automation.objects.filter(trigger_type="alert", project=project).count() == 3
    assert (
        Automation.objects.filter(trigger_type="report", project=project).count() == 1
    )


@pytest.mark.django_db
def test_report_automation_created_for_project_without_notifications(
    create_organization, create_project
):
    """A project with no notifications still gets a report automation."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)

    migrate(apps, None)

    assert Automation.objects.filter(trigger_type="alert").count() == 0
    assert (
        Automation.objects.filter(trigger_type="report", project=project).count() == 1
    )


# ---------------------------------------------------------------------------
# Combined behavior
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_full_migration_multiple_projects_and_notifications(
    create_organization, create_project, create_notification
):
    """End-to-end: two projects with mixed notifications produce correct alert+report counts."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    p1 = create_project("proj1", org)
    p2 = create_project("proj2", org)
    create_notification(
        "email-notif",
        p1,
        configuration={
            "types": ["created", "description"],
            "metrics": {"cvss31": "9.0"},
            "extras": {"email": "test@example.com"},
        },
    )
    create_notification(
        "slack-notif",
        p1,
        configuration={"types": ["weaknesses"]},
        is_enabled=False,
    )
    create_notification(
        "webhook-notif",
        p2,
        configuration={"types": ["metrics", "references"]},
    )

    migrate(apps, None)

    assert Automation.objects.filter(trigger_type="alert").count() == 3
    assert Automation.objects.filter(trigger_type="report").count() == 2

    alert1 = Automation.objects.get(trigger_type="alert", name="email-notif")
    assert alert1.project_id == p1.id
    assert alert1.is_enabled is True
    assert alert1.configuration["triggers"] == [
        "cve_enters_project",
        "description_changed",
    ]
    assert (
        alert1.configuration["conditions"]["children"][0]["children"][0]["value"][
            "value"
        ]
        == 9.0
    )

    alert2 = Automation.objects.get(trigger_type="alert", name="slack-notif")
    assert alert2.is_enabled is False
    assert alert2.configuration["triggers"] == ["new_weakness"]

    alert3 = Automation.objects.get(trigger_type="alert", name="webhook-notif")
    assert alert3.project_id == p2.id
    assert alert3.configuration["triggers"] == [
        "cvss_increased",
        "cvss_decreased",
        "new_reference",
    ]

    for report in Automation.objects.filter(trigger_type="report"):
        assert report.name == "Daily report"
        assert report.frequency == "daily"
        assert report.schedule_time == datetime.time(9, 0)
        assert report.schedule_timezone == "UTC"
        assert report.configuration["conditions"] == {
            "operator": "OR",
            "children": [],
        }
        assert report.configuration["actions"] == []


@pytest.mark.django_db
def test_migration_with_no_projects_and_no_notifications():
    """When the database has no projects at all, migration runs without error."""
    migrate = _load_migration_function()

    migrate(apps, None)

    assert Automation.objects.count() == 0


@pytest.mark.django_db
def test_notification_extras_preserved_across_projects(
    create_organization, create_project, create_notification
):
    """Extras in notification configurations are preserved per notification across projects."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    p1 = create_project("proj1", org)
    p2 = create_project("proj2", org)
    n1 = create_notification(
        "notif1", p1, configuration={"types": ["created"], "extras": {"key": "val1"}}
    )
    n2 = create_notification(
        "notif2", p2, configuration={"types": ["created"], "extras": {"key": "val2"}}
    )

    migrate(apps, None)

    n1.refresh_from_db()
    n2.refresh_from_db()
    assert n1.configuration == {"extras": {"key": "val1"}}
    assert n2.configuration == {"extras": {"key": "val2"}}


@pytest.mark.django_db
def test_all_legacy_type_mappings(
    create_organization, create_project, create_notification
):
    """Every legacy notification type is correctly mapped to its trigger identifiers."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)

    expected = {
        "created": ["cve_enters_project"],
        "description": ["description_changed"],
        "title": ["title_changed"],
        "first_time": ["cve_enters_project"],
        "weaknesses": ["new_weakness"],
        "cpes": ["new_vendor", "new_product"],
        "vendors": ["new_vendor", "new_product"],
        "references": ["new_reference"],
        "metrics": ["cvss_increased", "cvss_decreased"],
    }

    for legacy_type, expected_triggers in expected.items():
        Notification.objects.all().delete()
        Automation.objects.all().delete()
        create_notification(
            f"notif-{legacy_type}",
            project,
            configuration={"types": [legacy_type]},
        )

        migrate(apps, None)

        auto = Automation.objects.get(trigger_type="alert")
        assert (
            auto.configuration["triggers"] == expected_triggers
        ), f"Failed for type '{legacy_type}'"


@pytest.mark.django_db
def test_report_automation_across_multiple_organizations(
    create_organization, create_project
):
    """Projects in different organizations each get their own report automation."""
    migrate = _load_migration_function()
    org1 = create_organization("org1")
    org2 = create_organization("org2")
    p1 = create_project("proj1", org1)
    p2 = create_project("proj1", org2)

    migrate(apps, None)

    reports = Automation.objects.filter(trigger_type="report")
    assert reports.count() == 2
    assert set(reports.values_list("project_id", flat=True)) == {p1.id, p2.id}


@pytest.mark.django_db
def test_cvss31_integer_value_handled(
    create_organization, create_project, create_notification
):
    """An integer cvss31 value is correctly converted to float in the condition."""
    migrate = _load_migration_function()
    org = create_organization("org1")
    project = create_project("proj1", org)
    create_notification(
        "notif", project, configuration={"types": ["created"], "metrics": {"cvss31": 8}}
    )

    migrate(apps, None)

    auto = Automation.objects.get(trigger_type="alert")
    cvss_cond = auto.configuration["conditions"]["children"][0]["children"][0]
    assert cvss_cond["value"]["value"] == 8.0
    assert isinstance(cvss_cond["value"]["value"], float)
