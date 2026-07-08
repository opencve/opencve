import pytest
from django.core.exceptions import ValidationError

from projects.models import Automation
from projects.services.automations import (
    AUTOMATION_NAME_TAKEN_MESSAGE,
    validate_and_normalize_automation_write,
    validate_automation_configuration,
    validate_automation_name,
    validate_automation_schedule,
    validate_conditions_tree,
)

from tests.projects.services.conftest import MINIMAL_ALERT_CONFIGURATION


def test_validate_automation_name_reserved():
    """Reject reserved automation name 'add'."""
    with pytest.raises(ValidationError, match="reserved"):
        validate_automation_name("add")


def test_validate_automation_name_invalid_chars():
    """Reject automation names containing invalid characters."""
    with pytest.raises(ValidationError, match="Special characters"):
        validate_automation_name("bad@name")


def test_validate_automation_name_taken(
    create_organization, create_project, create_automation
):
    """Reject duplicate automation name within the same project."""
    org = create_organization(name="org")
    project = create_project(name="proj", organization=org)
    create_automation(name="existing", project=project)

    with pytest.raises(ValidationError, match=AUTOMATION_NAME_TAKEN_MESSAGE):
        validate_automation_name("existing", project=project)


def test_validate_automation_name_exclude_automation(
    create_organization, create_project, create_automation
):
    """Allow keeping the same name when updating an existing automation."""
    org = create_organization(name="org")
    project = create_project(name="proj", organization=org)
    automation = create_automation(name="existing", project=project)

    validate_automation_name(
        "existing",
        project=project,
        exclude_automation=automation,
    )


def test_validate_conditions_tree_group():
    """Accept a valid group node with OR operator and children."""
    validate_conditions_tree(
        {
            "operator": "OR",
            "children": [{"type": "severity", "value": "high"}],
        }
    )


def test_validate_conditions_tree_leaf():
    """Accept a valid leaf condition node."""
    validate_conditions_tree({"type": "severity", "value": "high"})


def test_validate_conditions_tree_invalid_node():
    """Reject condition nodes missing operator or type."""
    with pytest.raises(ValidationError, match="Condition node must have"):
        validate_conditions_tree({})


def test_validate_automation_configuration_missing_conditions():
    """Reject configuration missing required conditions and actions keys."""
    with pytest.raises(ValidationError, match="Configuration must contain"):
        validate_automation_configuration({}, trigger_type=Automation.TRIGGER_ALERT)


def test_validate_automation_configuration_alert_requires_triggers():
    """Reject alert configuration without triggers."""
    with pytest.raises(ValidationError) as exc:
        validate_automation_configuration(
            {"conditions": {"operator": "OR", "children": []}, "actions": []},
            trigger_type=Automation.TRIGGER_ALERT,
        )
    assert "event" in str(exc.value.messages[0]).lower()


def test_validate_automation_schedule_invalid_timezone():
    """Reject report schedules with an invalid IANA timezone."""
    with pytest.raises(ValidationError) as exc:
        validate_automation_schedule(
            {
                "frequency": Automation.FREQUENCY_DAILY,
                "schedule_timezone": "Invalid/Timezone",
                "schedule_time": "09:00",
            },
            trigger_type=Automation.TRIGGER_REPORT,
        )
    assert "schedule_timezone" in exc.value.message_dict


def test_validate_automation_schedule_half_hour_minute():
    """Reject schedule times that are not aligned to full hours."""
    with pytest.raises(ValidationError) as exc:
        validate_automation_schedule(
            {"schedule_time": "09:30"},
            trigger_type=Automation.TRIGGER_REPORT,
        )
    assert "schedule_time" in exc.value.message_dict


def test_validate_automation_schedule_weekly_without_weekday():
    """Reject weekly report schedules missing a weekday."""
    with pytest.raises(ValidationError) as exc:
        validate_automation_schedule(
            {
                "frequency": Automation.FREQUENCY_WEEKLY,
                "schedule_timezone": "UTC",
                "schedule_time": "09:00",
            },
            trigger_type=Automation.TRIGGER_REPORT,
        )
    assert "schedule_weekday" in exc.value.message_dict


def test_validate_automation_schedule_report_requires_fields():
    """Reject report schedules missing required schedule fields."""
    with pytest.raises(ValidationError) as exc:
        validate_automation_schedule(
            {"frequency": None, "schedule_timezone": None, "schedule_time": None},
            trigger_type=Automation.TRIGGER_REPORT,
        )
    assert "frequency" in exc.value.message_dict


def test_validate_and_normalize_alert_clears_schedule(
    create_organization, create_project
):
    """Clear schedule fields when normalizing alert automation writes."""
    org = create_organization(name="org")
    project = create_project(name="proj", organization=org)

    normalized = validate_and_normalize_automation_write(
        {
            "name": "my-alert",
            "trigger_type": Automation.TRIGGER_ALERT,
            "frequency": Automation.FREQUENCY_DAILY,
            "schedule_timezone": "UTC",
            "schedule_time": "09:00",
            "configuration": MINIMAL_ALERT_CONFIGURATION,
        },
        project=project,
    )

    assert normalized["frequency"] is None
    assert normalized["schedule_timezone"] is None
    assert normalized["schedule_time"] is None


def test_validate_and_normalize_automation_write_partial_update(
    create_organization, create_project, create_automation
):
    """Normalize only the fields included in a partial automation update."""
    org = create_organization(name="org")
    project = create_project(name="proj", organization=org)
    automation = create_automation(
        name="my-report",
        project=project,
        trigger_type=Automation.TRIGGER_REPORT,
        frequency=Automation.FREQUENCY_DAILY,
        schedule_timezone="UTC",
        schedule_time="09:00",
    )

    normalized = validate_and_normalize_automation_write(
        {"schedule_time": "10:00"},
        project=project,
        instance=automation,
        partial=True,
    )

    assert normalized == {"schedule_time": "10:00"}
