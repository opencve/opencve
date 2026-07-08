import json

import pytest
from django.test import override_settings

from projects.models import Automation
from tests.api.v2.conftest import (
    assert_v2_error,
    automation_detail_url,
    automation_execution_detail_url,
    automation_execution_list_url,
    automation_list_url,
    bearer,
    read_token,
    write_token,
)
from tests.projects.services.conftest import MINIMAL_ALERT_CONFIGURATION


REPORT_AUTOMATION_CONFIGURATION = {
    "actions": [{"type": "generate_report", "value": True}],
    "conditions": {
        "operator": "OR",
        "children": [
            {
                "operator": "AND",
                "children": [{"type": "kev_present", "value": True}],
            }
        ],
    },
}


@pytest.mark.django_db
def test_create_rejects_reserved_name(client, api_context, write_token, create_project):
    """Create rejects the reserved automation name 'add'."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "add",
                "trigger_type": Automation.TRIGGER_ALERT,
                "configuration": MINIMAL_ALERT_CONFIGURATION,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This name is reserved."]},
    )


@pytest.mark.django_db
def test_create_rejects_invalid_name_chars(
    client, api_context, write_token, create_project
):
    """Create rejects automation names with invalid characters."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "bad@name",
                "trigger_type": Automation.TRIGGER_ALERT,
                "configuration": MINIMAL_ALERT_CONFIGURATION,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={
            "name": ["Special characters (except dash and underscore) are not accepted"]
        },
    )


@pytest.mark.django_db
def test_create_rejects_duplicate_name(
    client, api_context, write_token, create_project, create_automation
):
    """Create rejects duplicate automation names within a project."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_automation(name="existing", project=project)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "existing",
                "trigger_type": Automation.TRIGGER_ALERT,
                "configuration": MINIMAL_ALERT_CONFIGURATION,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert_v2_error(
        response,
        "validation_error",
        details={"name": ["This name already exists."]},
    )


@pytest.mark.django_db
def test_list_automations(
    client, api_context, write_token, create_project, create_automation
):
    """List returns automations for the project."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_automation(name="weekly-report", project=project)

    response = client.get(automation_list_url(), **bearer(write_token))

    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 1
    assert results[0]["name"] == "weekly-report"
    assert "configuration" not in results[0]


@pytest.mark.django_db
def test_retrieve_automation(
    client, api_context, write_token, create_project, create_automation
):
    """Retrieve returns automation details including configuration."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_automation(name="weekly-report", project=project)

    response = client.get(
        automation_detail_url("weekly-report"),
        **bearer(write_token),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "weekly-report"
    assert "configuration" in data


@pytest.mark.django_db
def test_delete_automation_returns_204(
    client, api_context, write_token, create_project, create_automation
):
    """DELETE removes an automation and returns 204."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    create_automation(name="weekly-report", project=project)

    response = client.delete(
        automation_detail_url("weekly-report"),
        **bearer(write_token),
    )

    assert response.status_code == 204
    assert not Automation.objects.filter(name="weekly-report", project=project).exists()


@pytest.mark.django_db
def test_create_report_automation(client, api_context, write_token, create_project):
    """Create a scheduled report automation successfully."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "Weekly KEV report",
                "is_enabled": True,
                "trigger_type": Automation.TRIGGER_REPORT,
                "frequency": Automation.FREQUENCY_WEEKLY,
                "schedule_timezone": "UTC",
                "schedule_time": "09:00:00",
                "schedule_weekday": "monday",
                "configuration": REPORT_AUTOMATION_CONFIGURATION,
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Weekly KEV report"
    assert data["trigger_type"] == Automation.TRIGGER_REPORT
    assert data["frequency"] == Automation.FREQUENCY_WEEKLY


@pytest.mark.django_db
def test_create_alert_without_triggers_returns_400(
    client, api_context, write_token, create_project
):
    """Create alert automation without triggers returns 400."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "my-alert",
                "trigger_type": Automation.TRIGGER_ALERT,
                "configuration": {
                    "conditions": {"operator": "OR", "children": []},
                    "actions": [{"type": "send_notification", "value": "notif-1"}],
                },
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    assert "event" in str(response.json()["error"]["details"]).lower()


@pytest.mark.django_db
def test_create_invalid_conditions_returns_400(
    client, api_context, write_token, create_project
):
    """Create automation with invalid conditions returns 400."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "my-alert",
                "trigger_type": Automation.TRIGGER_ALERT,
                "configuration": {
                    **MINIMAL_ALERT_CONFIGURATION,
                    "conditions": {},
                },
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    assert "Condition node must have" in str(response.json()["error"]["details"])


@pytest.mark.django_db
def test_execution_list_and_retrieve_include_results(
    client,
    api_context,
    write_token,
    create_project,
    create_automation,
    create_automation_execution,
    create_automation_run_result,
):
    """Execution list and retrieve expose execution metadata and run results."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    automation = create_automation(name="weekly-report", project=project)
    execution = create_automation_execution(automation, matched_cves_count=2)
    create_automation_run_result(
        execution,
        output_type="notification_sent",
        label="Notification sent",
    )

    list_response = client.get(
        automation_execution_list_url("weekly-report"),
        **bearer(write_token),
    )
    detail_response = client.get(
        automation_execution_detail_url("weekly-report", execution.id),
        **bearer(write_token),
    )

    assert list_response.status_code == 200
    list_item = list_response.json()["results"][0]
    assert list_item["id"] == str(execution.id)
    assert list_item["matched_cves_count"] == 2
    assert "results" not in list_item

    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == str(execution.id)
    assert len(detail["results"]) == 1
    assert detail["results"][0]["label"] == "Notification sent"


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_read_only_token_on_post_returns_403(
    client, api_context, read_token, create_project
):
    """POST rejects read-only tokens with 403."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        automation_list_url(),
        data=json.dumps(
            {
                "name": "my-alert",
                "trigger_type": Automation.TRIGGER_ALERT,
                "configuration": MINIMAL_ALERT_CONFIGURATION,
            }
        ),
        content_type="application/json",
        **bearer(read_token),
    )

    assert_v2_error(response, "read_only_token", status_code=403)
