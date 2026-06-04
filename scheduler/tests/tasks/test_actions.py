import asyncio

import pendulum
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from includes.tasks.automations.actions import (
    execute_action,
    RESULT_STATUS_SUCCESS,
    RESULT_STATUS_SKIPPED,
    RESULT_STATUS_FAILED,
)


@pytest.mark.asyncio
async def test_execute_action_unknown_type():
    """Unknown action type returns a skipped result."""
    result = await execute_action({"type": "nonexistent"}, {})
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "Unknown action type" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_assign_user_action_success():
    """Assign user action upserts tracker records for matching CVEs."""
    mock_hook = MagicMock()
    mock_hook.get_records.return_value = [
        ("cve-uuid-1", "CVE-2024-0001", "2024-01-01"),
    ]
    action = {"type": "assign_user", "value": "user-uuid-1", "username": "john"}
    context = {
        "postgres_hook": mock_hook,
        "automation": {"project_id": "project-1"},
        "changes": ["change-1"],
        "item_changes_details": {
            "change-1": {"cve_id": "CVE-2024-0001"},
        },
    }
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_SUCCESS
    assert result["details"]["assigned_count"] == 1
    assert result["details"]["assignee"] == "john"
    mock_hook.run.assert_called_once()


@pytest.mark.asyncio
async def test_assign_user_action_no_assignee():
    """Assign user action is skipped when no assignee is provided."""
    action = {"type": "assign_user", "value": None}
    result = await execute_action(action, {})
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "No assignee specified" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_change_status_action_success():
    """Change status action upserts tracker records with new status."""
    mock_hook = MagicMock()
    mock_hook.get_records.return_value = [
        ("cve-uuid-1", "CVE-2024-0001", "2024-01-01"),
    ]
    action = {"type": "change_status", "value": "in_triage", "label": "In Triage"}
    context = {
        "postgres_hook": mock_hook,
        "automation": {"project_id": "project-1"},
        "changes": ["change-1"],
        "item_changes_details": {
            "change-1": {"cve_id": "CVE-2024-0001"},
        },
    }
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_SUCCESS
    assert result["details"]["updated_count"] == 1
    assert result["details"]["to_status"] == "in_triage"


@pytest.mark.asyncio
async def test_change_status_action_no_status():
    """Change status action is skipped when no status is provided."""
    action = {"type": "change_status", "value": None}
    result = await execute_action(action, {})
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "No status specified" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_generate_report_action_disabled():
    """Generate report action is skipped when value is False."""
    action = {"type": "generate_report", "value": False}
    context = {"automation": {"automation_name": "test"}, "changes": []}
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "disabled" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_generate_report_action_success():
    """Generate report action succeeds when report content is available."""
    action = {"type": "generate_report", "value": True}
    context = {
        "automation": {"automation_name": "test"},
        "changes": ["change-1"],
        "report_content": {
            "report_id": "report-1",
            "report_day": "2024-01-01",
            "cve_count": 5,
        },
    }
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_SUCCESS
    assert result["details"]["report_id"] == "report-1"
    assert result["details"]["cve_count"] == 5


@pytest.mark.asyncio
async def test_generate_report_action_no_report_content():
    """Generate report action is skipped when no report content is available."""
    action = {"type": "generate_report", "value": True}
    context = {
        "automation": {"automation_name": "test"},
        "changes": [],
        "report_content": None,
    }
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "No report content" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_send_notification_action_no_id():
    """Send notification is skipped when no notification ID is provided."""
    action = {"type": "send_notification", "value": None}
    result = await execute_action(action, {})
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "No notification ID" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_send_notification_action_not_found():
    """Send notification is skipped when notification record is not found."""
    mock_hook = MagicMock()
    mock_hook.get_first.return_value = None
    action = {
        "type": "send_notification",
        "value": "notif-1",
        "notification_name": "My Webhook",
    }
    context = {"postgres_hook": mock_hook}
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_SKIPPED
    assert "not found or disabled" in result["details"]["summary"]


@pytest.mark.asyncio
async def test_send_notification_action_uses_prefetched_cache():
    """Prefetched notifications_cache avoids per-action SQL lookups."""
    mock_hook = MagicMock()
    mock_notifier_cls = MagicMock()
    mock_notifier = AsyncMock()
    mock_notifier.execute.return_value = {
        "status": RESULT_STATUS_SUCCESS,
        "details": {"channel": "Email"},
    }
    mock_notifier_cls.return_value = mock_notifier

    action = {
        "type": "send_notification",
        "value": "notif-uuid-1",
        "notification_name": "Email",
    }
    context = {
        "postgres_hook": mock_hook,
        "notifications_cache": {
            "notif-uuid-1": {
                "name": "My Email",
                "type": "email",
                "configuration": {"to": "user@example.com"},
            }
        },
        "semaphore": asyncio.Semaphore(1),
        "session": MagicMock(),
        "automation": {
            "project_id": "project-1",
            "project_name": "test-project",
            "project_subscriptions": ["foo"],
            "organization_name": "test-org",
        },
        "changes": ["change-1"],
        "item_changes_details": {
            "change-1": {"cve_id": "CVE-2024-0001"},
        },
        "period": {
            "start": pendulum.datetime(2024, 1, 1, tz="UTC"),
            "end": pendulum.datetime(2024, 1, 2, tz="UTC"),
        },
    }

    with patch(
        "includes.tasks.automations.actions.resolve_notifier_class",
        return_value=mock_notifier_cls,
    ):
        result = await execute_action(action, context)

    assert result["status"] == RESULT_STATUS_SUCCESS
    mock_hook.get_first.assert_not_called()
    mock_notifier_cls.assert_called_once()


@pytest.mark.asyncio
async def test_execute_action_exception_returns_failed():
    """Action that raises an exception returns a failed result."""
    action = {"type": "assign_user", "value": "user-1"}
    mock_hook = MagicMock()
    mock_hook.get_records.side_effect = Exception("DB error")
    context = {
        "postgres_hook": mock_hook,
        "automation": {"project_id": "p1"},
        "changes": ["c1"],
        "item_changes_details": {"c1": {"cve_id": "CVE-2024-0001"}},
    }
    result = await execute_action(action, context)
    assert result["status"] == RESULT_STATUS_FAILED
