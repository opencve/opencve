import pytest

from includes.storage import (
    run_interval_key,
    redis_set,
    redis_get,
    automation_action_queue_prefix,
    REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_ALERT,
    REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_REPORT_DUE,
)


def test_run_interval_key():
    """Test Redis key format for a run interval."""
    key = run_interval_key(
        "changes_details", "2024-01-01 01:00:00", "2024-01-01 01:59:59"
    )
    assert key == "changes_details_2024-01-01 01:00:00_2024-01-01 01:59:59"


@pytest.mark.web_redis
def test_redis_set_and_get(web_redis_hook):
    """Test roundtrip store and retrieve of JSON data."""
    data = {"project-1": ["change-1", "change-2"]}
    redis_set(web_redis_hook, "test_prefix", "start", "end", data)
    result = redis_get(web_redis_hook, "test_prefix", "start", "end")
    assert result == data


@pytest.mark.web_redis
def test_redis_get_missing_key_returns_default(web_redis_hook):
    """Test that missing key returns empty dict by default."""
    result = redis_get(web_redis_hook, "nonexistent", "start", "end")
    assert result == {}


@pytest.mark.web_redis
def test_redis_get_custom_default(web_redis_hook):
    """Test that missing key returns custom default when specified."""
    result = redis_get(web_redis_hook, "nonexistent", "start", "end", default=[])
    assert result == []


@pytest.mark.web_redis
def test_redis_set_returns_key(web_redis_hook):
    """Test that redis_set returns the generated key."""
    key = redis_set(web_redis_hook, "prefix", "s", "e", {"a": 1})
    assert key == "prefix_s_e"


def test_automation_action_queue_prefix_alert():
    """Test alert queue prefix resolution."""
    assert (
        automation_action_queue_prefix("alert")
        == REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_ALERT
    )


def test_automation_action_queue_prefix_report_due():
    """Test report_due queue prefix resolution."""
    assert (
        automation_action_queue_prefix("report_due")
        == REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_REPORT_DUE
    )


def test_automation_action_queue_prefix_unknown():
    """Test that unknown queue name raises ValueError."""
    with pytest.raises(ValueError, match="Unknown automation action queue_name"):
        automation_action_queue_prefix("invalid")
