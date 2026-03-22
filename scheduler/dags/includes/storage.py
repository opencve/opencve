"""
Helpers for Redis keys scoped to a single DAG run interval (start/end).

Large payloads must be stored here — not in Airflow XCom — so the scheduler
can scale to many projects/automations without hitting XCom limits.

Key format matches historical usage: ``{prefix}_{start}_{end}`` where
``start``/``end`` are the same values as ``get_dates_from_context``.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Default TTL: 24h (same as existing tasks)
DEFAULT_RUN_REDIS_TTL_SECONDS = 60 * 60 * 24

# --- Key prefixes (before _{start}_{end}) ---------------------------------

REDIS_PREFIX_CHANGES_DETAILS = "changes_details"
REDIS_PREFIX_VENDOR_CHANGES = "vendor_changes"
REDIS_PREFIX_SUBSCRIPTIONS = "subscriptions"
REDIS_PREFIX_AUTOMATIONS = "automations"
REDIS_PREFIX_PROJECT_CHANGES = "project_changes"
REDIS_PREFIX_NOTIFICATIONS = "notifications"

# Automation pipeline (opencve DAG)
REDIS_PREFIX_SCHEDULED_HOURLY_REPORT_ITEMS = "scheduled_hourly_report_items"
REDIS_PREFIX_SCHEDULED_DUE_WORK_ITEMS = "scheduled_due_work_items"
REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_REALTIME = "automation_action_queue_realtime"
REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_SCHEDULED_DUE = (
    "automation_action_queue_scheduled_due"
)

# Sentinel: omit ``default=`` in ``redis_get`` → use ``{}`` (avoids a mutable default arg).
_REDIS_GET_DEFAULT = object()


def run_interval_key(prefix: str, start, end) -> str:
    """Build the Redis key for one run interval."""
    return f"{prefix}_{start}_{end}"


def _describe_value_for_log(value: Any) -> str:
    """Short summary for logs (avoid dumping huge payloads)."""
    if isinstance(value, dict):
        return f"dict({len(value)} keys)"
    if isinstance(value, list):
        return f"list({len(value)} items)"
    return f"{type(value).__name__}"


def redis_set(
    redis_conn,
    prefix: str,
    start,
    end,
    value: Any,
    ttl_seconds: int = DEFAULT_RUN_REDIS_TTL_SECONDS,
) -> str:
    """Store a JSON value under ``run_interval_key`` and set expiry."""
    key = run_interval_key(prefix, start, end)
    redis_conn.json().set(key, "$", value)
    redis_conn.expire(key, ttl_seconds)

    logger.info(
        "Redis SET JSON key=%s value=%s",
        key,
        _describe_value_for_log(value),
    )

    logger.debug(
        "Redis SET JSON key=%s value=%s data=%s",
        key,
        _describe_value_for_log(value),
        value,
    )

    return key


def redis_get(
    redis_conn,
    prefix: str,
    start,
    end,
    default: Any = _REDIS_GET_DEFAULT,
):
    """Read JSON for this run interval.

    If the key is absent or the stored value is JSON null, returns ``default``.
    When ``default`` is omitted, ``{}`` is used (typical case). Pass ``default=[]``
    when a missing key should yield an empty list.
    """
    if default is _REDIS_GET_DEFAULT:
        default = {}
    key = run_interval_key(prefix, start, end)
    data = redis_conn.json().get(key)
    if data is None:
        logger.info(
            "Redis GET JSON key=%s is empty (using default %s)",
            key,
            _describe_value_for_log(default),
        )
        return default

    logger.info(
        "Redis GET JSON key=%s hit value=%s",
        key,
        _describe_value_for_log(data),
    )

    logger.debug(
        "Redis GET JSON key=%s raw data=%s",
        key,
        data,
    )
    return data


def automation_action_queue_prefix(queue_name: str) -> str:
    """Map logical queue name to Redis prefix for action batches."""
    if queue_name == "realtime":
        return REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_REALTIME
    if queue_name == "scheduled_due":
        return REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_SCHEDULED_DUE
    raise ValueError(
        f"Unknown automation action queue_name={queue_name!r}; "
        f"expected 'realtime' or 'scheduled_due'"
    )
