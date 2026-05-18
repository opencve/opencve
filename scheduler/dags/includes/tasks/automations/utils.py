import importlib
import logging
import uuid

from includes.constants import SQL_CVE_ID_BY_CVE_ID, SQL_UPSERT_CVE_TRACKER

logger = logging.getLogger(__name__)


def get_item_cve_ids(changes, changes_details):
    return list(
        set(changes_details[c]["cve_id"] for c in changes if c in changes_details)
    )


def resolve_notifier_class(notification_type):
    return getattr(
        importlib.import_module("includes.notifiers"),
        f"{notification_type.capitalize()}Notifier",
    )


def upsert_tracker_records(
    postgres_hook, project_id, cve_id_strings, assignee_id=None, status=None
):
    if not cve_id_strings:
        return

    cve_records = postgres_hook.get_records(
        sql=SQL_CVE_ID_BY_CVE_ID,
        parameters={"cve_ids": tuple(cve_id_strings)},
    )
    cve_uuid_map = {record[1]: record[0] for record in cve_records}

    for cve_id_str in cve_id_strings:
        cve_uuid = cve_uuid_map.get(cve_id_str)
        if not cve_uuid:
            logger.warning("Could not find internal ID for CVE %s", cve_id_str)
            continue

        params = {
            "id": str(uuid.uuid4()),
            "cve_id": cve_uuid,
            "project_id": project_id,
            "assignee_id": assignee_id,
            "status": status,
        }
        postgres_hook.run(sql=SQL_UPSERT_CVE_TRACKER, parameters=params)


def as_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_metrics(change_details):
    payload = change_details.get("change_payload") or {}
    metrics = payload.get("metrics")
    return metrics if isinstance(metrics, dict) else {}


def get_updated_metric_change(metrics_details, metric_name):
    updated = metrics_details.get("updated")
    if not isinstance(updated, dict):
        return None, None
    metric_values = updated.get(metric_name) or {}
    old_score = as_number((metric_values.get("old") or {}).get("score"))
    new_score = as_number((metric_values.get("new") or {}).get("score"))
    return old_score, new_score


def has_added_values(change_details, key):
    payload = change_details.get("change_payload") or {}
    details = payload.get(key)
    if not isinstance(details, dict):
        return False
    added = details.get("added")
    return bool(added)
