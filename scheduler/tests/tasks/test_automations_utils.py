from unittest.mock import MagicMock

from includes.tasks.automations.utils import (
    as_number,
    get_item_cve_ids,
    get_metrics,
    get_updated_metric_change,
    has_added_values,
    resolve_notifier_class,
)


def test_as_number_valid():
    """Valid numeric strings and numbers are converted to float."""
    assert as_number("8.5") == 8.5
    assert as_number(10) == 10.0
    assert as_number(0) == 0.0


def test_as_number_invalid():
    """Non-numeric values return None."""
    assert as_number("abc") is None
    assert as_number(None) is None
    assert as_number("") is None


def test_get_item_cve_ids():
    """Extracts unique CVE IDs from changes list using changes_details lookup."""
    changes = ["change-1", "change-2", "change-3"]
    changes_details = {
        "change-1": {"cve_id": "CVE-2024-0001"},
        "change-2": {"cve_id": "CVE-2024-0001"},
        "change-3": {"cve_id": "CVE-2024-0002"},
    }
    result = sorted(get_item_cve_ids(changes, changes_details))
    assert result == ["CVE-2024-0001", "CVE-2024-0002"]


def test_get_item_cve_ids_missing_change():
    """Missing change IDs in changes_details are skipped."""
    result = get_item_cve_ids(["missing"], {"other": {"cve_id": "CVE-2024-0001"}})
    assert result == []


def test_resolve_notifier_class():
    """Resolves the notifier class for a given notification type."""
    cls = resolve_notifier_class("webhook")
    assert cls.__name__ == "WebhookNotifier"


def test_get_metrics():
    """Extracts metrics dict from change_payload."""
    change = {"change_payload": {"metrics": {"added": {"kev": True}}}}
    assert get_metrics(change) == {"added": {"kev": True}}


def test_get_metrics_empty():
    """Returns empty dict when change_payload is missing."""
    assert get_metrics({}) == {}
    assert get_metrics({"change_payload": None}) == {}
    assert get_metrics({"change_payload": {"metrics": "not_a_dict"}}) == {}


def test_get_updated_metric_change():
    """Extracts old and new scores from updated metrics."""
    metrics = {
        "updated": {
            "cvssV3_1": {
                "old": {"score": 5.0},
                "new": {"score": 8.0},
            }
        }
    }
    old, new = get_updated_metric_change(metrics, "cvssV3_1")
    assert old == 5.0
    assert new == 8.0


def test_get_updated_metric_change_missing():
    """Returns (None, None) when metric is not in updated."""
    old, new = get_updated_metric_change({}, "cvssV3_1")
    assert old is None
    assert new is None


def test_get_updated_metric_change_no_scores():
    """Returns (None, None) when old/new have no score key."""
    metrics = {"updated": {"cvssV3_1": {"old": {}, "new": {}}}}
    old, new = get_updated_metric_change(metrics, "cvssV3_1")
    assert old is None
    assert new is None


def test_has_added_values_true():
    """Returns True when the key has added values."""
    change = {"change_payload": {"vendors": {"added": ["new_vendor"]}}}
    assert has_added_values(change, "vendors") is True


def test_has_added_values_empty():
    """Returns False when added list is empty."""
    change = {"change_payload": {"vendors": {"added": []}}}
    assert has_added_values(change, "vendors") is False


def test_has_added_values_no_payload():
    """Returns False when change_payload is missing."""
    assert has_added_values({}, "vendors") is False


def test_has_added_values_not_dict():
    """Returns False when the key value is not a dict."""
    change = {"change_payload": {"vendors": "not_a_dict"}}
    assert has_added_values(change, "vendors") is False
