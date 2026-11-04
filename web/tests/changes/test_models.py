from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from django.test import override_settings

from changes.models import Change, Report


@pytest.mark.django_db
def test_change_model(create_cve, open_file):
    """Verify Change attributes, full_path, kb_data, and change_data from fixture KB."""
    cve = create_cve("CVE-2024-31331")
    change = Change.objects.filter(id="c8b1dcac-1137-4d07-b045-1903de09c7d9").first()

    # Attributes
    assert change.path == "2024/CVE-2024-31331.json"
    assert change.commit == "a" * 40
    assert change.types == ["weaknesses"]
    assert change.cve == cve

    # Properties
    with override_settings(KB_REPO_PATH="/foo/bar"):
        assert change.full_path == Path("/foo/bar/2024/CVE-2024-31331.json")

    kb_data = open_file("kb/2024/CVE-2024-31331.json")
    assert change.kb_data == kb_data

    assert change.change_data == {
        "created": "2024-10-25T19:00:00+00:00",
        "data": [
            {"details": {"added": [], "removed": ["CWE-783"]}, "type": "weaknesses"}
        ],
        "id": "c8b1dcac-1137-4d07-b045-1903de09c7d9",
    }


@pytest.mark.django_db
def test_change_model_kb_data_missing(create_cve, tmp_path):
    """Return empty kb_data and change_data when the KB snapshot file is missing."""
    create_cve("CVE-2024-31331")
    change = Change.objects.filter(id="c8b1dcac-1137-4d07-b045-1903de09c7d9").first()

    with override_settings(KB_REPO_PATH=str(tmp_path)):
        assert change.kb_data == {}
        assert change.change_data == {}


@pytest.mark.django_db
def test_change_model_previous_change(create_cve, open_file):
    """Verify get_previous_change returns the prior change for the same CVE."""
    cve = create_cve("CVE-2024-31331")
    change_1 = Change.objects.filter(id="17d98772-fcde-469c-9694-7f9080da3747").first()
    change_2 = Change.objects.filter(id="c8b1dcac-1137-4d07-b045-1903de09c7d9").first()

    assert not change_1.get_previous_change()
    assert change_2.get_previous_change() == change_1


def test_report_period_window_daily():
    """Verify daily report window spans midnight to end of the same calendar day."""
    report = Report(
        day=date(2026, 5, 18),
        period_type=Report.PERIOD_DAILY,
        period_timezone="UTC",
    )
    start, end = report.get_period_window()
    assert start == datetime(2026, 5, 18, 0, 0, 0, tzinfo=ZoneInfo("UTC"))
    assert end == datetime(2026, 5, 18, 23, 59, 59, tzinfo=ZoneInfo("UTC"))


def test_report_period_window_weekly():
    """Verify weekly report window spans seven days from the report day."""
    report = Report(
        day=date(2026, 5, 22),
        period_type=Report.PERIOD_WEEKLY,
        period_timezone="UTC",
    )
    start, end = report.get_period_window()
    assert start == datetime(2026, 5, 22, 0, 0, 0, tzinfo=ZoneInfo("UTC"))
    assert end == datetime(2026, 5, 28, 23, 59, 59, tzinfo=ZoneInfo("UTC"))


def test_report_period_window_unknown_timezone_falls_back_to_utc():
    """Verify invalid period_timezone falls back to UTC for the period window."""
    report = Report(
        day=date(2026, 5, 18),
        period_type=Report.PERIOD_DAILY,
        period_timezone="Not/A_Real/Zone",
    )
    start, end = report.get_period_window()
    assert start.tzinfo == ZoneInfo("UTC")
    assert end.tzinfo == ZoneInfo("UTC")
