import pendulum

from includes.tasks.automations import (
    _cvss_score_to_severity,
    _all_matching_subscriptions,
    build_cves_table_data,
    build_impact_summary_from_cves_table,
    chunk_actions,
    filter_changes_for_automation,
    get_accumulation_period_bucket,
    get_due_period_bucket,
    get_report_period_window,
)


def test_cvss_score_to_severity_critical():
    """Scores 9.0-10.0 are Critical."""
    assert _cvss_score_to_severity(9.0) == "Critical"
    assert _cvss_score_to_severity(10.0) == "Critical"


def test_cvss_score_to_severity_high():
    """Scores 7.0-8.9 are High."""
    assert _cvss_score_to_severity(7.0) == "High"
    assert _cvss_score_to_severity(8.9) == "High"


def test_cvss_score_to_severity_medium():
    """Scores 4.0-6.9 are Medium."""
    assert _cvss_score_to_severity(4.0) == "Medium"
    assert _cvss_score_to_severity(6.9) == "Medium"


def test_cvss_score_to_severity_low():
    """Scores below 4.0 are Low."""
    assert _cvss_score_to_severity(3.9) == "Low"
    assert _cvss_score_to_severity(0.1) == "Low"


def test_cvss_score_to_severity_none():
    """None score returns None."""
    assert _cvss_score_to_severity(None) is None


def test_all_matching_subscriptions():
    """Returns matching vendor/product labels from subscriptions."""
    automation = {"project_subscriptions": ["foo", "foo$PRODUCT$bar"]}
    cve_vendors = ["foo", "foo$PRODUCT$bar", "other"]
    result = _all_matching_subscriptions(automation, cve_vendors)
    assert "foo" in result
    assert "bar" in result


def test_all_matching_subscriptions_no_overlap():
    """Falls back to vendor labels from CVE when no subscription matches."""
    automation = {"project_subscriptions": ["unrelated"]}
    cve_vendors = ["vendor_a", "vendor_b$PRODUCT$prod_b"]
    result = _all_matching_subscriptions(automation, cve_vendors)
    assert "vendor_a" in result
    assert "prod_b" in result


def test_all_matching_subscriptions_empty():
    """Returns empty list when both inputs are empty."""
    result = _all_matching_subscriptions({"project_subscriptions": []}, [])
    assert result == []


def test_build_cves_table_data():
    """Builds CVE table rows from changes details."""
    automation = {"project_subscriptions": ["foo"]}
    item_changes_details = {
        "change-1": {
            "cve_id": "CVE-2024-0001",
            "cve_metrics": {
                "cvssV3_1": {"data": {"score": 8.8}},
                "epss": {"data": {"score": 0.5}},
                "kev": {"data": {"dateAdded": "2024-01-01"}},
            },
            "cve_vendors": ["foo", "foo$PRODUCT$bar"],
        },
    }
    result = build_cves_table_data(automation, item_changes_details)
    assert len(result) == 1
    row = result[0]
    assert row["cve_id"] == "CVE-2024-0001"
    assert row["cvss_31"] == 8.8
    assert row["epss"] == 0.5
    assert row["kev"] is True
    assert "foo" in row["matched_vendors_or_products"]


def test_build_cves_table_data_deduplicates():
    """Multiple changes for the same CVE produce a single row."""
    automation = {"project_subscriptions": []}
    item_changes_details = {
        "c1": {"cve_id": "CVE-2024-0001", "cve_metrics": {}, "cve_vendors": []},
        "c2": {"cve_id": "CVE-2024-0001", "cve_metrics": {}, "cve_vendors": []},
    }
    result = build_cves_table_data(automation, item_changes_details)
    assert len(result) == 1


def test_build_impact_summary_from_cves_table():
    """Builds impact summary with distribution, highest, average, etc."""
    cves_table = [
        {
            "cve_id": "CVE-2024-0001",
            "cvss_31": 9.5,
            "cvss_30": None,
            "cvss_20": None,
            "cvss_40": None,
            "epss": 0.8,
            "kev": True,
            "matched_vendors_or_products": ["vendor1"],
        },
        {
            "cve_id": "CVE-2024-0002",
            "cvss_31": 5.0,
            "cvss_30": None,
            "cvss_20": None,
            "cvss_40": None,
            "epss": 0.1,
            "kev": False,
            "matched_vendors_or_products": ["vendor1"],
        },
    ]
    result = build_impact_summary_from_cves_table(cves_table)
    assert result["cves_count"] == 2
    assert result["highest_cvss"] == 9.5
    assert result["cvss_distribution"]["Critical"] == 1
    assert result["cvss_distribution"]["Medium"] == 1
    assert result["kev_count"] == 1
    assert result["kev_percent"] == 50
    assert len(result["top_vendors_products"]) == 1
    assert result["top_vendors_products"][0]["name"] == "vendor1"
    assert result["top_vendors_products"][0]["count"] == 2


def test_build_impact_summary_from_cves_table_empty():
    """Returns None when input is empty."""
    assert build_impact_summary_from_cves_table([]) is None
    assert build_impact_summary_from_cves_table(None) is None


def test_get_accumulation_period_bucket_daily():
    """Daily accumulation bucket uses the local date."""
    automation = {"frequency": "daily", "schedule_timezone": "UTC"}
    context = {"data_interval_end": pendulum.datetime(2024, 6, 15, 10, 0, tz="UTC")}
    bucket = get_accumulation_period_bucket(automation, context)
    assert bucket["period_day"] == "2024-06-15"
    assert bucket["period_type"] == "daily"
    assert bucket["period_timezone"] == "UTC"


def test_get_accumulation_period_bucket_weekly_friday():
    """Weekly accumulation anchors to the rolling week start (schedule weekday)."""
    automation = {
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_weekday": "friday",
    }
    # Thursday May 28, 2026 is in the week starting Friday May 22
    context = {"data_interval_end": pendulum.datetime(2026, 5, 28, 10, 0, tz="UTC")}
    bucket = get_accumulation_period_bucket(automation, context)
    assert bucket["period_type"] == "weekly"
    assert bucket["period_day"] == "2026-05-22"


def test_get_accumulation_period_bucket_timezone():
    """Accumulation bucket respects the automation timezone."""
    automation = {"frequency": "daily", "schedule_timezone": "America/New_York"}
    context = {"data_interval_end": pendulum.datetime(2024, 6, 15, 3, 0, tz="UTC")}
    bucket = get_accumulation_period_bucket(automation, context)
    assert bucket["period_day"] == "2024-06-14"
    assert bucket["period_timezone"] == "America/New_York"


def test_get_due_period_bucket_daily():
    """Daily due bucket returns yesterday's date."""
    automation = {"frequency": "daily", "schedule_timezone": "UTC"}
    context = {"data_interval_end": pendulum.datetime(2024, 6, 15, 9, 0, tz="UTC")}
    bucket = get_due_period_bucket(automation, context)
    assert bucket["period_day"] == "2024-06-14"
    assert bucket["period_type"] == "daily"


def test_get_due_period_bucket_weekly_friday():
    """Weekly due bucket returns the previous complete 7-day rolling week."""
    automation = {
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_weekday": "friday",
    }
    context = {"data_interval_end": pendulum.datetime(2026, 5, 29, 9, 0, tz="UTC")}
    bucket = get_due_period_bucket(automation, context)
    assert bucket["period_day"] == "2026-05-22"
    assert bucket["period_type"] == "weekly"


def test_get_due_period_bucket_weekly_monday_paris():
    """Weekly due bucket respects automation timezone."""
    automation = {
        "frequency": "weekly",
        "schedule_timezone": "Europe/Paris",
        "schedule_weekday": "monday",
    }
    context = {"data_interval_end": pendulum.datetime(2026, 5, 25, 7, 0, tz="UTC")}
    bucket = get_due_period_bucket(automation, context)
    assert bucket["period_day"] == "2026-05-18"
    assert bucket["period_type"] == "weekly"


def test_get_due_period_bucket_daily_winnipeg():
    """Daily due bucket uses the previous local day in automation timezone."""
    automation = {
        "frequency": "daily",
        "schedule_timezone": "America/Winnipeg",
    }
    # Friday May 22, 2026 at 02:00 Winnipeg = 07:00 UTC
    context = {"data_interval_end": pendulum.datetime(2026, 5, 22, 7, 0, tz="UTC")}
    bucket = get_due_period_bucket(automation, context)
    assert bucket["period_day"] == "2026-05-21"
    assert bucket["period_type"] == "daily"


def test_get_report_period_window_daily_utc():
    """Daily report window spans the full calendar day in UTC."""
    window = get_report_period_window(
        {
            "period_day": "2024-06-14",
            "period_type": "daily",
            "period_timezone": "UTC",
        }
    )
    assert window["start"] == pendulum.datetime(2024, 6, 14, 0, 0, 0, tz="UTC")
    assert window["end"] == pendulum.datetime(2024, 6, 14, tz="UTC").end_of("day")


def test_get_report_period_window_weekly_friday():
    """Weekly report window spans 7 days from period_day (Friday through Thursday)."""
    window = get_report_period_window(
        {
            "period_day": "2026-05-22",
            "period_type": "weekly",
            "period_timezone": "UTC",
        }
    )
    assert window["start"] == pendulum.datetime(2026, 5, 22, 0, 0, 0, tz="UTC")
    assert window["end"] == pendulum.datetime(2026, 5, 28, tz="UTC").end_of("day")


def test_get_report_period_window_timezone():
    """Report window boundaries use the automation timezone."""
    window = get_report_period_window(
        {
            "period_day": "2024-06-14",
            "period_type": "daily",
            "period_timezone": "America/New_York",
        }
    )
    assert window["start"] == pendulum.datetime(
        2024, 6, 14, 0, 0, 0, tz="America/New_York"
    )
    assert window["end"] == pendulum.datetime(
        2024, 6, 14, tz="America/New_York"
    ).end_of("day")


def test_filter_changes_for_automation_no_conditions():
    """All changes pass when conditions tree is empty (returns False, so none pass)."""
    automation = {
        "trigger_type": "alert",
        "automation_conf": {"conditions": {}, "triggers": []},
    }
    changes = ["change-1"]
    changes_details = {
        "change-1": {"cve_id": "CVE-2024-0001", "cve_metrics": {}},
    }
    result = filter_changes_for_automation(automation, changes, changes_details, {})
    assert result == []


def test_filter_changes_for_automation_with_condition():
    """Changes matching the condition tree are kept."""
    automation = {
        "trigger_type": "alert",
        "automation_conf": {
            "conditions": {"type": "cvss_gte", "value": 7.0},
            "triggers": [],
        },
    }
    changes = ["change-1", "change-2"]
    changes_details = {
        "change-1": {
            "cve_id": "CVE-2024-0001",
            "cve_metrics": {"cvssV3_1": {"data": {"score": 8.8}}},
        },
        "change-2": {
            "cve_id": "CVE-2024-0002",
            "cve_metrics": {"cvssV3_1": {"data": {"score": 3.0}}},
        },
    }
    result = filter_changes_for_automation(automation, changes, changes_details, {})
    assert result == ["change-1"]


def test_filter_changes_for_automation_with_trigger():
    """Alert automations also evaluate triggers."""
    automation = {
        "trigger_type": "alert",
        "project_subscriptions": ["vendor1"],
        "automation_conf": {
            "conditions": {"type": "cvss_gte", "value": 0},
            "triggers": ["new_vendor"],
        },
    }
    changes = ["change-1", "change-2"]
    changes_details = {
        "change-1": {
            "cve_id": "CVE-2024-0001",
            "cve_metrics": {"cvssV3_1": {"data": {"score": 5.0}}},
            "change_payload": {"vendors": {"added": ["new_vendor"]}},
        },
        "change-2": {
            "cve_id": "CVE-2024-0002",
            "cve_metrics": {"cvssV3_1": {"data": {"score": 5.0}}},
            "change_payload": {"vendors": {"added": []}},
        },
    }
    result = filter_changes_for_automation(automation, changes, changes_details, {})
    assert result == ["change-1"]


def test_filter_changes_report_skips_triggers():
    """Report automations skip trigger evaluation."""
    automation = {
        "trigger_type": "report",
        "automation_conf": {
            "conditions": {"type": "cvss_gte", "value": 0},
            "triggers": ["new_vendor"],
        },
    }
    changes = ["change-1"]
    changes_details = {
        "change-1": {
            "cve_id": "CVE-2024-0001",
            "cve_metrics": {"cvssV3_1": {"data": {"score": 5.0}}},
        },
    }
    result = filter_changes_for_automation(automation, changes, changes_details, {})
    assert result == ["change-1"]


def test_chunk_actions(override_conf):
    """Actions list is divided into chunks based on max_automations_map_length."""
    override_conf("opencve", "max_automations_map_length", "2")
    actions = [{"a": 1}, {"a": 2}, {"a": 3}]
    result = chunk_actions(actions)
    assert len(result) == 2
    assert result[0] == [{"a": 1}, {"a": 2}]
    assert result[1] == [{"a": 3}]
