from includes.tasks.automations.triggers import evaluate_triggers


AUTOMATION = {"project_subscriptions": ["vendor1", "vendor1$PRODUCT$prod1"]}


def test_evaluate_triggers_empty_returns_true():
    """Empty trigger list means all changes pass."""
    assert evaluate_triggers([], {}, AUTOMATION) is True


def test_evaluate_triggers_unknown_trigger():
    """Unknown trigger names are skipped; no match returns False."""
    assert evaluate_triggers(["nonexistent_trigger"], {}, AUTOMATION) is False


def test_cve_enters_project_trigger_match():
    """Trigger fires when a subscribed vendor appears for the first time."""
    change = {"change_payload": {"first_time": ["vendor1"]}}
    assert evaluate_triggers(["cve_enters_project"], change, AUTOMATION) is True


def test_cve_enters_project_trigger_no_match():
    """Trigger does not fire when first_time vendors don't overlap subscriptions."""
    change = {"change_payload": {"first_time": ["other_vendor"]}}
    assert evaluate_triggers(["cve_enters_project"], change, AUTOMATION) is False


def test_cve_enters_project_trigger_no_payload():
    """Trigger does not fire when change_payload is missing."""
    assert evaluate_triggers(["cve_enters_project"], {}, AUTOMATION) is False


def test_cvss_increased_trigger_match():
    """Trigger fires when any CVSS score increases."""
    change = {
        "change_payload": {
            "metrics": {
                "updated": {
                    "cvssV3_1": {
                        "old": {"score": 5.0},
                        "new": {"score": 8.0},
                    }
                }
            }
        }
    }
    assert evaluate_triggers(["cvss_increased"], change, AUTOMATION) is True


def test_cvss_increased_trigger_no_change():
    """Trigger does not fire when CVSS score stays the same."""
    change = {
        "change_payload": {
            "metrics": {
                "updated": {
                    "cvssV3_1": {
                        "old": {"score": 8.0},
                        "new": {"score": 8.0},
                    }
                }
            }
        }
    }
    assert evaluate_triggers(["cvss_increased"], change, AUTOMATION) is False


def test_cvss_decreased_trigger_match():
    """Trigger fires when any CVSS score decreases."""
    change = {
        "change_payload": {
            "metrics": {
                "updated": {
                    "cvssV3_1": {
                        "old": {"score": 9.0},
                        "new": {"score": 5.0},
                    }
                }
            }
        }
    }
    assert evaluate_triggers(["cvss_decreased"], change, AUTOMATION) is True


def test_cvss_decreased_trigger_no_decrease():
    """Trigger does not fire when CVSS score increases."""
    change = {
        "change_payload": {
            "metrics": {
                "updated": {
                    "cvssV3_1": {
                        "old": {"score": 5.0},
                        "new": {"score": 9.0},
                    }
                }
            }
        }
    }
    assert evaluate_triggers(["cvss_decreased"], change, AUTOMATION) is False


def test_epss_increased_trigger():
    """Trigger fires when EPSS score goes up."""
    change = {
        "change_payload": {
            "metrics": {
                "updated": {"epss": {"old": {"score": 0.01}, "new": {"score": 0.5}}}
            }
        }
    }
    assert evaluate_triggers(["epss_increased"], change, AUTOMATION) is True


def test_epss_decreased_trigger():
    """Trigger fires when EPSS score goes down."""
    change = {
        "change_payload": {
            "metrics": {
                "updated": {"epss": {"old": {"score": 0.5}, "new": {"score": 0.01}}}
            }
        }
    }
    assert evaluate_triggers(["epss_decreased"], change, AUTOMATION) is True


def test_epss_trigger_no_change():
    """Neither EPSS trigger fires when there is no updated metrics."""
    change = {"change_payload": {"metrics": {}}}
    assert evaluate_triggers(["epss_increased"], change, AUTOMATION) is False
    assert evaluate_triggers(["epss_decreased"], change, AUTOMATION) is False


def test_kev_added_trigger_match():
    """Trigger fires when KEV data is added."""
    change = {
        "change_payload": {"metrics": {"added": {"kev": {"dateAdded": "2024-01-01"}}}}
    }
    assert evaluate_triggers(["kev_added"], change, AUTOMATION) is True


def test_kev_added_trigger_no_kev():
    """Trigger does not fire when added section has no KEV."""
    change = {"change_payload": {"metrics": {"added": {}}}}
    assert evaluate_triggers(["kev_added"], change, AUTOMATION) is False


def test_new_vendor_trigger():
    """Trigger fires when new vendors are added."""
    change = {"change_payload": {"vendors": {"added": ["new_vendor"]}}}
    assert evaluate_triggers(["new_vendor"], change, AUTOMATION) is True


def test_new_vendor_trigger_no_added():
    """Trigger does not fire when no vendors are added."""
    change = {"change_payload": {"vendors": {"added": []}}}
    assert evaluate_triggers(["new_vendor"], change, AUTOMATION) is False


def test_new_product_trigger():
    """Trigger fires when new CPEs (products) are added."""
    change = {"change_payload": {"cpes": {"added": ["new_product"]}}}
    assert evaluate_triggers(["new_product"], change, AUTOMATION) is True


def test_new_reference_trigger():
    """Trigger fires when new references are added."""
    change = {"change_payload": {"references": {"added": ["https://example.com"]}}}
    assert evaluate_triggers(["new_reference"], change, AUTOMATION) is True


def test_new_weakness_trigger():
    """Trigger fires when new weaknesses are added."""
    change = {"change_payload": {"weaknesses": {"added": ["CWE-79"]}}}
    assert evaluate_triggers(["new_weakness"], change, AUTOMATION) is True


def test_description_changed_trigger():
    """Trigger fires when description changes."""
    change = {"change_payload": {"description": {"old": "Old desc", "new": "New desc"}}}
    assert evaluate_triggers(["description_changed"], change, AUTOMATION) is True


def test_description_changed_trigger_same():
    """Trigger does not fire when old and new description are identical."""
    change = {"change_payload": {"description": {"old": "Same", "new": "Same"}}}
    assert evaluate_triggers(["description_changed"], change, AUTOMATION) is False


def test_title_changed_trigger():
    """Trigger fires when title changes."""
    change = {"change_payload": {"title": {"old": "Old title", "new": "New title"}}}
    assert evaluate_triggers(["title_changed"], change, AUTOMATION) is True


def test_title_changed_trigger_no_payload():
    """Trigger does not fire when there is no title payload."""
    change = {"change_payload": {}}
    assert evaluate_triggers(["title_changed"], change, AUTOMATION) is False


def test_multiple_triggers_any_match():
    """When multiple triggers are specified, any one match is sufficient."""
    change = {"change_payload": {"vendors": {"added": ["new_vendor"]}}}
    result = evaluate_triggers(["cvss_increased", "new_vendor"], change, AUTOMATION)
    assert result is True
