from includes.tasks.automations.conditions import (
    evaluate_condition_tree,
    evaluate_condition_node,
)


def test_evaluate_condition_tree_empty_returns_false():
    """Empty condition tree evaluates to False."""
    assert evaluate_condition_tree({}, {}, {}) is False
    assert evaluate_condition_tree(None, {}, {}) is False


def test_evaluate_condition_tree_single_node():
    """Single condition node is evaluated directly."""
    change = {"cve_metrics": {"cvssV3_1": {"data": {"score": 9.0}}}}
    tree = {"type": "cvss_gte", "value": 7.0}
    assert evaluate_condition_tree(tree, change, {}) is True


def test_evaluate_condition_tree_or_logic():
    """OR operator passes if any child matches."""
    change = {"cve_metrics": {"cvssV3_1": {"data": {"score": 5.0}}}}
    tree = {
        "operator": "OR",
        "children": [
            {"type": "cvss_gte", "value": 9.0},
            {"type": "cvss_gte", "value": 4.0},
        ],
    }
    assert evaluate_condition_tree(tree, change, {}) is True


def test_evaluate_condition_tree_or_none_match():
    """OR operator fails if no child matches."""
    change = {"cve_metrics": {"cvssV3_1": {"data": {"score": 3.0}}}}
    tree = {
        "operator": "OR",
        "children": [
            {"type": "cvss_gte", "value": 7.0},
            {"type": "cvss_gte", "value": 9.0},
        ],
    }
    assert evaluate_condition_tree(tree, change, {}) is False


def test_evaluate_condition_tree_and_logic():
    """AND operator requires all children to match."""
    change = {
        "cve_metrics": {
            "cvssV3_1": {"data": {"score": 9.5}},
            "epss": {"data": {"score": 0.8}},
        }
    }
    tree = {
        "operator": "AND",
        "children": [
            {"type": "cvss_gte", "value": 7.0},
            {"type": "epss_gte", "value": 0.5},
        ],
    }
    assert evaluate_condition_tree(tree, change, {}) is True


def test_evaluate_condition_tree_and_one_fails():
    """AND operator fails if any child does not match."""
    change = {
        "cve_metrics": {
            "cvssV3_1": {"data": {"score": 9.5}},
            "epss": {"data": {"score": 0.1}},
        }
    }
    tree = {
        "operator": "AND",
        "children": [
            {"type": "cvss_gte", "value": 7.0},
            {"type": "epss_gte", "value": 0.5},
        ],
    }
    assert evaluate_condition_tree(tree, change, {}) is False


def test_evaluate_condition_tree_nested():
    """Nested tree: AND with an OR child."""
    change = {
        "cve_metrics": {"cvssV3_1": {"data": {"score": 8.0}}},
        "cve_vendors": ["vendor_a"],
    }
    tree = {
        "operator": "AND",
        "children": [
            {"type": "cvss_gte", "value": 7.0},
            {
                "operator": "OR",
                "children": [
                    {"type": "vendor_equals", "value": "vendor_a"},
                    {"type": "vendor_equals", "value": "vendor_b"},
                ],
            },
        ],
    }
    assert evaluate_condition_tree(tree, change, {}) is True


def test_evaluate_condition_tree_or_empty_children():
    """OR with no children returns False."""
    tree = {"operator": "OR", "children": []}
    assert evaluate_condition_tree(tree, {}, {}) is False


def test_cvss_gte_condition_above():
    """CVSS GTE passes when score is above threshold."""
    change = {"cve_metrics": {"cvssV3_1": {"data": {"score": 8.8}}}}
    node = {"type": "cvss_gte", "value": 7.0}
    assert evaluate_condition_node(node, change, {}) is True


def test_cvss_gte_condition_below():
    """CVSS GTE fails when score is below threshold."""
    change = {"cve_metrics": {"cvssV3_1": {"data": {"score": 3.0}}}}
    node = {"type": "cvss_gte", "value": 7.0}
    assert evaluate_condition_node(node, change, {}) is False


def test_cvss_gte_condition_equal():
    """CVSS GTE passes when score equals threshold."""
    change = {"cve_metrics": {"cvssV3_1": {"data": {"score": 7.0}}}}
    node = {"type": "cvss_gte", "value": 7.0}
    assert evaluate_condition_node(node, change, {}) is True


def test_cvss_gte_condition_with_version():
    """CVSS GTE with explicit version uses the right metric."""
    change = {
        "cve_metrics": {
            "cvssV3_1": {"data": {"score": 3.0}},
            "cvssV4_0": {"data": {"score": 9.0}},
        }
    }
    node = {"type": "cvss_gte", "value": {"version": "v4.0", "value": 7.0}}
    assert evaluate_condition_node(node, change, {}) is True


def test_cvss_gte_condition_no_score():
    """CVSS GTE fails when there is no score data."""
    change = {"cve_metrics": {}}
    node = {"type": "cvss_gte", "value": 7.0}
    assert evaluate_condition_node(node, change, {}) is False


def test_epss_gte_condition_above():
    """EPSS GTE passes when score is above threshold."""
    change = {"cve_metrics": {"epss": {"data": {"score": 0.8}}}}
    node = {"type": "epss_gte", "value": 0.5}
    assert evaluate_condition_node(node, change, {}) is True


def test_epss_gte_condition_below():
    """EPSS GTE fails when score is below threshold."""
    change = {"cve_metrics": {"epss": {"data": {"score": 0.1}}}}
    node = {"type": "epss_gte", "value": 0.5}
    assert evaluate_condition_node(node, change, {}) is False


def test_kev_present_condition_true():
    """KEV present passes when kev data is populated."""
    change = {"cve_metrics": {"kev": {"data": {"dateAdded": "2024-01-01"}}}}
    node = {"type": "kev_present", "value": True}
    assert evaluate_condition_node(node, change, {}) is True


def test_kev_present_condition_false():
    """KEV present fails when kev data is empty."""
    change = {"cve_metrics": {"kev": {"data": {}}}}
    node = {"type": "kev_present", "value": True}
    assert evaluate_condition_node(node, change, {}) is False


def test_vendor_equals_condition_match():
    """Vendor equals matches a plain vendor name."""
    change = {"cve_vendors": ["foo", "foo$PRODUCT$bar"]}
    node = {"type": "vendor_equals", "value": "foo"}
    assert evaluate_condition_node(node, change, {}) is True


def test_vendor_equals_condition_no_match():
    """Vendor equals does not match when vendor is absent."""
    change = {"cve_vendors": ["other_vendor"]}
    node = {"type": "vendor_equals", "value": "foo"}
    assert evaluate_condition_node(node, change, {}) is False


def test_vendor_equals_condition_case_insensitive():
    """Vendor equals is case insensitive."""
    change = {"cve_vendors": ["FooVendor"]}
    node = {"type": "vendor_equals", "value": "foovendor"}
    assert evaluate_condition_node(node, change, {}) is True


def test_product_equals_condition_match():
    """Product equals matches the product part after $PRODUCT$."""
    change = {"cve_vendors": ["foo$PRODUCT$bar"]}
    node = {"type": "product_equals", "value": "bar"}
    assert evaluate_condition_node(node, change, {}) is True


def test_product_equals_condition_no_match():
    """Product equals fails when product is not present."""
    change = {"cve_vendors": ["foo$PRODUCT$baz"]}
    node = {"type": "product_equals", "value": "bar"}
    assert evaluate_condition_node(node, change, {}) is False


def test_cve_status_condition_match():
    """CVE status matches when tracker has the expected status."""
    change = {"cve_id": "CVE-2024-0001"}
    trackers = {"CVE-2024-0001": {"status": "in_triage", "assignee_id": None}}
    node = {"type": "cve_status", "value": "in_triage"}
    assert evaluate_condition_node(node, change, trackers) is True


def test_cve_status_condition_no_match():
    """CVE status fails when tracker has a different status."""
    change = {"cve_id": "CVE-2024-0001"}
    trackers = {"CVE-2024-0001": {"status": "resolved", "assignee_id": None}}
    node = {"type": "cve_status", "value": "in_triage"}
    assert evaluate_condition_node(node, change, trackers) is False


def test_cve_status_condition_no_tracker():
    """CVE status fails when there is no tracker for the CVE."""
    change = {"cve_id": "CVE-2024-0001"}
    node = {"type": "cve_status", "value": "in_triage"}
    assert evaluate_condition_node(node, change, {}) is False


def test_cve_unassigned_condition_true():
    """CVE unassigned passes when there is no tracker."""
    change = {"cve_id": "CVE-2024-0001"}
    node = {"type": "cve_unassigned", "value": True}
    assert evaluate_condition_node(node, change, {}) is True


def test_cve_unassigned_condition_assigned():
    """CVE unassigned fails when there is an assignee."""
    change = {"cve_id": "CVE-2024-0001"}
    trackers = {"CVE-2024-0001": {"status": "open", "assignee_id": "user-1"}}
    node = {"type": "cve_unassigned", "value": True}
    assert evaluate_condition_node(node, change, trackers) is False


def test_cve_unassigned_condition_no_assignee():
    """CVE unassigned passes when tracker exists but has no assignee."""
    change = {"cve_id": "CVE-2024-0001"}
    trackers = {"CVE-2024-0001": {"status": "open", "assignee_id": None}}
    node = {"type": "cve_unassigned", "value": True}
    assert evaluate_condition_node(node, change, trackers) is True


def test_cve_newer_than_condition_current_year():
    """CVE newer_than always passes for CVEs from the current year."""
    from datetime import datetime, timezone

    current_year = datetime.now(tz=timezone.utc).year
    change = {"cve_id": f"CVE-{current_year}-0001"}
    node = {"type": "cve_newer_than", "value": "30"}
    assert evaluate_condition_node(node, change, {}) is True


def test_cve_newer_than_condition_old_cve():
    """CVE newer_than fails for old CVEs with short threshold."""
    change = {"cve_id": "CVE-2020-0001"}
    node = {"type": "cve_newer_than", "value": "30"}
    assert evaluate_condition_node(node, change, {}) is False


def test_change_type_condition_description_changed():
    """Change type condition fires when change_types includes the expected type."""
    change = {"change_types": ["description", "metrics"]}
    node = {"type": "description_changed", "value": None}
    assert evaluate_condition_node(node, change, {}) is True


def test_change_type_condition_no_match():
    """Change type condition fails when change_types don't include the expected type."""
    change = {"change_types": ["metrics"]}
    node = {"type": "description_changed", "value": None}
    assert evaluate_condition_node(node, change, {}) is False


def test_change_type_condition_cve_enters_project():
    """cve_enters_project change type condition fires on 'created'."""
    change = {"change_types": ["created"]}
    node = {"type": "cve_enters_project", "value": None}
    assert evaluate_condition_node(node, change, {}) is True


def test_unknown_condition_returns_false():
    """Unknown condition type returns False."""
    node = {"type": "nonexistent_condition", "value": None}
    assert evaluate_condition_node(node, {}, {}) is False
