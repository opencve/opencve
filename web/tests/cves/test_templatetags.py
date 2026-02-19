from cves.templatetags.opencve_extras import (
    get_item,
    get_active_cvss_tab,
    advisory_source_display,
    tracker_status_badge_class,
    enrichment_scores_tooltip,
)


def test_get_item():
    class Item:
        """Mock the regroup tag result."""

        def __init__(self, grouper, list):
            self.grouper = grouper
            self.list = list

    item1 = Item(grouper="foo", list=["a", "b"])
    item2 = Item(grouper="bar", list=["c", "d"])

    assert get_item([item1, item2], "foo") == ["a", "b"]
    assert get_item([item1, item2], "bar") == ["c", "d"]


import pytest
from cves.templatetags.opencve_extras import needs_quotes


@pytest.mark.parametrize(
    "value, expected",
    [
        # Normal values that should not need quotes
        ("normaltext", False),
        ("normal-text", False),
        ("normal_text", False),
        ("normaltext123", False),
        ("", False),
        # Values with special characters that need quotes
        ("text:colon", True),
        ("text'quote", True),
        ('text"doublequote', True),
        ("text(parentheses)", True),
        ("text[brackets]", True),
        ("text{braces}", True),
        ("text&ampersand", True),
        ("text|pipe", True),
        ("text=equals", True),
        ("text!bang", True),
        ("text\\backslash", True),
        ("text<less>", True),
        ("text>greater", True),
        ("text+plus", True),
        ("text*star", True),
        ("text?question", True),
        ("text^caret", True),
        ("text~tilde", True),
        # Values with spaces
        ("text with space", True),
        ("multiple words here", True),
        (" leadingspace", True),
        ("trailingspace ", True),
        # Edge cases
        (":", True),
        ("'", True),
        ('"', True),
        (" ", True),
        ("\\", True),
    ],
)
def test_needs_quotes(value, expected):
    """
    Test needs_quotes function to ensure it correctly identifies values
    that need to be quoted due to special characters or spaces.
    """
    assert needs_quotes(value) == expected


def test_get_active_cvss_tab():
    """
    Test get_active_cvss_tab function to ensure it returns the correct
    active tab based on CVSS score availability priority.
    """

    class MockCVE:
        def __init__(self, cvssV4_0=None, cvssV3_1=None, cvssV3_0=None, cvssV2_0=None):
            self.cvssV4_0 = cvssV4_0
            self.cvssV3_1 = cvssV3_1
            self.cvssV3_0 = cvssV3_0
            self.cvssV2_0 = cvssV2_0

    # CVSS v4.0 has highest priority
    cve_with_all = MockCVE(cvssV4_0="10", cvssV3_1="10", cvssV3_0="10", cvssV2_0="10")
    assert get_active_cvss_tab(cve_with_all) == "cvss40"

    # Choose v3.1 when v4.0 is not available
    cve_with_v31_and_below = MockCVE(
        cvssV4_0=None, cvssV3_1="10", cvssV3_0="10", cvssV2_0="10"
    )
    assert get_active_cvss_tab(cve_with_v31_and_below) == "cvss31"

    # Choose v3.0 when v4.0 and v3.1 are not available
    cve_with_v30_and_below = MockCVE(
        cvssV4_0=None, cvssV3_1=None, cvssV3_0="10", cvssV2_0="10"
    )
    assert get_active_cvss_tab(cve_with_v30_and_below) == "cvss30"

    # Choose v2.0 when only v2.0 is available
    cve_with_only_v2 = MockCVE(
        cvssV4_0=None, cvssV3_1=None, cvssV3_0=None, cvssV2_0="10"
    )
    assert get_active_cvss_tab(cve_with_only_v2) == "cvss2"

    # Fallback to v4.0 when no CVSS scores are available
    cve_with_no_scores = MockCVE(
        cvssV4_0=None, cvssV3_1=None, cvssV3_0=None, cvssV2_0=None
    )
    assert get_active_cvss_tab(cve_with_no_scores) == "cvss40"

    # Treat empty strings as None/falsy
    cve_with_empty_strings = MockCVE(cvssV4_0="", cvssV3_1="", cvssV3_0="", cvssV2_0="")
    assert get_active_cvss_tab(cve_with_empty_strings) == "cvss40"

    # Mixed scenarios
    cve_mixed_1 = MockCVE(cvssV4_0=None, cvssV3_1=None, cvssV3_0="10", cvssV2_0=None)
    assert get_active_cvss_tab(cve_mixed_1) == "cvss30"

    cve_mixed_2 = MockCVE(cvssV4_0="10", cvssV3_1=None, cvssV3_0=None, cvssV2_0="10")
    assert get_active_cvss_tab(cve_mixed_2) == "cvss40"


def test_advisory_source_display():
    """
    Test advisory_source_display function to ensure it correctly formats
    advisory sources with icons and proper display text.
    """
    # Test known sources
    euvd_result = advisory_source_display("euvd")
    assert "img/sources/euvd.png" in euvd_result
    assert "EUVD" in euvd_result
    assert 'alt="EUVD"' in euvd_result

    usn_result = advisory_source_display("usn")
    assert "img/sources/usn.png" in usn_result
    assert "Ubuntu USN" in usn_result
    assert 'alt="Ubuntu USN"' in usn_result

    dsa_result = advisory_source_display("dsa")
    assert "img/sources/dsa.png" in dsa_result
    assert "Debian DSA" in dsa_result
    assert 'alt="Debian DSA"' in dsa_result

    dla_result = advisory_source_display("dla")
    assert "img/sources/dla.png" in dla_result
    assert "Debian DLA" in dla_result
    assert 'alt="Debian DLA"' in dla_result

    ghsa_result = advisory_source_display("ghsa")
    assert "img/sources/ghsa.png" in ghsa_result
    assert "Github GHSA" in ghsa_result
    assert 'alt="Github GHSA"' in ghsa_result

    # Test case insensitive
    upper_case_result = advisory_source_display("EUVD")
    assert "img/sources/euvd.png" in upper_case_result
    assert "EUVD" in upper_case_result

    mixed_case_result = advisory_source_display("GhSa")
    assert "img/sources/ghsa.png" in mixed_case_result
    assert "Github GHSA" in mixed_case_result

    # Test HTML structure
    result = advisory_source_display("euvd")
    assert "<img src=" in result
    assert 'style="width: 22px; margin-right: 4px; vertical-align: middle;"' in result
    assert result.count("<img") == 1  # Only one image tag


def test_enrichment_scores_tooltip():
    """Test enrichment_scores_tooltip formats scores for tooltip display."""
    assert enrichment_scores_tooltip([]) == ""
    assert enrichment_scores_tooltip(None) == ""
    scores = [
        {"source": "inferred", "score": 95.0},
        {"source": "matching", "score": 100.0},
    ]
    assert enrichment_scores_tooltip(scores) == "Inferred: 95.0%<br />Matching: 100.0%"


@pytest.mark.parametrize(
    "status, expected",
    [
        (None, "badge-secondary"),
        ("", "badge-secondary"),
        (0, "badge-secondary"),
        (False, "badge-secondary"),
        ("to_evaluate", "badge-secondary"),
        ("pending_review", "badge-secondary"),
        ("analysis_in_progress", "badge-info"),
        ("remediation_in_progress", "badge-info"),
        ("evaluated", "badge-success"),
        ("resolved", "badge-success"),
        ("not_applicable", "badge-warning"),
        ("risk_accepted", "badge-warning"),
        ("unknown_status", "badge-secondary"),
        ("invalid", "badge-secondary"),
    ],
)
def test_tracker_status_badge_class(status, expected):
    """
    Test tracker_status_badge_class function.
    """
    assert tracker_status_badge_class(status) == expected
