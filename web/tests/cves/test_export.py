"""Tests for cves.export module."""

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from django.http import StreamingHttpResponse

from cves.export import (
    _format_cvss_score,
    _format_datetime_iso_seconds,
    _format_description,
    _format_epss,
    _format_vendors_for_csv,
    _format_weaknesses_for_csv,
    _row_from_cve,
    build_cve_csv_response,
    stream_cve_queryset_to_csv,
)
from cves.models import Cve


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, ""),
        (datetime(2026, 1, 25, 14, 36, 24, 455000), "2026-01-25T14:36:24Z"),
        (
            datetime(2026, 1, 25, 14, 36, 24, 455000, tzinfo=timezone.utc),
            "2026-01-25T14:36:24Z",
        ),
        ("foo", "foo"),
    ],
    ids=["none", "naive_datetime", "aware_utc", "non_datetime"],
)
def test_format_datetime_iso_seconds(value, expected):
    assert _format_datetime_iso_seconds(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", ""),
        (None, ""),
        ("Single line", "Single line"),
        ("Line one\nLine two", "Line one Line two"),
        ("A\n\nB", "A B"),
    ],
    ids=["empty_string", "none", "one_line", "newlines", "double_newline"],
)
def test_format_description(value, expected):
    assert _format_description(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ([], ""),
        (None, ""),
        (["linux"], "linux"),
        (
            ["github", "github$PRODUCT$copilot", "github$PRODUCT$actions"],
            "github (copilot, actions)",
        ),
        (
            [
                "github",
                "github$PRODUCT$copilot",
                "microsoft",
                "microsoft$PRODUCT$visual_studio_code",
            ],
            "github (copilot), microsoft (visual_studio_code)",
        ),
    ],
    ids=[
        "empty_list",
        "none",
        "single_vendor_no_products",
        "vendor_with_products",
        "multiple_vendors_comma_separated",
    ],
)
def test_format_vendors_for_csv(value, expected):
    assert _format_vendors_for_csv(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ([], ""),
        (None, ""),
        (["CWE-787"], "CWE-787"),
        (["CWE-787", "CWE-89"], "CWE-787, CWE-89"),
    ],
    ids=["empty_list", "none", "single", "multiple"],
)
def test_format_weaknesses_for_csv(value, expected):
    assert _format_weaknesses_for_csv(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, ""),
        ({}, ""),
        ({"data": None}, ""),
        ({"data": {}}, ""),
        ({"data": {"score": 0.00021}}, "0.00021"),
        ({"data": {"score": 0.5}}, "0.5"),
    ],
    ids=[
        "none",
        "empty_dict",
        "data_none",
        "data_empty",
        "score_decimal",
        "score_half",
    ],
)
def test_format_epss(value, expected):
    assert _format_epss(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, ""),
        ("", ""),
        (7.4, "7.4"),
        (5.0, "5.0"),
        (5, "5.0"),
        ("n/a", ""),
        ("foo", ""),
    ],
    ids=[
        "none",
        "empty_string",
        "float",
        "float_int",
        "integer",
        "invalid_na",
        "invalid_foo",
    ],
)
def test_format_cvss_score(value, expected):
    assert _format_cvss_score(value) == expected


def test_row_from_cve_mock():
    """_row_from_cve builds a list matching DEFAULT_CVE_CSV_HEADERS order."""
    cve = Mock()
    cve.cve_id = "CVE-2025-1234"
    cve.title = "A title"
    cve.description = "Line one\nLine two"
    cve.vendors = ["intel", "intel$PRODUCT$proset"]
    cve.weaknesses = ["CWE-787"]
    cve.created_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    cve.updated_at = datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    cve.kev = {"data": {"dateAdded": "2025-01-01"}}
    cve.epss = {"data": {"score": 0.00021}}
    cve.cvssV4_0 = {"score": 8.3}
    cve.cvssV3_1 = {"score": 7.4}
    cve.cvssV3_0 = {}
    cve.cvssV2_0 = None

    row = _row_from_cve(cve)
    assert sorted(row) == sorted(
        [
            "CVE-2025-1234",
            "A title",
            "Line one Line two",
            "intel (proset)",
            "CWE-787",
            "2025-01-01T12:00:00Z",
            "2025-01-02T12:00:00Z",
            "true",
            "0.00021",
            "8.3",
            "7.4",
            "",
            "",
        ]
    )


@pytest.mark.django_db
def test_stream_cve_queryset_to_csv_empty_queryset():
    """An empty queryset yields only the CSV header line."""
    qs = Cve.objects.filter(cve_id="nonexistent")
    chunks = list(stream_cve_queryset_to_csv(qs))
    assert len(chunks) == 1  # header only
    content = "".join(chunks)
    assert content.strip().startswith("cve_id,")
    lines = content.strip().split("\r\n")
    assert len(lines) == 1


@pytest.mark.django_db
def test_stream_cve_queryset_to_csv_with_cves(create_cve):
    """A queryset with CVEs yields a CSV with header and one row per CVE."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2023-22490")
    qs = Cve.objects.filter(cve_id__in=["CVE-2021-44228", "CVE-2023-22490"]).order_by(
        "cve_id"
    )
    chunks = list(stream_cve_queryset_to_csv(qs))
    content = "".join(chunks)
    lines = content.strip().split("\r\n")
    assert lines[0].startswith("cve_id,title,description,")
    assert len(lines) == 3  # header + 2 rows
    assert "CVE-2021-44228" in content
    assert "CVE-2023-22490" in content


@pytest.mark.django_db
def test_build_cve_csv_response_type_and_headers(create_cve):
    """Response is a StreamingHttpResponse with CSV Content-Type."""
    create_cve("CVE-2021-44228")
    qs = Cve.objects.filter(cve_id="CVE-2021-44228")
    response = build_cve_csv_response(qs, "test-export")
    assert isinstance(response, StreamingHttpResponse)
    assert "text/csv" in response["Content-Type"]
    assert "attachment" in response["Content-Disposition"]
    assert "test-export.csv" in response["Content-Disposition"]


@pytest.mark.django_db
def test_build_cve_csv_response_adds_csv_extension():
    """If the filename has no extension, .csv is added automatically."""
    qs = Cve.objects.none()
    response = build_cve_csv_response(qs, "myfile")
    assert "myfile.csv" in response["Content-Disposition"]


@pytest.mark.django_db
def test_build_cve_csv_response_keeps_csv_extension():
    """If the filename already ends with .csv, the extension is preserved."""
    qs = Cve.objects.none()
    response = build_cve_csv_response(qs, "already.csv")
    assert "already.csv" in response["Content-Disposition"]
