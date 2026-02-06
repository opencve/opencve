import csv
from io import StringIO
from datetime import datetime, timezone

from django.http import StreamingHttpResponse

from cves.utils import list_to_dict_vendors


CVE_CSV_EXPORT_MAX_ROWS = 10000

# Column headers: snake_case, no spaces (enterprise-ready)
DEFAULT_CVE_CSV_HEADERS = [
    "cve_id",
    "title",
    "description",
    "vendors",
    "weaknesses",
    "created_at",
    "updated_at",
    "kev",
    "epss",
    "cvss_v4_0",
    "cvss_v3_1",
    "cvss_v3_0",
    "cvss_v2_0",
]


def _format_datetime_iso_seconds(value):
    """Format datetime for CSV: truncated to second, UTC, e.g. 2026-01-25T14:36:24Z."""
    if value is None:
        return ""
    if not isinstance(value, datetime):
        return str(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_description(description):
    """One-line description for CSV (newlines replaced by space)."""
    if not description:
        return ""
    return " ".join(description.split())


def _format_vendors_for_csv(vendors):
    """Format vendors as 'vendor (p1, p2), vendor2 (p3)' (comma between vendor groups)."""
    if not vendors:
        return ""
    d = list_to_dict_vendors(vendors)
    parts = []
    for vendor, products in sorted(d.items()):
        if products:
            parts.append(f"{vendor} ({', '.join(products)})")
        else:
            parts.append(vendor)
    return ", ".join(parts)


def _format_weaknesses_for_csv(weaknesses):
    """Format weaknesses list as comma-separated CWE ids."""
    if not weaknesses:
        return ""
    return ", ".join(weaknesses)


def _format_epss(epss_metric):
    """EPSS score as decimal string, or empty if not present."""
    if not epss_metric or not epss_metric.get("data"):
        return ""
    score = epss_metric["data"].get("score")
    if score is None:
        return ""
    return str(score)


def _format_cvss_score(score):
    """CVSS score as float string (e.g. 5.0, 7.4), or empty."""
    if score is None or score == "":
        return ""
    try:
        f = float(score)
        return f"{f:.1f}"
    except (TypeError, ValueError):
        return ""


def _row_from_cve(cve):
    """Build a list of CSV cell values from a Cve instance."""
    cvss_v4 = cve.cvssV4_0.get("score") if cve.cvssV4_0 else None
    cvss_v31 = cve.cvssV3_1.get("score") if cve.cvssV3_1 else None
    cvss_v30 = cve.cvssV3_0.get("score") if cve.cvssV3_0 else None
    cvss_v20 = cve.cvssV2_0.get("score") if cve.cvssV2_0 else None
    kev = "true" if (cve.kev and cve.kev.get("data")) else "false"
    return [
        cve.cve_id,
        cve.title or "",
        _format_description(cve.description),
        _format_vendors_for_csv(cve.vendors),
        _format_weaknesses_for_csv(cve.weaknesses),
        _format_datetime_iso_seconds(cve.created_at),
        _format_datetime_iso_seconds(cve.updated_at),
        kev,
        _format_epss(cve.epss),
        _format_cvss_score(cvss_v4),
        _format_cvss_score(cvss_v31),
        _format_cvss_score(cvss_v30),
        _format_cvss_score(cvss_v20),
    ]


def stream_cve_queryset_to_csv(queryset, headers=None):
    """
    Generator that yields CSV chunks for the given CVE queryset.
    Yields header row then data rows.
    """
    if headers is None:
        headers = DEFAULT_CVE_CSV_HEADERS
    buffer = StringIO()
    writer = csv.writer(buffer)

    # Header row
    writer.writerow(headers)
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)

    for cve in queryset.iterator(chunk_size=2000):
        writer.writerow(_row_from_cve(cve))
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


def build_cve_csv_response(queryset, filename, headers=None):
    """
    Build a StreamingHttpResponse that streams the given CVE queryset as CSV.
    """
    if headers is None:
        headers = DEFAULT_CVE_CSV_HEADERS

    # Ensure .csv extension
    if not filename.endswith(".csv"):
        filename = f"{filename}.csv"

    response = StreamingHttpResponse(
        stream_cve_queryset_to_csv(queryset, headers),
        content_type="text/csv",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
