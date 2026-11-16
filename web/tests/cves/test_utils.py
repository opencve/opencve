import json

import pytest
from django.contrib import auth
from django.http.request import QueryDict
from django.test import override_settings

from cves.models import Weakness
from users.models import UserTag, CveTag
from cves.constants import PRODUCT_SEPARATOR
from cves.utils import (
    affected_product_tab_context,
    metrics_tab_context,
    affected_to_dict_vendors,
    list_filtered_cves,
    list_to_dict_vendors,
    list_weaknesses,
    load_repo_json_file,
    normalize_enrichment_affected,
    project_subscription_match_keys,
)


def test_affected_to_dict_vendors():
    """Test affected_to_dict_vendors transforms enrichment affected array for list_to_dict_vendors."""
    assert affected_to_dict_vendors([]) == []
    assert affected_to_dict_vendors(None) == []

    affected = [
        {"vendor": "ibm", "product": "mq_advanced"},
        {"vendor": "ibm", "product": "mq_operator"},
    ]
    flat = affected_to_dict_vendors(affected)
    assert flat == ["ibm", "ibm$PRODUCT$mq_advanced", "ibm$PRODUCT$mq_operator"]
    assert list_to_dict_vendors(flat) == {"ibm": ["mq_advanced", "mq_operator"]}

    affected_vendor_only = [{"vendor": "linux"}]
    flat2 = affected_to_dict_vendors(affected_vendor_only)
    assert flat2 == ["linux"]
    assert list_to_dict_vendors(flat2) == {"linux": []}


def test_normalize_enrichment_affected():
    """Test normalize_enrichment_affected converts float to int when whole."""
    assert normalize_enrichment_affected([]) == []
    assert normalize_enrichment_affected(None) == []

    affected = [
        {
            "vendor": "ibm",
            "product": "mq",
            "enrichment": {
                "confidence": 100.0,
                "scores": [
                    {"source": "inferred", "score": 95.0},
                    {"source": "matching", "score": 100.0},
                ],
            },
        }
    ]
    result = normalize_enrichment_affected(affected)
    assert result[0]["enrichment"]["confidence"] == 100
    assert isinstance(result[0]["enrichment"]["confidence"], int)
    assert result[0]["enrichment"]["scores"][0]["score"] == 95
    assert result[0]["enrichment"]["scores"][1]["score"] == 100

    # Non-whole float unchanged
    affected_decimal = [
        {"vendor": "x", "enrichment": {"confidence": 95.5, "scores": []}}
    ]
    result2 = normalize_enrichment_affected(affected_decimal)
    assert result2[0]["enrichment"]["confidence"] == 95.5


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.parametrize(
    "params,result",
    [
        ("", ["CVE-2021-44228", "CVE-2022-22965"]),  # no filter
        ("search=log4j", ["CVE-2021-44228"]),  # text in description
        ("search=spring", ["CVE-2022-22965"]),  # text in description
        ("search=44228", ["CVE-2021-44228"]),  # text in CVE ID
        ("search=oracle", ["CVE-2022-22965"]),  # text in vendors
        ("weakness=CWE-400", ["CVE-2021-44228"]),
        ("cvss=low", []),
        ("cvss=critical", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor=siemens", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor=veritas", ["CVE-2022-22965"]),
        ("vendor=veritas&product=flex_appliance", ["CVE-2022-22965"]),
    ],
)
def test_list_filtered_cves(db, create_cve, client, params, result):
    """Verify list_filtered_cves applies search, weakness, CVSS, and vendor filters."""
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")
    user = auth.get_user(client)

    assert (
        sorted([c.cve_id for c in list_filtered_cves(QueryDict(params), user)])
        == result
    )


def test_list_weaknesses(db):
    """Verify list_weaknesses maps known CWE IDs to their names."""
    Weakness.objects.create(cwe_id="CWE-79", name="Cross-site Scripting")
    Weakness.objects.create(cwe_id="CWE-89", name="SQL Injection")

    assert list_weaknesses(["CWE-79", "CWE-89"]) == {
        "CWE-79": "Cross-site Scripting",
        "CWE-89": "SQL Injection",
    }


def test_list_weaknesses_unknown_cwe(db):
    """Verify list_weaknesses returns None for unkown CWE."""
    assert list_weaknesses(["CWE-999"]) == {"CWE-999": None}


def test_list_filtered_cves_with_tag(db, create_cve, create_user):
    """Verify list_filtered_cves restricts results to CVEs tagged by the user."""
    cve = create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    user = create_user()
    tag = UserTag.objects.create(name="test", user=user)
    CveTag.objects.create(user=user, cve=cve, tags=[tag.name])

    assert sorted(
        [c.cve_id for c in list_filtered_cves(QueryDict("tag=test"), user)]
    ) == ["CVE-2021-44228"]


def test_load_repo_json_file_valid_dict(tmp_path):
    """Return parsed dict when the repository JSON file exists and is valid."""
    path = tmp_path / "cve.json"
    path.write_text(json.dumps({"cve": "CVE-2024-0001"}), encoding="utf-8")
    assert load_repo_json_file(path) == {"cve": "CVE-2024-0001"}


def test_load_repo_json_file_missing(tmp_path):
    """Return empty dict when the repository JSON file does not exist."""
    path = tmp_path / "missing.json"
    assert load_repo_json_file(path) == {}


def test_load_repo_json_file_invalid_json(tmp_path):
    """Return empty dict when the file content is not valid JSON."""
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    assert load_repo_json_file(path) == {}


def test_load_repo_json_file_non_dict_root(tmp_path):
    """Return empty dict when the JSON root value is not an object."""
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert load_repo_json_file(path) == {}


def test_metrics_tab_context():
    """Expose per-metric tab flags and pick the highest CVSS tab with data."""

    class CveStub:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    cve = CveStub(
        cvssV4_0={},
        cvssV3_1={"score": 9.8},
        cvssV3_0={},
        cvssV2_0={},
        kev={"data": {"dateAdded": "2024-01-01"}},
        epss={},
        ssvc=None,
    )
    ctx = metrics_tab_context(cve)
    assert ctx["metrics_tab_has_data"]["cvss40"] is False
    assert ctx["metrics_tab_has_data"]["cvss31"] is True
    assert ctx["metrics_tab_has_data"]["kev"] is True
    assert ctx["metrics_tab_has_data"]["epss"] is False
    assert ctx["metrics_active_cvss_tab"] == "cvss31"


def test_affected_product_tab_context():
    """Pick the first affected-products source tab that has data."""

    class CveStub:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    cve = CveStub(
        mitre_json={"containers": {"cna": {"affected": [{"vendor": "x"}]}}},
        nvd_json={},
        redhat_json={},
        enrichment_json={"vendors": ["a"]},
    )
    ctx = affected_product_tab_context(cve)
    assert ctx["affected_tab_has_data"]["mitre"] is True
    assert ctx["affected_tab_has_data"]["nvd"] is False
    assert ctx["affected_active_tab"] == "mitre"

    cve2 = CveStub(
        mitre_json={"containers": {"cna": {}}},
        nvd_json={"configurations": [{}]},
        redhat_json={},
        enrichment_json={},
    )
    assert affected_product_tab_context(cve2)["affected_active_tab"] == "nvd"


def test_project_subscription_match_keys():
    """Return sorted vendor and product keys matched by project subscriptions."""
    cve_vendors = [
        "fortinet",
        f"fortinet{PRODUCT_SEPARATOR}fortios",
        "linux",
    ]
    subscriptions = {
        "vendors": ["fortinet"],
        "products": [f"fortinet{PRODUCT_SEPARATOR}fortios"],
    }
    assert project_subscription_match_keys(cve_vendors, subscriptions) == [
        "fortinet",
        f"fortinet{PRODUCT_SEPARATOR}fortios",
    ]


def test_build_cve_quick_search_sidebar_entries():
    """Mark quick-search links beyond the preview as hidden in the sidebar."""
    from cves.constants import (
        CVE_QUICK_SEARCH_GROUPS,
        CVE_SIDEBAR_QUICK_SEARCHES_PREVIEW,
        build_cve_quick_search_sidebar_entries,
    )

    entries, total = build_cve_quick_search_sidebar_entries(
        CVE_QUICK_SEARCH_GROUPS,
        preview=2,
    )
    link_entries = [e for e in entries if e.get("kind") == "link"]
    assert total >= len(link_entries)
    assert any(e["hidden"] for e in link_entries)
    assert any(not e["hidden"] for e in link_entries)


def test_build_cve_quick_search_sidebar_entries_expands_when_active_hidden():
    """Reveal collapsed quick searches when the current query matches a hidden link."""
    from cves.constants import (
        CVE_QUICK_SEARCH_GROUPS,
        build_cve_quick_search_sidebar_entries,
    )

    link_queries = [
        item["query"] for group in CVE_QUICK_SEARCH_GROUPS for item in group["items"]
    ]
    assert len(link_queries) > 2
    active_q = link_queries[2]

    entries, _ = build_cve_quick_search_sidebar_entries(
        CVE_QUICK_SEARCH_GROUPS,
        preview=2,
        current_q=active_q,
    )
    assert not any(entry.get("hidden") for entry in entries)
