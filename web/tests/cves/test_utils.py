import pytest
from django.contrib import auth
from django.http.request import QueryDict
from django.test import override_settings

from users.models import UserTag, CveTag
from cves.utils import (
    affected_to_dict_vendors,
    list_filtered_cves,
    list_to_dict_vendors,
    normalize_enrichment_affected,
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
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")
    user = auth.get_user(client)

    assert (
        sorted([c.cve_id for c in list_filtered_cves(QueryDict(params), user)])
        == result
    )


def test_list_filtered_cves_with_tag(db, create_cve, create_user):
    cve = create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    user = create_user()
    tag = UserTag.objects.create(name="test", user=user)
    CveTag.objects.create(user=user, cve=cve, tags=[tag.name])

    assert sorted(
        [c.cve_id for c in list_filtered_cves(QueryDict("tag=test"), user)]
    ) == ["CVE-2021-44228"]
