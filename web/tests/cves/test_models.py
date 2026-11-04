import pytest

from django.db.utils import IntegrityError
from django.test import override_settings


@pytest.mark.django_db
def test_variable_model(create_variable):
    """Verify Variable stores the given name and JSON value."""
    variable = create_variable("var1", {"foo": "bar"})
    assert variable.name == "var1"
    assert variable.value == {"foo": "bar"}


@pytest.mark.django_db
def test_variable_is_unique(create_variable):
    """Verify Variable name must be unique."""
    create_variable("foo", {})
    create_variable("bar", {})

    with pytest.raises(IntegrityError):
        create_variable("foo", {})


@pytest.mark.django_db
def test_cve_model_basic_properties(create_cve):
    """Verify basic CVE fields and string representation after import."""
    cve = create_cve("CVE-2021-44228")

    assert cve.cve_id == "CVE-2021-44228"
    assert cve.title is not None
    assert cve.description is not None
    assert isinstance(cve.vendors, list)
    assert isinstance(cve.weaknesses, list)
    assert isinstance(cve.metrics, dict)
    assert str(cve) == "CVE-2021-44228"


@pytest.mark.django_db
def test_cve_model_kb_path_property(create_cve):
    """Verify kb_path points to year/CVE-ID.json under the KB repository."""
    cve = create_cve("CVE-2021-44228")

    kb_path = cve.kb_path
    assert str(kb_path).endswith("2021/CVE-2021-44228.json")


@pytest.mark.django_db
def test_cve_model_kb_json_property(create_cve):
    """Verify kb_json loads the CVE record from the KB repository file."""
    cve = create_cve("CVE-2021-44228")

    kb_json = cve.kb_json
    assert isinstance(kb_json, dict)
    assert kb_json["cve"] == "CVE-2021-44228"
    assert "opencve" in kb_json
    assert "mitre" in kb_json


@pytest.mark.django_db
def test_cve_model_cvss_properties(create_cve):
    """Verify CVSS version properties expose metrics data from the CVE record."""
    cve = create_cve("CVE-2021-44228")

    cvss_v2 = cve.cvssV2_0
    cvss_v3_0 = cve.cvssV3_0
    cvss_v3_1 = cve.cvssV3_1
    cvss_v4_0 = cve.cvssV4_0

    assert cvss_v2 == {"score": 9.3, "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C"}
    assert cvss_v3_0 == {}
    assert cvss_v3_1 == {
        "score": 10.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    assert cvss_v4_0 == {}


@pytest.mark.django_db
def test_cve_model_security_metrics(create_cve):
    """Verify KEV, EPSS, and SSVC blocks are exposed from stored metrics."""
    cve = create_cve("CVE-2025-48543")

    assert cve.kev == {
        "data": {
            "dueDate": "2025-09-25T00:00:00+00:00",
            "dateAdded": "2025-09-04T00:00:00+00:00",
        },
        "provider": "cisa",
    }
    assert cve.epss == {"data": {"score": 0.00223}, "provider": "first"}
    assert cve.ssvc == {
        "data": {
            "options": {
                "Automatable": "no",
                "Exploitation": "active",
                "Technical Impact": "total",
            },
            "version": "2.0.3",
        },
        "provider": "vulnrichment",
    }


@pytest.mark.django_db
def test_cve_model_references_property(create_cve):
    """Verify references returns OpenCVE aggregated links from the KB file."""
    cve = create_cve("CVE-2025-48543")
    assert cve.references == {
        "data": [
            "https://android.googlesource.com/platform/art/+/444fc40dfb04d2ec5f74c443ed3a4dd45d3131f2",
            "https://source.android.com/security/bulletin/2025-09-01",
        ],
        "providers": ["mitre", "nvd"],
    }


@pytest.mark.django_db
def test_cve_model_solution_property(create_cve):
    """Verify solution returns the English CNA solution text from mitre_json."""
    cve = create_cve("CVE-2025-2239")

    # Mock the mitre_json property to return the expected data
    mock_mitre_data = {
        "containers": {
            "cna": {
                "solutions": [
                    {
                        "lang": "en",
                        "supportingMedia": [
                            {
                                "base64": False,
                                "type": "text/html",
                                "value": "Upgrade the NGWF device to version 5.5R8P23 or higher.",
                            }
                        ],
                        "value": "Upgrade the NGWF device to version 5.5R8P23 or higher.",
                    }
                ]
            }
        }
    }

    cve._mitre_json = mock_mitre_data
    assert cve.solution == "Upgrade the NGWF device to version 5.5R8P23 or higher."


@pytest.mark.django_db
def test_cve_model_workaround_property(create_cve):
    """Verify workaround returns the English CNA workaround text from mitre_json."""
    cve = create_cve("CVE-2025-2239")

    # Mock the mitre_json property to return the expected data
    mock_mitre_data = {
        "containers": {
            "cna": {
                "workarounds": [
                    {
                        "lang": "en",
                        "supportingMedia": [
                            {
                                "base64": False,
                                "type": "text/html",
                                "value": 'If an upgrade is not feasible in the short term, we advise mitigating the risk by configuring a "Trusted Host Access" policy.\n\n\n\n<br>',
                            }
                        ],
                        "value": 'If an upgrade is not feasible in the short term, we advise mitigating the risk by configuring a "Trusted Host Access" policy.',
                    }
                ]
            }
        }
    }

    cve._mitre_json = mock_mitre_data
    assert (
        cve.workaround
        == 'If an upgrade is not feasible in the short term, we advise mitigating the risk by configuring a "Trusted Host Access" policy.'
    )


@pytest.mark.django_db
def test_cve_model_advisories_property(create_cve):
    """Verify advisories reads the list from kb_json when present."""
    cve = create_cve("CVE-2025-48543")
    assert cve.advisories == []

    cve._kb_json = {
        "advisories": [
            {"source": "euvd", "id": "EUVD-2025-0001", "title": "EUVD Advisory"},
        ]
    }
    assert cve.advisories == [
        {"source": "euvd", "id": "EUVD-2025-0001", "title": "EUVD Advisory"},
    ]


@pytest.mark.django_db
def test_cve_model_kb_json_when_kb_file_missing(create_cve, tmp_path):
    """Return empty kb_json and references when the KB file cannot be loaded."""
    cve = create_cve("CVE-2021-44228")
    with override_settings(KB_REPO_PATH=str(tmp_path)):
        assert cve.kb_json == {}
        assert cve.references == {}


@pytest.mark.django_db
@pytest.mark.parametrize(
    "repo_setting,kb_key,repo_path_key,json_property",
    [
        ("MITRE_REPO_PATH", "mitre", "mitre_repo_path", "mitre_json"),
        ("NVD_REPO_PATH", "nvd", "nvd_repo_path", "nvd_json"),
        ("REDHAT_REPO_PATH", "redhat", "redhat_repo_path", "redhat_json"),
        (
            "VULNRICHMENT_REPO_PATH",
            "vulnrichment",
            "vulnrichment_repo_path",
            "vulnrichment_json",
        ),
    ],
)
def test_cve_model_satellite_json_when_file_missing(
    create_cve, tmp_path, repo_setting, kb_key, repo_path_key, json_property
):
    """Return empty satellite JSON when the repository file is missing."""
    cve = create_cve("CVE-2021-44228")
    cve._kb_json = {kb_key: {repo_path_key: "2021/CVE-2021-44228.json"}}
    with override_settings(**{repo_setting: str(tmp_path)}):
        assert getattr(cve, json_property) == {}
