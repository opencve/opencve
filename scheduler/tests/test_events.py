from events.mitre import MitreSummary
from events.nvd import NvdSummary, NvdFirstTime, NvdCvss, NvdCwes, NvdReference, NvdCpe


def test_events_mitre_summary(open_file):
    old = open_file("mitre/repo/b/cves/2023/5xxx/CVE-2023-5301.json")

    # No change detected
    new = open_file("mitre/repo/b/cves/2023/5xxx/CVE-2023-5301.json")
    result = MitreSummary(old=old, new=new).execute()
    assert not result

    # Summary has changed from commit b to c
    new = open_file("mitre/repo/c/cves/2023/5xxx/CVE-2023-5301.json")
    result = MitreSummary(old=old, new=new).execute()
    assert result["type"] == "mitre_summary"
    assert result["details"]["added"] == {}
    assert result["details"]["removed"] == {}
    assert result["details"]["changed"]["en"]["new"] == "OpenCVE tests"
    assert result["details"]["changed"]["en"]["old"].startswith(
        "A vulnerability classified as critical was found in DedeCMS 5.7.111"
    )

    # Check the diff for a rejected CVE
    old = {
        "containers": {
            "cna": {"descriptions": [{"lang": "foo", "value": "Lorem ipsum"}]}
        }
    }
    new = {
        "containers": {
            "cna": {"rejectedReasons": [{"lang": "bar", "value": "Lorem ipsum"}]}
        }
    }
    result = MitreSummary(old=old, new=new).execute()
    assert result["type"] == "mitre_summary"
    assert result["details"] == {
        "added": {"bar": "Lorem ipsum"},
        "removed": {"foo": "Lorem ipsum"},
        "changed": {},
    }


def test_events_nvd_summary(open_file):
    old = open_file("nvd/events/original.json")

    # No change detected
    new = open_file("nvd/events/original.json")
    result = NvdSummary(old=old, new=new).execute()
    assert not result

    # Summary has changed from commit b to c
    new = open_file("nvd/events/summary.json")
    result = NvdSummary(old=old, new=new).execute()
    assert result["type"] == "nvd_summary"
    assert result["details"]["added"] == {}
    assert result["details"]["removed"] == {}
    assert result["details"]["changed"]["en"]["new"] == "OpenCVE tests"
    assert result["details"]["changed"]["en"]["old"].startswith(
        "An issue was discovered in Django"
    )

    # Check detection of added and removed descriptions
    old = {"descriptions": [{"lang": "foo", "value": "Lorem ipsum"}]}
    new = {"descriptions": [{"lang": "bar", "value": "Lorem ipsum"}]}
    result = NvdSummary(old=old, new=new).execute()
    assert result == {
        "type": "nvd_summary",
        "details": {
            "added": {"bar": "Lorem ipsum"},
            "removed": {"foo": "Lorem ipsum"},
            "changed": {},
        },
    }


def test_events_nvd_first_time(open_file):
    old = open_file("nvd/events/original.json")

    # No change detected
    new = open_file("nvd/events/original.json")
    result = NvdFirstTime(old=old, new=new).execute()
    assert not result

    # New vendor (opencveio) & product (opencve) appear in the new version
    new = open_file("nvd/events/configurations.json")
    result = NvdFirstTime(old=old, new=new).execute()
    assert result["type"] == "nvd_first_time"
    assert sorted(result["details"]) == ["opencveio", "opencveio$PRODUCT$opencve"]


def test_events_nvd_cvss(open_file):
    old = open_file("nvd/events/original.json")

    # No change detected
    new = open_file("nvd/events/original.json")
    result = NvdCvss(old=old, new=new).execute()
    assert not result

    # CVSSv2 removed, CVSSv3.1 added, CVSS3.0 updated.
    new = open_file("nvd/events/cvss.json")
    result = NvdCvss(old=old, new=new).execute()
    assert result["type"] == "nvd_cvss"
    assert result["details"] == {
        "new": {"v30": 4.7, "v31": 8.8},
        "old": {"v2": 5.0, "v30": 7.5},
    }


def test_events_nvd_cwes(open_file):
    old = open_file("nvd/events/original.json")

    # No change detected
    new = open_file("nvd/events/original.json")
    result = NvdCwes(old=old, new=new).execute()
    assert not result

    # CVSSv2 removed, CVSSv3.1 added, CVSS3.0 updated.
    new = open_file("nvd/events/cwes.json")
    result = NvdCwes(old=old, new=new).execute()
    assert result["type"] == "nvd_cwes"
    assert result["details"] == {"added": ["CWE-123"], "removed": ["CWE-400"]}


def test_events_nvd_references(open_file):
    old = open_file("nvd/events/original.json")

    # No change detected
    new = open_file("nvd/events/original.json")
    result = NvdReference(old=old, new=new).execute()
    assert not result

    # 1 reference changed, 1 removed and 1 added
    new = open_file("nvd/events/references.json")
    result = NvdReference(old=old, new=new).execute()
    assert result["type"] == "nvd_references"
    assert result["details"] == {
        "added": [{"source": "tests@opencve.io", "url": "https://www.opencve.io"}],
        "changed": [
            {
                "new": {
                    "source": "cve@mitre.org",
                    "tags": ["Vendor Advisory", "OpenCVE tests"],
                    "url": "https://www.djangoproject.com/weblog/2019/aug/01/security-releases/",
                },
                "old": {
                    "source": "cve@mitre.org",
                    "tags": ["Vendor Advisory"],
                    "url": "https://www.djangoproject.com/weblog/2019/aug/01/security-releases/",
                },
            }
        ],
        "removed": [
            {
                "source": "cve@mitre.org",
                "url": "https://www.debian.org/security/2019/dsa-4498",
            }
        ],
    }


def test_events_nvd_cpes(open_file):
    old = open_file("nvd/events/original.json")

    # No change detected
    new = open_file("nvd/events/original.json")
    result = NvdCpe(old=old, new=new).execute()
    assert not result

    # 1 CPE added and 1 CPE removed
    new = open_file("nvd/events/cpes.json")
    result = NvdCpe(old=old, new=new).execute()
    assert result["type"] == "nvd_cpes"
    assert result["details"] == {
        "added": ["cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*"],
        "removed": ["cpe:2.3:o:opensuse:leap:15.1:*:*:*:*:*:*:*"],
    }
