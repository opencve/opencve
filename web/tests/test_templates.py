import pytest

from cves.templatetags.opencve_extras import (
    metric_class_from_ssvc,
    metric_class_from_vector,
    ssvc_tab_summary,
)


@pytest.mark.parametrize(
    "metric,value,result",
    [
        ("exploitation", "none", "neutral"),
        ("Exploitation", "None", "neutral"),
        ("Technical Impact", "Total", "danger"),
        ("technical impact", "total", "danger"),
        ("Automatable", "yes", "neutral"),
        ("automatable", "no", "neutral"),
        ("Foo", "bar", "muted"),
        ("Exploitation", "foobar", "neutral"),
    ],
)
def test_metric_class_from_ssvc(metric, value, result):
    assert metric_class_from_ssvc(metric, value) == result


def test_metric_class_from_vector_network_is_neutral():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert metric_class_from_vector(vector, "AV") == "neutral"
    assert metric_class_from_vector(vector, "C") == "danger"


def test_ssvc_tab_summary():
    assert ssvc_tab_summary(None) == "Not assessed"
    assert (
        ssvc_tab_summary({"options": {"Exploitation": "active"}})
        == "Active exploitation"
    )
