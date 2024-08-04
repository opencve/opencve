import pytest

from cves.templatetags.opencve_extras import metric_class_from_ssvc


@pytest.mark.parametrize(
    "metric,value,result",
    [
        ("exploitation", "none", "default"),
        ("Exploitation", "None", "default"),
        ("Technical Impact", "Total", "danger"),
        ("technical impact", "total", "danger"),
        ("Foo", "bar", "default"),
        ("Exploitation", "foobar", "default"),
    ],
)
def test_metric_class_from_ssvc(metric, value, result):
    assert metric_class_from_ssvc(metric, value) == result
