from opencve.constants import PRODUCT_SEPARATOR
from opencve.utils import convert_cpes, flatten_vendors


def test_convert_empty_conf():
    assert convert_cpes({}) == {}


def test_convert_simple_conf(open_file):
    conf = open_file("configurations/simple.json")
    assert convert_cpes(conf) == {"foo": ["bar"]}


def test_convert_conf_multiple_products(open_file):
    conf = open_file("configurations/multiple_products.json")
    vendors = convert_cpes(conf)
    vendors["foo"] = sorted(vendors["foo"])
    assert vendors == {"foo": ["bar", "baz"]}


def test_convert_conf_multiple_vendors(open_file):
    conf = open_file("configurations/multiple_vendors.json")
    vendors = convert_cpes(conf)
    vendors["foo"] = sorted(vendors["foo"])
    assert len(vendors) == 2
    assert vendors["foo"] == ["bar", "baz"]
    assert vendors["bar"] == ["baz"]


def test_convert_conf_nested(open_file):
    conf = open_file("configurations/nested.json")
    vendors = convert_cpes(conf)
    vendors["foo"] = sorted(vendors["foo"])
    assert vendors == {"foo": ["bar", "baz"], "bar": ["baz"]}


def test_flatten_empty_vendors():
    assert flatten_vendors({}) == []


def test_flatten_simple_vendor():
    assert flatten_vendors({"foo": ["bar"]}) == ["foo", f"foo{PRODUCT_SEPARATOR}bar"]


def test_flatten_multiple_products():
    assert flatten_vendors({"foo": ["bar", "baz"]}) == [
        "foo",
        f"foo{PRODUCT_SEPARATOR}bar",
        f"foo{PRODUCT_SEPARATOR}baz",
    ]


def test_flatten_multiple_vendors():
    assert flatten_vendors({"foo": ["bar", "baz"], "bar": ["baz"]}) == [
        "foo",
        f"foo{PRODUCT_SEPARATOR}bar",
        f"foo{PRODUCT_SEPARATOR}baz",
        "bar",
        f"bar{PRODUCT_SEPARATOR}baz",
    ]
