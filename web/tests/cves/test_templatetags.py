from cves.templatetags.opencve_extras import get_item


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
