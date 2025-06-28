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


import pytest
from cves.templatetags.opencve_extras import needs_quotes


@pytest.mark.parametrize(
    "value, expected",
    [
        # Normal values that should not need quotes
        ("normaltext", False),
        ("normal-text", False),
        ("normal_text", False),
        ("normaltext123", False),
        ("", False),
        # Values with special characters that need quotes
        ("text:colon", True),
        ("text'quote", True),
        ('text"doublequote', True),
        ("text(parentheses)", True),
        ("text[brackets]", True),
        ("text{braces}", True),
        ("text&ampersand", True),
        ("text|pipe", True),
        ("text=equals", True),
        ("text!bang", True),
        ("text\\backslash", True),
        ("text<less>", True),
        ("text>greater", True),
        ("text+plus", True),
        ("text*star", True),
        ("text?question", True),
        ("text^caret", True),
        ("text~tilde", True),
        # Values with spaces
        ("text with space", True),
        ("multiple words here", True),
        (" leadingspace", True),
        ("trailingspace ", True),
        # Edge cases
        (":", True),
        ("'", True),
        ('"', True),
        (" ", True),
        ("\\", True),
    ],
)
def test_needs_quotes(value, expected):
    """
    Test needs_quotes function to ensure it correctly identifies values
    that need to be quoted due to special characters or spaces.
    """
    assert needs_quotes(value) == expected
