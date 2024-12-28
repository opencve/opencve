import pytest
from django.db.utils import IntegrityError


def test_variable_model(create_variable):
    variable = create_variable("var1", {"foo": "bar"})
    assert variable.name == "var1"
    assert variable.value == {"foo": "bar"}


def test_variable_is_unique(create_variable):
    create_variable("foo", {})
    create_variable("bar", {})

    with pytest.raises(IntegrityError):
        create_variable("foo", {})
