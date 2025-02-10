from views.forms import ViewForm


def test_view_form_valid():
    form = ViewForm(
        data={
            "name": "my-view",
            "query": "my-query",
            "privacy": "public",
        }
    )
    assert form.errors == {}


def test_view_form_invalid_privacy():
    form = ViewForm(
        data={
            "name": "my-view",
            "query": "my-query",
            "privacy": "foobar",
        }
    )
    assert form.errors == {
        "privacy": [
            "Select a valid choice. foobar is not one of the available choices."
        ]
    }


def test_view_form_name_too_long():
    form = ViewForm(
        data={
            "name": "a" * 200,
            "query": "my-query",
            "privacy": "public",
        }
    )
    assert form.errors == {
        "name": ["Ensure this value has at most 100 characters (it has 200)."]
    }


def test_view_form_clean_name():
    form = ViewForm(
        data={
            "name": "add",
            "query": "my-query",
            "privacy": "public",
        }
    )
    assert form.errors == {"name": ["This view is reserved."]}


def test_view_form_clean_query():
    form = ViewForm(
        data={
            "name": "my-view",
            "query": "/",
            "privacy": "public",
        }
    )
    assert form.errors == {
        "query": ["Expected 'OR' operations, found '/'  (at char 0), (line:1, col:1)"]
    }


def test_view_form_clean_privacy():
    form = ViewForm(
        data={
            "name": "my-view",
            "query": "my-query",
            "privacy": "foobar",
        }
    )
    assert form.errors == {
        "privacy": [
            "Select a valid choice. foobar is not one of the available choices."
        ]
    }
