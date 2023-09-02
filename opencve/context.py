from flask import current_app as app
from flask import request, url_for
from flask_user import current_user

from opencve.constants import EVENT_TYPES, PRODUCT_SEPARATOR
from opencve.models.tags import UserTag


def _cvss_percent(score):
    percent = score * 100 / 10
    return "{}%".format(str(percent))


def _cvss_bg(score):
    score = float(score)

    if 0 <= score <= 3.9:
        return ("bg-blue", "label-info")
    elif 4.0 <= score <= 6.9:
        return ("bg-yellow", "label-warning")
    elif 7.0 <= score <= 8.9:
        return ("bg-red", "label-danger")
    else:
        return ("bg-critical", "label-critical")


def _metric_bg(version, type, value):
    metrics_v2 = {
        "AV": {
            "local": "label-default",
            "adjacent network": "label-warning",
            "network": "label-danger",
        },
        "AC": {
            "high": "label-default",
            "medium": "label-warning",
            "low": "label-danger",
        },
        "AU": {
            "multiple": "label-default",
            "single": "label-warning",
            "none": "label-danger",
        },
        "C": {
            "none": "label-default",
            "partial": "label-warning",
            "complete": "label-danger",
        },
        "I": {
            "none": "label-default",
            "partial": "label-warning",
            "complete": "label-danger",
        },
        "A": {
            "none": "label-default",
            "partial": "label-warning",
            "complete": "label-danger",
        },
    }

    metrics_v3 = {
        "AV": {
            "network": "label-danger",
            "adjacent": "label-warning",
            "local": "label-warning",
            "physical": "label-default",
        },
        "AC": {"low": "label-danger", "high": "label-warning"},
        "PR": {"none": "label-danger", "low": "label-warning", "high": "label-default"},
        "UI": {"none": "label-danger", "required": "label-warning"},
        "S": {"unchanged": "label-default", "changed": "label-danger"},
        "C": {"high": "label-danger", "low": "label-warning", "none": "label-default"},
        "I": {"high": "label-danger", "low": "label-warning", "none": "label-default"},
        "A": {"high": "label-danger", "low": "label-warning", "none": "label-default"},
    }
    versions = {"v2": metrics_v2, "v3": metrics_v3}

    try:
        value = versions[version][type][value.lower()]
    except KeyError:
        return ("label-default", "No description")

    return value


def _humanize_filter(s):
    return " ".join(map(lambda x: x.capitalize(), s.split("_")))


def _excerpt(objects, _type):
    """
    This function takes a flat list of vendors and products and returns
    the HTML code used in the CVEs list page.
    """
    output = ""

    if not objects:
        return output

    # Keep the objects of the requested type
    if _type == "products":
        objects = [o for o in objects if PRODUCT_SEPARATOR in o]
    else:
        objects = [o for o in objects if not PRODUCT_SEPARATOR in o]

    objects = sorted(objects)
    output += '<span class="badge badge-primary">{}</span> '.format(len(objects))

    # Keep the remains size and reduce the list
    remains = len(objects[app.config["COUNT_EXCERPT"] :])

    if len(objects) > app.config["COUNT_EXCERPT"]:
        objects = objects[: app.config["COUNT_EXCERPT"]]

    # Construct the HTML
    for idx, obj in enumerate(objects):
        if _type == "products":
            vendor, product = obj.split(PRODUCT_SEPARATOR)
            url = url_for("main.cves", vendor=vendor, product=product)
            output += f"<a href='{url}'>{_humanize_filter(product)}</a>"
        elif _type == "vendors":
            url = url_for("main.cves", vendor=obj)
            output += f"<a href='{url}'>{_humanize_filter(obj)}</a>"
        else:
            url = url_for("main.cves", tag=obj)
            tag = UserTag.query.filter_by(user_id=current_user.id, name=obj).first()
            output += f"<a href='{url}'><span class='label label-tag' style='background-color: {tag.color};'>{obj}</span></a>"

        output += ", " if idx + 1 != len(objects) and _type != "tags" else " "

    if remains:
        output += "<i>and {} more</i>".format(remains)

    return output


def _report_excerpt(items):
    output = ""

    if not items:
        return output

    items_copy = items
    if len(items) > app.config["REPORT_COUNT_EXCERPT"]:
        items = items[: app.config["REPORT_COUNT_EXCERPT"]]

    for idx, item in enumerate(items):
        output += _humanize_filter(item)
        if idx + 1 != len(items):
            output += ", "
        else:
            output += " "

    remains = len(items_copy[app.config["REPORT_COUNT_EXCERPT"] :])

    if remains:
        output += "<i>and {} more</i>".format(remains)

    return output


def _is_active(route):
    return request.endpoint in route.split(",")


def _event_excerpt(details):
    if isinstance(details, list):
        return f"<strong>{len(details)}</strong> added"
    else:
        output = []
        if "changed" in details:
            output.append(f"<strong>{len(details['changed'])}</strong> changed")
        if "added" in details:
            output.append(f"<strong>{len(details['added'])}</strong> added")
        if "removed" in details:
            output.append(f"<strong>{len(details['removed'])}</strong> removed")
        return ", ".join(output)


def _event_description(code):
    return dict(EVENT_TYPES)[code]


def _remove_product_separator(s):
    return s.replace(PRODUCT_SEPARATOR, " ")


def _display_sorting_icon(args: list, desc: str, asc: str):
    if args is None or (desc not in args and asc not in args):
        return "fa fa-sort"
    if desc in args and asc in args:
        if args.index(desc) < args.index(asc):
            output = "fa fa-sort-desc"
        else:
            output = "fa fa-sort-asc"
    elif desc in args:
        output = "fa fa-sort-desc"
    elif asc in args:
        output = "fa fa-sort-asc"
    return output


def _get_sort_parameter(args, value):
    if args is None:
        args = []
    if value in args:
        args = args[: args.index(value)]
        args.append(value + "_asc")
    elif value + "_asc" in args:
        args = args[: args.index(value + "_asc")]
    else:
        args.append(value)

    return args
