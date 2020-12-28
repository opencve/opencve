from flask import current_app as app
from flask import request, url_for

from opencve.constants import PRODUCT_SEPARATOR


def _cvss_percent(score):
    percent = score * 100 / 10
    return "{}%".format(str(percent))


def _cvss_bg(score):
    score = float(score)

    if 0 <= score <= 3.9:
        return ("bg-blue", "progress-bar-info", "label-info")
    elif 4.0 <= score <= 7.4:
        return ("bg-yellow", "progress-bar-warning", "label-warning")
    else:
        return ("bg-red", "progress-bar-danger", "label-danger")


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
    output = ""

    if not objects:
        return output

    if len(objects) > app.config["COUNT_EXCERPT"]:
        objects = objects[: app.config["COUNT_EXCERPT"]]

    # Returns products or vendors
    if _type == "products":
        objects = [o for o in objects if PRODUCT_SEPARATOR in o]
    else:
        objects = [o for o in objects if not PRODUCT_SEPARATOR in o]

    output += '<span class="badge badge-primary">{}</span> '.format(len(objects))
    ordered = sorted(objects)

    for idx, obj in enumerate(objects):
        try:
            # Products are formed like vendorPRODUCT_SEPARATORproduct
            vendor, product = obj.split(PRODUCT_SEPARATOR)
            url = url_for("main.cves", vendor=vendor, product=product)
            output += f"<a href='{url}'>{_humanize_filter(product)}</a>"
        except ValueError:
            url = url_for("main.cves", vendor=obj)
            output += f"<a href='{url}'>{_humanize_filter(obj)}</a>"

        output += ", " if idx + 1 != len(objects) else " "

    remains = len(ordered[app.config["COUNT_EXCERPT"] :])
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
