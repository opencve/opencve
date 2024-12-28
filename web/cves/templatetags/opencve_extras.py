import hashlib
import json
import logging
from datetime import datetime

from django import template
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlencode
from django.utils.safestring import mark_safe

from cves.constants import (
    CVSS_CHART_BACKGROUNDS,
    CVSS_HUMAN_SCORE,
    CVSS_NAME_MAPPING,
    CVSS_VECTORS_MAPPING,
    PRODUCT_SEPARATOR,
)
from cves.utils import get_metric_from_vector
from cves.utils import humanize as _humanize

logger = logging.getLogger(__name__)

register = template.Library()


def excerpt(objects, _type):
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
    remains = len(objects[settings.COUNT_EXCERPT :])

    if len(objects) > settings.COUNT_EXCERPT:
        objects = objects[: settings.COUNT_EXCERPT]

    # Construct the HTML
    for idx, obj in enumerate(objects):
        base_url = reverse("cves")

        if _type == "products":
            vendor, product = obj.split(PRODUCT_SEPARATOR)
            query_kwargs = urlencode({"vendor": vendor, "product": product})
            output += f"<a href='{base_url}?{query_kwargs}'>{humanize(product)}</a>"
        elif _type == "vendors":
            query_kwargs = urlencode({"vendor": obj})
            output += f"<a href='{base_url}?{query_kwargs}'>{humanize(obj)}</a>"
        """else:
            url = url_for("main.cves", tag=obj)
            tag = UserTag.query.filter_by(user_id=current_user.id, name=obj).first()
            output += f"<a href='{url}'><span class='label label-tag' style='background-color: {tag.color};'>{obj}</span></a>"""

        output += ", " if idx + 1 != len(objects) and _type != "tags" else " "

    if remains:
        output += "<i>and {} more</i>".format(remains)

    return output


@register.filter(is_safe=True)
def vendors_excerpt(s):
    return mark_safe(excerpt(s, "vendors"))


@register.filter(is_safe=True)
def products_excerpt(s):
    return mark_safe(excerpt(s, "products"))


@register.filter
def humanize(s):
    return _humanize(s)


@register.filter
def gravatar_url(email, size=40):
    return "https://www.gravatar.com/avatar/{}?{}".format(
        hashlib.md5(email.lower().encode("utf-8")).hexdigest(),
        urlencode({"s": str(size)}),
    )


# Filters & Tags related to the CVSS scores


@register.filter
def cvss_level(score):
    score = float(score)

    if 0 <= score <= 3.9:
        return "info"
    elif 4.0 <= score <= 6.9:
        return "warning"
    elif 7.0 <= score <= 8.9:
        return "danger"
    else:
        return "critical"


@register.filter
def cvss_human_score(score):
    level = cvss_level(score)
    return CVSS_HUMAN_SCORE[level]


@register.simple_tag
def cvss_chart_data(vector, score):
    metric = get_metric_from_vector(vector)
    version = metric["version"]
    level = cvss_level(score)

    labels = {}
    for k, v in metric["metrics"].items():
        try:
            labels[CVSS_NAME_MAPPING[version][k]] = CVSS_VECTORS_MAPPING[version][k][v][
                "weight"
            ]
        except KeyError:
            # TODO: replace with a Sentry alert
            logger.debug(f"Metric {k}:{v} not supported in vector {vector}")

    return json.dumps(
        {
            "labels": [k for k in labels.keys()],
            "datasets": [
                {
                    "data": [v for v in labels.values()],
                    "backgroundColor": CVSS_CHART_BACKGROUNDS[level]["alpha"],
                    "borderColor": CVSS_CHART_BACKGROUNDS[level]["color"],
                    "pointBackgroundColor": CVSS_CHART_BACKGROUNDS[level]["color"],
                    "borderWidth": 2,
                    "pointRadius": 1,
                }
            ],
        }
    )


@register.simple_tag
def metric_class_from_vector(vector, metric):
    data = get_metric_from_vector(vector, metric)
    return ["default", "warning", "danger"][data["weight"]]


@register.simple_tag
def metric_text_from_vector(vector, metric):
    data = get_metric_from_vector(vector, metric)
    return data["text"]


@register.simple_tag
def metric_class_from_ssvc(metric, value):
    metric = metric.lower()
    value = value.lower()

    metrics = {
        "exploitation": {
            "none": "default",
            "poc": "warning",
            "active": "danger",
        },
        "automatable": {
            "no": "default",
            "yes": "danger",
        },
        "technical impact": {
            "partial": "default",
            "total": "danger",
        },
    }

    if metric not in metrics.keys() or value not in metrics[metric]:
        return "default"

    return metrics[metric][value]


@register.simple_tag(takes_context=True)
def query_params_url(context, *args):
    query_params = dict(context["request"].GET)
    for key, value in query_params.items():
        if isinstance(value, list):
            query_params[key] = value[0]

    # Update query values with new ones provided in the tag
    grouped_params = {args[i]: args[i + 1] for i in range(0, len(args), 2)}
    query_params.update(grouped_params)

    return urlencode(query_params)


@register.filter
def remove_product_separator(s):
    return s.replace(PRODUCT_SEPARATOR, " ")


@register.simple_tag
def search_vendor_url(s):
    base_url = reverse("subscribe")

    if PRODUCT_SEPARATOR in s:
        vendor, product = s.split(PRODUCT_SEPARATOR)
        return f"{base_url}?vendor={vendor}&product={product}"

    return f"{base_url}?vendor={s}"


@register.filter
def event_excerpt(details):
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


@register.filter
def event_humanized_type(event):
    return humanize(event["type"])


@register.filter
def is_new_cve(change):
    return len(change.types) == 1 and change.types[0] == "created"


@register.simple_tag(takes_context=True)
def is_active_link(context, *args):
    url_name = context["request"].resolver_match.url_name
    if url_name in args:
        return "active"
    return ""


@register.simple_tag(takes_context=True)
def is_active_project_link(context, *args):
    resolver = context["request"].resolver_match
    if "/projects/" not in resolver.route:
        return ""

    current_project_name = resolver.kwargs.get("name")
    if not current_project_name:
        return ""
    elif current_project_name == args[0]:
        return "active"

    return ""


@register.filter
def split(value, key):
    return value.split(key)


@register.filter
def flat_vendors(vendors):
    output = []

    for vendor in vendors:
        if PRODUCT_SEPARATOR in vendor:
            product = " ".join(vendor.split(PRODUCT_SEPARATOR))
            output.append(humanize(product))
        else:
            output.append(humanize(vendor))
    sorted(output)
    return ", ".join(output)


@register.filter
def convert_str_date(value):
    return datetime.fromisoformat(value)


@register.filter
def get(mapping, key):
    """
    Used to return data when a space is contained in the key.
    """
    return mapping.get(key, "")
