import os

from flask import Blueprint
from jinja2.filters import do_mark_safe

from opencve.configuration import OPENCVE_WELCOME_FILES
from opencve.constants import EMAIL_CONFIRMATION_MESSAGE
from opencve.context import (
    _cvss_bg,
    _cvss_percent,
    _excerpt,
    _event_excerpt,
    _humanize_filter,
    _metric_bg,
    _report_excerpt,
)

main = Blueprint(
    "main",
    __name__,
    static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
)

welcome = Blueprint(
    "welcome",
    __name__,
    static_url_path="/static/welcome",
    static_folder=OPENCVE_WELCOME_FILES,
    template_folder=OPENCVE_WELCOME_FILES,
)


@main.context_processor
def cvss_percent():
    return {"cvss_score_percent": _cvss_percent}


@main.context_processor
def cvss_bg():
    return {"cvss_bg": _cvss_bg}


@main.context_processor
def metric_bg():
    return {"metric_bg": _metric_bg}


from flask import url_for


def url_for_asset(filename):
    return url_for("static", filename=filename)


@main.context_processor
def get_url_for_asset():
    return {"url_for_asset": url_for_asset}


@main.app_template_filter("humanize")
def humanize_filter(s):
    return _humanize_filter(s)


@main.app_template_filter("vendors_excerpt")
def vendors_excerpt(s):
    return _excerpt(s, "vendors")


@main.app_template_filter("products_excerpt")
def products_excerpt(s):
    return _excerpt(s, "products")


@main.app_template_filter("report_excerpt")
def report_excerpt(s):
    return _report_excerpt(s)


@main.app_template_filter("event_excerpt")
def event_excerpt(s):
    return _event_excerpt(s)


@main.app_template_filter("custom_safe")
def custom_safe(s):
    if s == EMAIL_CONFIRMATION_MESSAGE:
        return do_mark_safe(s)
    return s
