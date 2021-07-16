from flask import current_app as app
from flask import abort, redirect, render_template, request, url_for
from flask_paginate import Pagination
from flask_user import current_user
from sqlalchemy import and_
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm import joinedload

from opencve.constants import PRODUCT_SEPARATOR
from opencve.controllers.main import main, welcome
from opencve.controllers.reports import ReportController
from opencve.models.changes import Change
from opencve.models.cve import Cve


@welcome.route("/welcome")
def index():
    if not app.config.get("DISPLAY_WELCOME", False):
        abort(404)
    return render_template("index.html")


@welcome.route("/terms")
def terms():
    if not app.config.get("DISPLAY_TERMS", False):
        abort(404)
    return render_template("terms.html")


@main.route("/")
def home():
    # Allow customization of the homepage
    if not current_user.is_authenticated:
        if app.config.get("DISPLAY_WELCOME", False):
            return redirect(url_for("welcome.index"))
        return redirect(url_for("main.cves"))

    # Fetch the user subscriptions
    vendors = [v.name for v in current_user.vendors]
    vendors.extend(
        [f"{p.vendor.name}{PRODUCT_SEPARATOR}{p.name}" for p in current_user.products]
    )

    objects = []
    pagination = None
    reports = ReportController.list_items({"user_id": current_user.id})

    # If user has subscriptions we can display the last activities of the vendors
    if vendors:
        page = request.args.get("page", type=int, default=1)
        query = (
            Change.query.options(joinedload("cve"))
            .options(joinedload("events"))
            .filter(Change.cve_id == Cve.id)
            .filter(Cve.vendors.has_any(array(vendors)))
            .filter(Change.events.any())
            .order_by(Change.created_at.desc())
            .limit(500)
            .from_self()
        )

        # Make the pagination
        objects = query.paginate(page, app.config["ACTIVITIES_PER_PAGE"], True)
        pagination = Pagination(
            page=page,
            total=objects.total,
            per_page=app.config["ACTIVITIES_PER_PAGE"],
            record_name="cves",
            css_framework="bootstrap3",
        )

    return render_template(
        "home.html", changes=objects, pagination=pagination, reports=reports
    )
