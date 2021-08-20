from flask import current_app as app
from flask import abort, redirect, render_template, request, url_for
from flask_user import current_user
from sqlalchemy import and_
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm import joinedload, aliased

from opencve.constants import PRODUCT_SEPARATOR
from opencve.controllers.main import main, welcome
from opencve.controllers.reports import ReportController
from opencve.extensions import db
from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.events import Event


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

    # Handle the page parameter
    page = request.args.get("page", type=int, default=1)
    page = 1 if page < 1 else page

    # Default values
    per_page = app.config["ACTIVITIES_PER_PAGE"]
    changes = []

    # Only display the 5 last reports
    reports = ReportController.list_items({"user_id": current_user.id})[:5]

    # If user has subscriptions we can display the last activities of the vendors
    if vendors:
        changes = (
            Change.query.options(joinedload("cve"))
            .options(joinedload("events"))
            .filter(Change.cve_id == Cve.id)
            .filter(Cve.vendors.has_any(array(vendors)))
            .filter(Change.events.any())
            .order_by(Change.created_at.desc())
            .limit(per_page)
            .offset((page - 1) * per_page)
            .all()
        )

    return render_template("home.html", changes=changes, reports=reports, page=page)
