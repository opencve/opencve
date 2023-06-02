from flask import current_app as app
from flask import abort, flash, redirect, render_template, request, url_for
from flask_user import current_user
from sqlalchemy import and_
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm import joinedload, aliased

from opencve.constants import PRODUCT_SEPARATOR, VULNERABLE_SEPARATOR
from opencve.controllers.main import main, welcome
from opencve.controllers.reports import ReportController
from opencve.extensions import db
from opencve.forms import ActivitiesViewForm
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


@main.route("/", methods=["GET", "POST"])
def home():
    # Allow customization of the homepage
    if not current_user.is_authenticated:
        if app.config.get("DISPLAY_WELCOME", False):
            return redirect(url_for("welcome.index"))
        return redirect(url_for("main.cves"))

    # Form used to customize the activities view
    activities_view_form = ActivitiesViewForm(
        obj=current_user,
        view=current_user.settings["activities_view"],
    )

    if request.method == "POST":
        form_name = request.form["form-name"]
        if form_name == "activities_view_form" and activities_view_form.validate():
            new_settings = {
                **current_user.settings,
                "activities_view": activities_view_form.view.data,
            }
            current_user.settings = new_settings
            db.session.commit()

            flash("Your settings has been updated.", "success")
            return redirect(url_for("main.home"))

    # Handle the page parameter
    page = request.args.get("page", type=int, default=1)
    page = 1 if page < 1 else page
    per_page = app.config["ACTIVITIES_PER_PAGE"]

    # Only display the 5 last reports
    reports = ReportController.list_items({"user_id": current_user.id})[:5]

    # Build the query to fetch the last changes
    query = (
        Change.query.options(joinedload("cve"))
        .options(joinedload("events"))
        .filter(Change.cve_id == Cve.id)
        .filter(Change.events.any())
    )

    # Filter by subscriptions
    if current_user.settings["activities_view"] == "subscriptions":
        vendors = [v.name for v in current_user.vendors]
        vendors.extend(
            [
                f"{p.vendor.name}{PRODUCT_SEPARATOR}{p.name}"
                for p in current_user.products
            ]
        )
        if not vendors:
            vendors = [None]
        query = query.filter(Cve.vendors.has_any(array(vendors)))

    # Filter by vulnerable subscriptions
    if current_user.settings["activities_view"] == "vulnerable":
        vendors = [VULNERABLE_SEPARATOR + v.name for v in current_user.vendors]
        vendors.extend(
            [
                f"{VULNERABLE_SEPARATOR}{p.vendor.name}{PRODUCT_SEPARATOR}{p.name}"
                for p in current_user.products
            ]
        )
        if not vendors:
            vendors = [None]
        query = query.filter(Cve.vendors.has_any(array(vendors)))

    # List the paginated changes
    changes = (
        query.order_by(Change.created_at.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
        .all()
    )

    return render_template(
        "home.html",
        changes=changes,
        reports=reports,
        page=page,
        activities_view_form=activities_view_form,
    )
