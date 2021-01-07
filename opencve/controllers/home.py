from flask import current_app as app
from flask import abort, redirect, render_template, request, url_for
from flask_paginate import Pagination
from flask_user import current_user
from sqlalchemy import and_
from sqlalchemy.dialects.postgresql import array

from opencve.constants import PRODUCT_SEPARATOR
from opencve.controllers.main import main, welcome
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

    # Display empty message
    if not vendors:
        return render_template("home.html", cves=[], pagination=None)

    # Start the query asking any CVE having one vendor at least
    q = Cve.query.filter(Cve.vendors.has_any(array(vendors)))

    # Filter by CVSS score
    if request.args.get("cvss") and request.args.get("cvss").lower() in [
        "none",
        "low",
        "medium",
        "high",
        "critical",
    ]:
        if request.args.get("cvss").lower() == "none":
            q = q.filter(Cve.cvss3 == None)

        if request.args.get("cvss").lower() == "low":
            q = q.filter(and_(Cve.cvss3 >= 0.1, Cve.cvss3 <= 3.9))

        if request.args.get("cvss").lower() == "medium":
            q = q.filter(and_(Cve.cvss3 >= 4.0, Cve.cvss3 <= 6.9))

        if request.args.get("cvss").lower() == "high":
            q = q.filter(and_(Cve.cvss3 >= 7.0, Cve.cvss3 <= 8.9))

        if request.args.get("cvss").lower() == "critical":
            q = q.filter(and_(Cve.cvss3 >= 9.0, Cve.cvss3 <= 10.0))

    # Make the pagination
    page = request.args.get("page", type=int, default=1)
    objects = q.order_by(Cve.updated_at.desc()).paginate(
        page, app.config["CVES_PER_PAGE"], True
    )
    pagination = Pagination(
        page=page,
        total=objects.total,
        per_page=app.config["CVES_PER_PAGE"],
        record_name="cves",
        css_framework="bootstrap3",
    )

    return render_template("home.html", cves=objects, pagination=pagination)
