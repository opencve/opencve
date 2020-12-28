from collections import OrderedDict

from flask import current_app as app
from flask import redirect, render_template, request, url_for
from flask_login import login_required
from flask_paginate import Pagination
from flask_user import current_user
from sqlalchemy.orm import joinedload

from opencve.context import _humanize_filter
from opencve.controllers.main import main
from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.reports import Report


@main.route("/reports")
@login_required
def reports():
    q = Report.query.filter_by(user=current_user).order_by(Report.created_at.desc())

    page = request.args.get("page", type=int, default=1)
    reports = q.paginate(page, app.config["REPORTS_PER_PAGE"], True)
    pagination = Pagination(
        page=page,
        total=reports.total,
        per_page=app.config["REPORTS_PER_PAGE"],
        record_name="reports",
        css_framework="bootstrap3",
    )

    return render_template("reports.html", reports=reports, pagination=pagination)


@main.route("/reports/<link>")
def report(link):
    report = Report.query.filter_by(public_link=link).first()
    if not report:
        return redirect(url_for("main.reports"))

    # The report is now seen
    report.seen = True
    db.session.commit()

    alerts = Alert.query.options(joinedload("cve")).filter_by(report_id=report.id).all()

    # List of vendors/products per alert
    alerts_sorted = {}
    for alert in alerts:

        for vendor in alert.details["vendors"]:
            if vendor not in alerts_sorted:
                alerts_sorted[vendor] = {
                    "name": _humanize_filter(vendor),
                    "alerts": [],
                    "max": 0,
                }
            alerts_sorted[vendor]["alerts"].append(alert)
        for product in alert.details["products"]:
            if product not in alerts_sorted:
                alerts_sorted[product] = {
                    "name": _humanize_filter(product),
                    "alerts": [],
                    "max": 0,
                }
            alerts_sorted[product]["alerts"].append(alert)

    # For each vendor, we take the max score
    for k, als in alerts_sorted.items():

        # Get the max score
        cvss = [al.cve.cvss3 for al in als["alerts"] if al.cve.cvss3]
        if cvss:
            alerts_sorted[k]["max"] = max(cvss)

    alerts_sorted = OrderedDict(
        sorted(alerts_sorted.items(), key=lambda i: i[1]["max"], reverse=True)
    )

    # Some stats
    total_alerts = len(alerts)
    maximum_score = max([v["max"] for k, v in alerts_sorted.items()])

    return render_template(
        "report.html",
        alerts_sorted=alerts_sorted,
        total_alerts=total_alerts,
        total_vendors_products=len(alerts_sorted.keys()),
        maximum_score=maximum_score,
        report=report,
    )
