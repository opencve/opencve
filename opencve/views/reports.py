from collections import OrderedDict

from flask import request, render_template
from flask_login import login_required
from flask_user import current_user

from opencve.context import _humanize_filter
from opencve.controllers.main import main
from opencve.controllers.alerts import AlertController
from opencve.controllers.reports import ReportController


@main.route("/reports")
@login_required
def reports():
    reports, _, pagination = ReportController.list(
        {**request.args, "user_id": current_user.id}
    )
    return render_template("reports.html", reports=reports, pagination=pagination)


@main.route("/reports/<link>")
def report(link):
    report = ReportController.get({"public_link": link})
    alerts = AlertController.list_items({"report_id": report.id})

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
