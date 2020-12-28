from collections import OrderedDict
from datetime import datetime, time

from celery.utils.log import get_task_logger
from flask import render_template

from opencve.context import _humanize_filter
from opencve.extensions import cel, db, user_manager
from opencve.models.alerts import Alert
from opencve.models.cve import Cve
from opencve.models.reports import Report
from opencve.models.users import User

logger = get_task_logger(__name__)


@cel.task(name="HANDLE_REPORTS")
def handle_reports():
    cel.app.app_context().push()

    # The server name is mandatory to generate the mails
    if not cel.app.config.get("SERVER_NAME"):
        raise ValueError(
            "The `server_name` variable is not set in your `opencve.cf` file. "
            "Please configure it to allow OpenCVE to create reports and send the mails."
        )

    query = User.query.filter(User.alerts.any(Alert.notify == False))

    # If we are between 11:00 AM and 11:15 AM, we get all the users (including `once`
    # and `always`). Otherwise we just take the `always` ones.
    # /!\ TODO : change this ! It can happen that a previous job takes too much time,
    # so this period can be sometimes no reached.
    now = datetime.now()
    if time(11, 0) <= now.time() <= time(11, 15):
        logger.info("We are between 11:00 AM and 11:15 AM, get all the users...")
        users = query.all()
    else:
        logger.info("Get the users who want to always receive email...")
        users = query.filter(User.frequency_notifications == "always").all()

    if not users:
        logger.info("No alert to send.")
        return

    # Get alerts for all users, create a report containing it
    # and send a mail with the top alerts.
    logger.info("Checking {} users with alerts to send...".format(len(users)))

    for user in users:
        alerts = Alert.query.filter_by(user=user, notify=False).all()
        count_alerts = len(alerts)
        logger.info("{} alerts to notify for {}".format(count_alerts, user.username))

        # Order the Top 10 alerts
        top_alerts = (
            db.session.query(Alert.id)
            .filter_by(user=user, notify=False)
            .join(Alert.cve)
            .order_by(Cve.cvss3.desc())
            .limit(10)
            .all()
        )

        # Then we convert this list of ID in a list of objects
        top_alerts = [alert[0] for alert in top_alerts]
        top_alerts = db.session.query(Alert).filter(Alert.id.in_(top_alerts)).all()

        # List of vendors/products per alert
        alerts_sorted = {}
        for alert in top_alerts:
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

        # Get the vendors and products of all alerts
        all_vendors_products = []
        for alert in alerts:
            all_vendors_products.extend(
                sorted(
                    list(set(alert.details["vendors"]))
                    + list(set(alert.details["products"]))
                )
            )

        # Remove duplicates
        all_vendors_products = sorted(list(set(all_vendors_products)))

        # Humanize it for the mail title
        all_vendors_products_humanized = list(
            map(_humanize_filter, all_vendors_products)
        )

        # Create the report
        report = Report(user=user, alerts=alerts, details=all_vendors_products)
        db.session.add(report)
        db.session.commit()

        logger.info("Report {0} created.".format(report.id))

        if not user.enable_notifications:
            logger.info(
                "User {} do not want to receive email notifications, skip it.".format(
                    user.username
                )
            )
        else:
            alert_str = "alerts" if len(alerts) > 1 else "alert"
            subject = "{count} {alerts} on {vendors}".format(
                count=count_alerts,
                alerts=alert_str,
                vendors=", ".join(all_vendors_products_humanized),
            )
            user_manager.email_manager.send_user_report(
                user,
                **{
                    "subject": subject,
                    "total_alerts": count_alerts,
                    "alerts_sorted": alerts_sorted,
                    "report_public_link": report.public_link,
                }
            )
            logger.info("Mail sent for {}".format(user.email))

        # The alerts have been notified
        for alert in alerts:
            alert.notify = True
        db.session.commit()
