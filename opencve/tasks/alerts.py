from celery.utils.log import get_task_logger

from opencve.constants import PRODUCT_SEPARATOR, VULNERABLE_SEPARATOR
from opencve.extensions import cel, db
from opencve.models.alerts import Alert
from opencve.models.cve import Cve
from opencve.models.events import Event
from opencve.models.products import Product
from opencve.models.vendors import Vendor

logger = get_task_logger(__name__)


def filter_events(user, events):
    # Only keep the wanted events
    filtered_events = {
        e.type.code: e
        for e in events
        if e.type.code in user.filters_notifications["event_types"]
    }

    # Check if new vendors/products match the user's subscriptions
    if "first_time" in filtered_events.keys():

        # TODO: refactor with controllers.home::home (+tests)
        subscriptions = [v.name for v in user.vendors]
        subscriptions.extend(
            [f"{p.vendor.name}{PRODUCT_SEPARATOR}{p.name}" for p in user.products]
        )

        if not any(s in filtered_events["first_time"].details for s in subscriptions):
            del filtered_events["first_time"]

    return list(filtered_events.values())


@cel.task(name="HANDLE_ALERTS")
def handle_alerts():
    cel.app.app_context().push()

    logger.info("Checking for new alerts...")

    # Retrieve the CVE list for which events no reviewed exist.
    cves = Cve.query.filter(Cve.events.any(Event.review == False)).all()
    if not cves:
        logger.info("No CVE to review")
        return

    # Check each CVE, get its events and create alerts
    logger.info("Checking {} CVE containing event(s) no reviewed...".format(len(cves)))

    for cve in cves:
        users = {}
        events = Event.query.filter_by(cve=cve, review=False).all()
        logger.info(
            "{} contains {} events to review...".format(cve.cve_id, len(events))
        )

        # Save the subscribers for each vendor of the CVE
        for v in cve.vendors:

            # Product contains the separator
            if PRODUCT_SEPARATOR in v:
                vendor = Vendor.query.filter_by(
                    name=v.split(PRODUCT_SEPARATOR)[0]
                ).first()
                # Skip if vendor is duplicate for vulnerability identification
                if vendor is None:
                    continue
                product = Product.query.filter_by(
                    name=v.split(PRODUCT_SEPARATOR)[1], vendor_id=vendor.id
                ).first()
                # Skip if product is duplicate for vulnerability identification
                if product is None:
                    continue
                for user in product.users:
                    if user not in users.keys():
                        users[user] = {"products": [], "vendors": []}
                    # User only wants notification for alerts where subscriptions are marked as vulnerable
                    if (
                            "vulnerable" in user.filters_notifications
                            and VULNERABLE_SEPARATOR in product.name
                    ):
                        users[user]["products"].append(
                            product.name.replace(VULNERABLE_SEPARATOR, "")
                        )
                    # User wants all notifications for subscriptions independent independent of vulnerability
                    elif (
                            "vulnerable" not in user.filters_notifications
                            and VULNERABLE_SEPARATOR not in product.name
                    ):
                        users[user]["products"].append(product.name)
            # Vendor
            else:
                vendor = Vendor.query.filter_by(name=v).first()
                # Skip if v is duplicate of vendor to identify vulnerability
                if vendor is None:
                    continue
                for user in vendor.users:
                    if user not in users.keys():
                        users[user] = {"products": [], "vendors": []}
                    users[user]["vendors"].append(vendor.name)

        # No users concerned
        if not users:
            logger.info("No users to alert.")
            for event in events:
                event.review = True
            db.session.commit()
            continue

        # Users need to be alerted
        logger.info("{} users found, creating the alerts...".format(len(users)))

        for user, details in users.items():

            # Filter by CVSS v3 score
            cvss_score = cve.cvss3

            if cvss_score and cvss_score < user.filters_notifications["cvss"]:
                logger.info(
                    "Skip alert for {0} because of CVSSv3 filter ({1} < {2})".format(
                        user.username, cvss_score, user.filters_notifications["cvss"]
                    )
                )
                continue

            # Keep the wanted filter by user
            events_copy = list(events)
            events_copy = filter_events(user, events_copy)

            if not events_copy:
                logger.info(
                    "No event matches the filters for {0}".format(user.username)
                )
            else:
                logger.info(
                    "Events match for {0} ({1})".format(
                        user.username, ",".join(e.type.code for e in events_copy)
                    )
                )

                # We add the filters in the details
                details["filters"] = [e.type.code for e in events_copy]

                # An alert is composed of a CVE, events for that CVE,
                # and details including vendors and products.
                alert = Alert(
                    user=user, cve=cve, details=details, events=events, notify=False
                )
                db.session.add(alert)
                db.session.commit()

                logger.info(
                    "Alert created for {} (ID: {})".format(user.username, alert.id)
                )

        # We can review the events
        for event in events:
            event.review = True
        db.session.commit()
