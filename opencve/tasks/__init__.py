from datetime import timedelta

from celery import chain

from opencve.extensions import cel
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.events import handle_events
from opencve.tasks.reports import handle_reports

# Celery Beat configuration
CELERYBEAT_SCHEDULE = {}

# Periodic CVE check
CELERYBEAT_SCHEDULE["cve-updates-15-mn"] = {
    "task": "CVE_UPDATES",
    "schedule": timedelta(minutes=15),
}


@cel.task(bind=True, name="CVE_UPDATES")
def cve_updates(self):
    return chain(handle_events.si(), handle_alerts.si(), handle_reports.si())()
