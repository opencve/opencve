from datetime import timedelta

import redis
from redis.lock import Lock
from celery import chain
from celery.schedules import crontab
from celery.utils.log import get_task_logger

from opencve.extensions import cel
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.events import handle_events
from opencve.tasks.reports import handle_reports

logger = get_task_logger(__name__)


# Celery Beat configuration
CELERYBEAT_SCHEDULE = {}

# Periodic CVE check
CELERYBEAT_SCHEDULE["cve-updates-15-mn"] = {
    "task": "CVE_UPDATES",
    "schedule": timedelta(minutes=15),
}

# Periodic Reports cleanup
CELERYBEAT_SCHEDULE["reports-cleanup-daily"] = {
    "task": "REPORTS_CLEANUP",
    "schedule": crontab(minute=0, hour=0),
}


@cel.task(name="RELEASE_LOCK")
def release_lock():
    r = redis.Redis.from_url(cel.app.config.get("CELERY_LOCK_URL"))
    r.delete("cve_updates_lock")


@cel.task(name="CVE_UPDATES")
def cve_updates():
    cel.app.app_context().push()
    r = redis.Redis.from_url(cel.app.config.get("CELERY_LOCK_URL"))

    # The RELEASE_LOCK task release this lock after the chain completion or when
    # an error occurs, so we avoid parallel chains. A TTL of 12 hours is applied,
    # so the lock will be automatically released even if an unexpected problem occurs.
    acquired = Lock(r, "cve_updates_lock", timeout=3600 * 12, blocking=False).acquire()

    if not acquired:
        logger.info("Lock not acquired, skipping.")
        return False

    signature = chain(
        handle_events.si(), handle_alerts.si(), handle_reports.si(), release_lock.si()
    )
    signature.apply_async(link_error=release_lock.si())
