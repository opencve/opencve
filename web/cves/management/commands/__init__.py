import time
from contextlib import contextmanager

from django.conf import settings
from django.core.management.base import BaseCommand as DjangoBaseCommand


class BaseCommand(DjangoBaseCommand):
    kb_path = settings.KB_REPO_PATH

    procedures = {
        "mitre": "CALL mitre_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(path)s);",
        "nvd": "CALL nvd_upsert(%(cve)s, %(created)s, %(updated)s, %(cvss)s, %(vendors)s, %(cwes)s, %(path)s);",
    }

    def error(self, message, ending=None):
        self.stdout.write(f"[error] {message}", ending=ending)

    def info(self, message, ending=None):
        self.stdout.write(f"{message}", ending=ending)

    def bold(self, message):
        return self.style.MIGRATE_LABEL(message)

    def blue(self, message):
        return self.style.MIGRATE_HEADING(message)

    @contextmanager
    def timed_operation(self, start_msg, end_msg=None):
        self.info(f"{start_msg}...")
        start = time.time()
        yield

        if not end_msg:
            end_msg = "Done"

        elapsed_time = f"{round(time.time() - start, 3)}s"
        self.info(f"{end_msg} in {self.style.MIGRATE_LABEL(elapsed_time)}")
