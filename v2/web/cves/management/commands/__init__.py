import pathlib
import time
from contextlib import contextmanager

from django.conf import settings
from django.core.management.base import BaseCommand as DjangoBaseCommand
from django.db import connection


class BaseCommand(DjangoBaseCommand):
    mitre_path = settings.MITRE_REPO_PATH
    nvd_path = settings.NVD_REPO_PATH
    procedures = {
        "cves": "CALL cve_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(cvss)s, %(vendors)s, %(cwes)s, %(source)s);",
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

    def repos_exist(self, paths):
        if not all(
            [
                pathlib.Path.exists(pathlib.Path(p) / ".git")
                for p in paths
            ]
        ):
            return False
        return True

    def call_procedure(self, procedure, params):
        with connection.cursor() as cursor:
            cursor.execute(self.procedures.get(procedure), params)
