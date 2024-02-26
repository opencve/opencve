import glob
import json
import pathlib

from django.db import connection
from psycopg2.extras import Json

from cves.management.commands import BaseCommand


class Command(BaseCommand):
    CVE_UPSERT_PROCEDURE = """
    CALL cve_upsert(
        %(cve)s, %(created)s, %(updated)s, %(description)s, %(title)s, %(metrics)s, %(vendors)s, %(weaknesses)s
    );
    """

    def call_procedure(self, params):
        with connection.cursor() as cursor:
            cursor.execute(self.CVE_UPSERT_PROCEDURE, params)

    def kb_repo_exist(self):
        return pathlib.Path.exists(pathlib.Path(self.kb_path))

    def insert_cve(self, path):
        with open(path) as f:
            cve = json.load(f)

        cve_data = cve.get("opencve")
        params = dict(
            cve_data,
            **{
                "metrics": Json(cve_data["metrics"]),
                "vendors": Json(cve_data["vendors"]),
                "weaknesses": Json(cve_data["weaknesses"]),
            },
        )
        self.call_procedure(params)

    def handle(self, *args, **options):
        if not self.kb_repo_exist():
            self.error("The OpenCVE KB repository has to be cloned first")
            return

        self.info(f"Parsing the OpenCVE KB repository ({self.blue(self.kb_path)})")
        files = glob.glob(self.kb_path + "/**/CVE*.json", recursive=True)
        msg = f"Found {self.blue(len(files))} CVEs, adding them in database"

        with self.timed_operation(msg):
            for path in sorted(files):
                self.insert_cve(path)
