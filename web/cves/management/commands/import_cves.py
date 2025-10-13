import glob
import json
import pathlib

from django.conf import settings
from django.db import connection
from psycopg2.extras import Json

from opencve.commands import BaseCommand


class Command(BaseCommand):
    KB_PATH = settings.KB_REPO_PATH
    CVE_UPSERT_PROCEDURE = """
    CALL cve_upsert(
        %(cve)s,
        %(created)s,
        %(updated)s,
        %(description)s,
        %(title)s,
        %(metrics)s,
        %(vendors)s,
        %(weaknesses)s,
        %(changes)s
    );
    """

    def call_procedure(self, params):
        with connection.cursor() as cursor:
            cursor.execute(self.CVE_UPSERT_PROCEDURE, params)

    def kb_repo_exist(self):
        return pathlib.Path.exists(pathlib.Path(self.KB_PATH))

    def insert_cve(self, path):
        with open(path) as f:
            cve = json.load(f)

        cve_data = cve.get("opencve") or {}

        def data_of(key, default=None):
            v = cve_data.get(key) or {}
            return v.get("data") if isinstance(v, dict) else default

        created = data_of("created")
        if not created:
            self.stdout.write(
                self.style.WARNING(f"Skipping {cve.get('cve','<unknown>')}: missing 'created' date")
            )
            return

        params = dict(
            cve_data,
            **{
                "cve": cve.get("cve"),
                "created": created,
                "updated": data_of("updated"),
                "description": data_of("description", ""),
                "title": data_of("title", cve.get("cve", "")),
                "metrics": Json(cve_data.get("metrics") or {}),
                "vendors": Json(data_of("vendors", [])),
                "weaknesses": Json(data_of("weaknesses", [])),
                "changes": Json([]),
            },
        )

        self.call_procedure(params)

    def handle(self, *args, **options):
        if not self.kb_repo_exist():
            self.error("The OpenCVE KB repository has to be cloned first")
            return

        self.info(f"Parsing the OpenCVE KB repository ({self.blue(self.KB_PATH)})")
        files = glob.glob(self.KB_PATH + "/**/CVE*.json", recursive=True)
        msg = f"Found {self.blue(len(files))} CVEs, adding them in database"

        with self.timed_operation(msg):
            for path in sorted(files):
                self.insert_cve(path)