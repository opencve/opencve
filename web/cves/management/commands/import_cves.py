import glob
import json
import pathlib

from django.conf import settings
from django.db import connection
from psycopg2.extras import Json

from opencve.commands import BaseCommand

import re
from datetime import datetime, timezone

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
        
        cve_data = cve.get("opencve", {})
        cve_id = cve.get("cve")
        
        created = cve_data.get("created", {}).get("data")
        if not created:
            created = self.fake_cve_date(cve_id)
        
        updated = cve_data.get("updated", {}).get("data")
        if not updated:
            updated = self.fake_cve_date(cve_id)
        
        params = dict(
            cve_data,
            **{
                "cve": cve_id,
                "created": created,
                "updated": updated,
                "description": cve_data.get("description", {}).get("data", ""),
                "title": cve_data.get("title", {}).get("data", ""),
                "metrics": Json(cve_data.get("metrics", {})),
                "vendors": Json(cve_data.get("vendors", {}).get("data", [])),
                "weaknesses": Json(cve_data.get("weaknesses", {}).get("data", [])),
                "changes": Json([]),
            },
        )
        self.call_procedure(params)

    def fake_cve_date(self, cve):
        m = re.match(r'^\s*CVE-(\d{4})-\d+', cve or '', flags=re.IGNORECASE)
        if not m:
            return None
        year = int(m.group(1))
        return datetime(year, 1, 1, tzinfo=timezone.utc)
        

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
