import re

import arrow
from psycopg2.extras import Json

from constants import SQL_PROCEDURES
from events.mitre import MitreEvents
from utils import run_sql
from includes.handlers import DiffHandler


class MitreHandler(DiffHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = "mitre"

    def validate_files(self):
        # cves/2015/1000xxx/CVE-2015-1000000.json
        # cves/2023/23xxx/CVE-2023-23002.json
        # cves/2009/3xxx/CVE-2009-3005.json
        regex = r"cves\/\d{4}\/.+\/CVE-.*.json"
        return re.match(regex, self.path)

    def get_description(self):
        cna = self.right["containers"]["cna"]
        descriptions = cna.get("descriptions") or cna["rejectedReasons"]

        # In case of multiple languages, keep the EN one
        if len(descriptions) > 1:
            descriptions = [d for d in descriptions if d["lang"] in ("en", "en-US")]
        description = descriptions[0]["value"]

        return description

    @staticmethod
    def get_dates(metadata):
        # Rejected CVEs doesn't have published date
        cve_created = metadata.get("datePublished") or metadata["dateReserved"]
        cve_created_utc = arrow.get(cve_created).to("utc").datetime.isoformat()

        # Recent CVEs doesn't have updated date
        cve_updated = metadata.get("dateUpdated") or cve_created
        cve_updated_utc = arrow.get(cve_updated).to("utc").datetime.isoformat()

        return cve_created_utc, cve_updated_utc

    def execute(self):
        metadata = self.right["cveMetadata"]
        cve_id = metadata["cveId"]

        # Get the description and the dates of the CVE
        created_at, updated_at = self.get_dates(metadata)
        description = self.get_description()

        run_sql(
            query=SQL_PROCEDURES.get("mitre"),
            parameters={
                "cve": cve_id,
                "created": created_at,
                "updated": updated_at,
                "summary": description,
                "path": Json({"mitre": self.path}),
            },
        )

        self.create_change(cve_id, MitreEvents)
