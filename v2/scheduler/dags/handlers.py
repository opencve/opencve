import json
import logging
import re
import uuid

import arrow
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.extras import Json

from constants import SQL_PROCEDURES
from events.nvd import NvdEvents
from events.mitre import MitreEvents
from utils import vendors_conf_to_flat, weaknesses_to_flat, run_sql

logger = logging.getLogger(__name__)


class DiffHandler:
    def __init__(self, commit, diff):
        self.commit = commit
        self.diff = diff
        self._path = None
        self._source = None
        self._left = None
        self._right = None
        self._redis = None

    @property
    def redis(self):
        if not self._redis:
            self._redis = RedisHook(redis_conn_id="opencve_redis").get_conn()
        return self._redis

    @property
    def is_new(self):
        return self.diff.change_type == "A"

    @property
    def path(self):
        if not self._path:
            self._path = self.diff.b_path
        return self._path

    @property
    def left(self):
        if not self._left:
            self._left = (
                json.loads(self.diff.a_blob.data_stream.read().decode("utf-8"))
                if self.diff.a_blob
                else None
            )
        return self._left

    @property
    def right(self):
        if not self._right:
            self._right = json.loads(
                self.diff.b_blob.data_stream.read().decode("utf-8")
            )
        return self._right

    def create_change(self, cve_id, diff_cls):
        events = []

        if self.is_new:
            events.append({"type": "new_cve", "details": {}})
        else:
            for event_cls in diff_cls.__subclasses__():
                event = event_cls(self.left, self.right).execute()
                if event:
                    events.append(event)

        if events:
            change_id = str(uuid.uuid4())
            parameters = {
                "cve": cve_id,
                "change_id": change_id,
                "path": self.path,
                "commit": str(self.commit),
                "events": Json(events),
                "created": arrow.get(self.commit.authored_date).datetime.isoformat(),
                "updated": arrow.get(self.commit.authored_date).datetime.isoformat(),
            }
            run_sql(query=SQL_PROCEDURES.get("events"), parameters=parameters)

            # We'll reuse the list of changes in a next task of the DAG
            self.redis.sadd("changes_ids", change_id)

    def handle(self):
        logger.info(f"Analysing {self.diff.b_path} ({self.diff.change_type})")
        if not self.validate_files():
            return
        self.execute()

    def execute(self):
        raise NotImplemented

    def validate_files(self):
        raise NotImplemented


class MitreHandler(DiffHandler):
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
                "source": Json({"mitre": self.path}),
            },
        )

        self.create_change(cve_id, MitreEvents)


class NvdHandler(DiffHandler):
    def validate_files(self):
        return not(self.path == "last.json")

    def get_data(self):
        """
        This method is the same as web/cves/management/commands/import_cves::get_nvd_sata
        """
        cve_data = {
            "vendors": vendors_conf_to_flat(self.right.get("configurations")),
            "cwes": weaknesses_to_flat(self.right.get("weaknesses")),
            "cvss": {"v20": None, "v30": None, "v31": None},
        }

        # Parse the CVE scores
        if "metrics" in cve_data:
            cvss_keys = {
                "v20": "cvssMetricV2",
                "v30": "cvssMetricV30",
                "v31": "cvssMetricV31",
            }
            for k, v in cvss_keys.items():
                if v in self.right.get("metrics"):
                    cve_data["cvss"][k] = self.right.get("metrics")[v][0]["cvssData"][
                        "baseScore"
                    ]
        return cve_data

    def execute(self):
        cve_data = self.get_data()

        # Created & updated dates
        created = arrow.get(self.right["published"]).to("utc").datetime.isoformat()
        updated = arrow.get(self.right["lastModified"]).to("utc").datetime.isoformat()

        run_sql(
            query=SQL_PROCEDURES.get("nvd"),
            parameters={
                "cve": self.right["id"],
                "created": created,
                "updated": updated,
                "cvss": Json(cve_data["cvss"]),
                "vendors": Json(cve_data["vendors"]),
                "cwes": Json(cve_data["cwes"]),
                "path": Json({"nvd": self.path}),
            }
        )

        self.create_change(self.right["id"], NvdEvents)
