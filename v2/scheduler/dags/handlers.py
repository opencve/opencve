import json
import logging
import uuid

import arrow
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.extras import Json

from constants import SQL_EVENTS, SQL_CVE
from utils import vendors_conf_to_flat, weaknesses_to_flat, run_sql
from nvd import NvdEvents

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
    def cve_name(self):
        # Example: 2023/CVE-2023-28640.json
        return self.path.split("/")[1].split(".")[0]

    @property
    def source(self):
        if not self._source:
            self._source = self.diff.b_path.split("/")[0]
        return self._source

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

    def create_change(self, cve_name, events):
        change_id = str(uuid.uuid4())
        parameters = {
            "cve": cve_name,
            "change_id": change_id,
            "path": self.path,
            "commit": str(self.commit),
            "events": Json(events),
            "created": arrow.get(self.commit.authored_date).datetime.isoformat(),
            "updated": arrow.get(self.commit.authored_date).datetime.isoformat(),
        }
        run_sql(query=SQL_EVENTS, parameters=parameters)

        # We'll reuse the list of changes in a next task of the DAG
        self.redis.sadd("changes_ids", change_id)

    def handle(self):
        logger.info(f"Analysing {self.diff.b_path} ({self.diff.change_type})")


class MitreHandler(DiffHandler):
    def handle(self):
        pass


class NvdHandler(DiffHandler):
    def handle(self):
        events = []

        if self.path == "last.json":
            return

        # Upsert the CVE
        try:
            source = {"nvd": self.path}

            # CVSS scores
            cvss2 = None
            cvss3 = None

            if "metrics" in self.right:
                if "cvssMetricV2" in self.right["metrics"]:
                    cvss2 = self.right["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]

                if "cvssMetricV3" in self.right["metrics"]:
                    cvss3 = self.right["metrics"]["cvssMetricV3"][0]["cvssData"]["baseScore"]

            # Created & updated dates
            created = arrow.get(self.right["published"]).to("utc").datetime.isoformat()
            updated = arrow.get(self.right["lastModified"]).to("utc").datetime.isoformat()

            run_sql(
                query=SQL_CVE,
                parameters={
                    "cve": self.right["id"],
                    "created": created,
                    "updated": updated,
                    "summary": self.right["descriptions"][0]["value"],
                    "cvss2": cvss2,
                    "cvss3": cvss3,
                    "vendors": Json(vendors_conf_to_flat(self.right.get("configurations"))),
                    "cwes": Json(weaknesses_to_flat(self.right.get("weaknesses"))),
                    "source": Json(source),
                },
            )
        except Exception as e:
            logger.error(self.right)

            # TODO: send a sentry
            raise e

        if self.is_new:
            events.append({"type": "new_cve", "details": {}})
        else:
            for event_cls in NvdEvents.__subclasses__():
                event = event_cls(self.left, self.right).execute()
                if event:
                    events.append(event)

        if events:
            self.create_change(self.cve_name, events)
