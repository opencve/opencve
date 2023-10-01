import json
import uuid

import arrow
from airflow.providers.redis.hooks.redis import RedisHook
from psycopg2.extras import Json

from constants import SQL_PROCEDURES
from utils import run_sql


class DiffHandler:
    def __init__(self, logger, commit, diff):
        self.logger = logger
        self.commit = commit
        self.diff = diff
        self.kind = None
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
            events.append({"type": f"new_{self.kind}", "details": {}})
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

            # We first create the change and its events, then we add it
            # in Redis to reuse it in a next task.
            # TODO: make the `change_events` procedure idempotent to avoid duplicated changes
            run_sql(query=SQL_PROCEDURES.get("events"), parameters=parameters)
            self.redis.sadd("changes_ids", change_id)

    def handle(self):
        if not self.validate_files():
            return
        self.logger.info(f"Checking %s (%s)", self.diff.b_path, self.diff.change_type)
        self.execute()

    def execute(self):
        raise NotImplemented

    def validate_files(self):
        raise NotImplemented
