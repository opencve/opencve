import json
import os

from includes.constants import KB_LOCAL_REPO
from psycopg2.extras import Json


class DiffHandler:
    def __init__(self, diff, commit_hash):
        self.diff = diff
        self.commit_hash = commit_hash
        self._path = None
        self._data = None

    @property
    def path(self):
        if not self._path:
            self._path = self.diff.b_path
        return self._path

    @property
    def full_path(self):
        return KB_LOCAL_REPO / self.path

    @property
    def filename(self):
        return os.path.basename(self.path)

    @property
    def data(self):
        if not self._data:
            # We can use b_blob part of diff as the KB is an append-only repo
            self._data = json.loads(self.diff.b_blob.data_stream.read().decode("utf-8"))
        return self._data

    def is_new_file(self):
        return self.diff.change_type == "A"

    def format_cve(self):
        data = self.data["opencve"]
        payload = {
            "cve": self.data["cve"],
            "created": data["created"]["data"],
            "updated": data["updated"]["data"],
            "description": data["description"]["data"],
            "title": data["title"]["data"],
            "metrics": Json(data["metrics"]),
            "vendors": Json(data["vendors"]["data"]),
            "weaknesses": Json(data["weaknesses"]["data"]),
        }

        changes = []
        for change in data.get("changes", []):
            changes.append(
                {
                    "change": change["id"],
                    "created": change["created"],
                    "updated": change["created"],
                    "file_path": self.path,
                    # Add the commit hash in each change, the `cve_upsert`
                    # procedure will only add the new ones with this clause:
                    # `ON CONFLICT (created_at, cve_id) DO NOTHING`
                    "commit_hash": self.commit_hash,
                    "event_types": [e["type"] for e in change["data"]],
                }
            )
        payload["changes"] = Json(changes)

        return payload
