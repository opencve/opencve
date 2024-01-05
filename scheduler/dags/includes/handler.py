import json
import os
import uuid
import re

from psycopg2.extras import Json

from includes.constants import KB_LOCAL_REPO
from includes.utils import format_cve_payload


class DiffHandler:
    def __init__(self, commit, diff):
        self.commit = commit
        self.diff = diff
        self._path = None
        self._data = None
        self._type = None

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
    def cve_id(self):
        return self.path.split("/")[1]

    @property
    def diff_type(self):
        if re.search(r"CVE-\d{4}-\d{4,7}", self.filename):
            return "cve"

        if self.path.split("/")[-2] == "changes":
            return "change"

        return None

    @property
    def data(self):
        if not self._data:
            # We can use b_blob part of diff as the KB is an append-only repo
            self._data = json.loads(
                self.diff.b_blob.data_stream.read().decode("utf-8")
            )
        return self._data

    def is_new_file(self):
        return self.diff.change_type == "A"

    def is_cve_file(self):
        return self.diff_type == "cve"

    def is_change_file(self):
        return self.diff_type == "change"

    def format_cve(self):
        data = format_cve_payload(self.data)
        data["cve"] = self.cve_id
        return data

    def format_change(self):
        data = self.data
        data["updated"] = data["created"]
        data["change"] = str(uuid.uuid4())
        data["cve"] = self.cve_id
        data["file_path"] = self.path
        data["commit_hash"] = self.commit.hexsha
        data["event_types"] = Json([e["type"] for e in data["events"]])
        return data
