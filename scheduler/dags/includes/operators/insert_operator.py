import pathlib
import json
from typing import List

from git.objects.commit import Commit
from git.repo import Repo
from pendulum.datetime import DateTime
from airflow.exceptions import AirflowException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.models.baseoperator import BaseOperator

from includes.constants import KB_LOCAL_REPO, CHANGE_UPSERT_PROCEDURE, CVE_UPSERT_PROCEDURE
from includes.handler import DiffHandler
from includes.utils import format_cve_payload


class ProcessKbOperator(BaseOperator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.hook = PostgresHook(postgres_conn_id="opencve_postgres")

    def list_commits(self, start: DateTime, end: DateTime) -> List[Commit]:
        self.log.info("Reading %s repository", KB_LOCAL_REPO)
        repo_path = pathlib.Path(KB_LOCAL_REPO)

        if not all([start, end]):
            raise AirflowException("Start and end intervals must be set")

        # Each DagRun only parses its associated commits (schedule is hourly).
        # We'll use the interval dates to list commits during this period, but
        # git log --before and --after options are both included, so we need to
        # subtract 1 second to the end date in order to avoid duplicates commits.
        end = end.subtract(seconds=1)

        self.log.info("Listing commits between %s and %s", start, end)
        repo = Repo(repo_path)
        commits = list(repo.iter_commits(after=start, before=end, reverse=True))

        if not commits:
            self.log.info("No commit found, skip the task")
            return []

        # Iterate over all commits
        self.log.info(
            "Found %s commit(s), from %s to %s",
            str(len(commits)),
            commits[0],
            commits[-1],
        )

        return commits

    @staticmethod
    def raise_if_no_parents(commit: Commit):
        """
        The parsed repos were created long before the scheduler is executed
        (for instance the MITRE repository was created in Feb 2022). So the
        normal usage is to check diffs between 2 existing commits.
        """
        if not commit.parents:
            raise AirflowException(
                "The first commit can't be used by the scheduler. "
                "Please follow the expected usage of OpenCVE."
            )

    def process_commit(self, commit: Commit):
        """
        This method check the diffs of a commit and launch the CVE
        procedure to create the CVEs data in database.
        It returns the list of processed CVE and the changes to apply.
        """
        data = {"cves": [], "changes": {}}

        for diff in commit.parents[0].diff(commit):
            handler = DiffHandler(commit, diff)
            self.log.info(f"Checking file %s (%s)", handler.path, handler.diff.change_type)

            if handler.diff.change_type == "D":
                continue

            if handler.is_cve_file():
                self.log.info(f"Inserting %s data", handler.cve_id)
                self.hook.run(sql=CVE_UPSERT_PROCEDURE, parameters=handler.format_cve())
                data["cves"].append(handler.cve_id)

            elif handler.is_change_file():
                data["changes"][handler.cve_id] = []
                data["changes"][handler.cve_id].append(handler.format_change())
            else:
                # We'll probably add new procedure later
                # (the advisories for instance)
                continue

        return data

    def execute(self, context):
        commits = self.list_commits(
            start=context.get("data_interval_start"),
            end=context.get("data_interval_end")
        )

        for commit in commits:
            commit_stats = commit.stats.total
            self.log.info(
                "Analysing %s with %s files changed, %s insertions(+), %s deletions(-)",
                commit,
                commit_stats.get("files"),
                commit_stats.get("insertions"),
                commit_stats.get("deletions"),
            )
            self.raise_if_no_parents(commit)
            commit_results = self.process_commit(commit)

            # Normally all CVEs exist before checking their changes, but it's possible that
            # a DagRun has been failed or cancelled for any reasons. In this case a commit
            # can include a change on a CVE declared in a previous commit. This part of
            # the code avoid this problem by recreating in any case the CVE data.
            changes = commit_results["changes"]
            processed_cves = commit_results["cves"]

            self.log.info(f"Analysing %s changes", str(len(changes)))

            for cve_id, payloads in changes.items():

                # Launch the CVE procedure before launching the Change one
                if cve_id not in processed_cves:

                    cve_kb = KB_LOCAL_REPO / cve_id.split("-")[1] / cve_id / f"{cve_id}.json"
                    with open(cve_kb) as f:
                        cve_data = json.load(f)

                    self.log.info(f"Inserting %s data", cve_id)
                    self.hook.run(sql=CVE_UPSERT_PROCEDURE, parameters=format_cve_payload(format_cve_payload(cve_data)))

                # Create the change and its events
                for payload in payloads:
                    self.hook.run(sql=CHANGE_UPSERT_PROCEDURE, parameters=payload)
