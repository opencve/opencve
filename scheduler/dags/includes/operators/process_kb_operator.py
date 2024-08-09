from airflow.models.baseoperator import BaseOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook
from git.objects.commit import Commit

from includes.constants import CVE_UPSERT_PROCEDURE
from includes.handler import DiffHandler
from includes.utils import list_commits


class ProcessKbOperator(BaseOperator):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.hook = PostgresHook(postgres_conn_id="opencve_postgres")

    def process_diff(self, diff, commit_hash):
        handler = DiffHandler(diff, commit_hash)
        self.log.info("Checking file %s (%s)", handler.path, handler.diff.change_type)

        # Do nothing if it's a deletion
        if handler.diff.change_type == "D":
            return

        return handler.format_cve()

    def process_commit(self, commit: Commit):
        commit_hash = commit.hexsha

        for diff in commit.parents[0].diff(commit):
            cve_payload = self.process_diff(diff, commit_hash)

            self.log.info("Inserting %s data", cve_payload["cve"])
            self.hook.run(sql=CVE_UPSERT_PROCEDURE, parameters=cve_payload)

    def execute(self, context):
        commits = list_commits(
            logger=self.log,
            start=context.get("data_interval_start"),
            end=context.get("data_interval_end"),
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

            # The very first commit does not have parent, we
            # can't check the diff so we simply discard it.
            if not commit.parents:
                return

            self.process_commit(commit)
