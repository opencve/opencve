import importlib

import git
from airflow.exceptions import AirflowException, AirflowSkipException

from includes.operators import KindOperator


class ParserOperator(KindOperator):
    def handle(self, commit, diffs):
        handler_mod = importlib.import_module(f"includes.handlers.{self.kind}")
        handler_name = f"{self.kind.capitalize()}Handler"

        for diff in diffs:
            getattr(handler_mod, handler_name)(self.log, commit, diff).handle()

    def execute(self, context):
        repo_path = self.get_repo_path()
        start = context.get("data_interval_start")
        end = context.get("data_interval_end")

        if not all([start, end]):
            raise AirflowException("Start and end intervals must be set")

        # Each DagRun only parses its associated commits (schedule is hourly).
        # We'll use the interval dates to list commits during this period, but
        # git log --before and --after options are both included, so we need to
        # subtract 1 second to the end date in order to avoid duplicates commits.
        end = end.subtract(seconds=1)

        self.log.info("Listing the commits between %s and %s", start, end)
        repo = git.Repo(repo_path)
        commits = list(repo.iter_commits(after=start, before=end, reverse=True))

        if not commits:
            self.log.info("No commit found, skip the task")
            return

        # Iterate over all commits
        self.log.info(
            "Found %s commit(s), from %s to %s",
            str(len(commits)),
            commits[0],
            commits[-1],
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

            # The parsed repos were created long before the scheduler is executed
            # (for instance the cvelistV5 repo was created in Feb 2022). So the
            # normal usage is to check diffs between 2 existing commits.
            if not commit.parents:
                raise AirflowException(
                    "The first commit can't be used by the scheduler. "
                    "Please follow the expected usage of OpenCVE."
                )

            # Launch the diffs handlers
            diffs = commit.parents[0].diff(commit)
            self.handle(commit, diffs)
