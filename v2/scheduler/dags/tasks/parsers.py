import importlib
import logging

import git
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.models import Variable

from constants import NVD_LOCAL_REPO, MITRE_LOCAL_REPO

logger = logging.getLogger(__name__)


def parse_commits(repo_type, repo_name, variable):
    repo = git.Repo(repo_name)

    # This is the first execution, we iterate over all commits
    last_commit_hash = Variable.get(variable, default_var=None)
    if not last_commit_hash:
        last_commit_hash = repo.git.rev_list("--max-parents=0", "HEAD")

    # List of commits from last known to HEAD
    commits = [c for c in repo.iter_commits(rev=f"{last_commit_hash}..HEAD")]
    if not commits:
        logger.info(f"No diff to parse")
        raise AirflowSkipException

    logger.info(
        f"Analysing {len(commits)} commit(s) (from {last_commit_hash} to {repo.head.commit.hexsha})"
    )

    for commit in commits[::-1]:
        # List the diffs between last analysed commit and current one
        diffs = repo.commit(last_commit_hash).diff(commit)

        # Parse the diffs and execute their handler
        logger.info(f"Parsing {len(diffs)} diffs (from {last_commit_hash} to {commit})")
        for diff in diffs:
            getattr(
                importlib.import_module("handlers"),
                f"{repo_type.capitalize()}Handler",
            )(commit, diff).handle()

        # Save the last know commit
        last_commit_hash = commit
        Variable.set(variable, last_commit_hash)


@task
def parse_mitre():
    parse_commits("mitre", MITRE_LOCAL_REPO, "mitre_last_commit")


@task
def parse_nvd():
    parse_commits("nvd", NVD_LOCAL_REPO, "nvd_last_commit")
