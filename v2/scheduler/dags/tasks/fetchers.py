import logging
import pathlib

import git
from airflow.decorators import task
from airflow.exceptions import AirflowException

from constants import NVD_LOCAL_REPO, MITRE_LOCAL_REPO

logger = logging.getLogger(__name__)


def git_pull(local_repo):
    if not pathlib.Path.exists(local_repo / ".git"):
        raise AirflowException(
            f"The repository {local_repo} seems empty or broken, you need to clone it first."
        )

    # Check if remotes is well configured
    repo = git.Repo(local_repo)
    remotes = repo.remotes
    if not remotes:
        raise AirflowException(f"Repo {local_repo} has no remote.")

    # Pull the last changes
    last_commit = repo.head.commit
    logger.info(f"Local HEAD is {last_commit}")
    logger.info(f"Pulling last changes from {local_repo}...")
    repo.remotes.origin.pull("main")

    if last_commit == repo.head.commit:
        logger.info(f"No change detected")
        return

    logger.info(f"New HEAD is {repo.head.commit})")


@task
def fetch_mitre():
    git_pull(MITRE_LOCAL_REPO)


@task
def fetch_nvd():
    git_pull(NVD_LOCAL_REPO)
