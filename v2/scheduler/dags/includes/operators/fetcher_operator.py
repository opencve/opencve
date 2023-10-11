import logging
import pathlib

import git
from airflow.exceptions import AirflowException

from includes.operators import KindOperator

logger = logging.getLogger(__name__)


class FetcherOperator(KindOperator):
    def execute(self, context):
        repo_path = self.get_repo_path()

        if not pathlib.Path.exists(repo_path / ".git"):
            raise AirflowException(f"Repository {repo_path} seems empty or broken")

        # Check if remotes is well configured
        repo = git.Repo(repo_path)
        remotes = repo.remotes
        if not remotes:
            raise AirflowException(f"Repository {repo_path} has no remote")

        # Pull the last changes
        last_commit = repo.head.commit
        logger.info(f"Local HEAD is {last_commit}")
        logger.info(f"Pulling last changes from {repo_path}...")
        repo.remotes.origin.pull("main")

        if last_commit == repo.head.commit:
            logger.info("No change detected")
            return

        logger.info(f"New HEAD is {repo.head.commit})")
