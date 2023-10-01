import logging
import pathlib

import git
from airflow.exceptions import AirflowException
from airflow.models.baseoperator import BaseOperator

from utils import get_repo_path

logger = logging.getLogger(__name__)


class FetcherOperator(BaseOperator):
    def __init__(self, kind: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.kind = kind
        self.repo_path = get_repo_path(self.kind)

    def execute(self, context):
        if not pathlib.Path.exists(self.repo_path / ".git"):
            raise AirflowException(
                f"The repository {self.repo_path} seems empty or broken, you need to clone it first."
            )

        # Check if remotes is well configured
        repo = git.Repo(self.repo_path)
        remotes = repo.remotes
        if not remotes:
            raise AirflowException(f"Repo {self.repo_path} has no remote.")

        # Pull the last changes
        last_commit = repo.head.commit
        logger.info(f"Local HEAD is {last_commit}")
        logger.info(f"Pulling last changes from {self.repo_path}...")
        repo.remotes.origin.pull("main")

        if last_commit == repo.head.commit:
            logger.info(f"No change detected")
            return

        logger.info(f"New HEAD is {repo.head.commit})")
