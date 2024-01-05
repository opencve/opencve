import pathlib

from airflow.exceptions import AirflowException
from airflow.models.baseoperator import BaseOperator

from includes.constants import KB_LOCAL_REPO, MITRE_LOCAL_REPO, NVD_LOCAL_REPO


class KindOperator(BaseOperator):
    def __init__(self, kind: str, **kwargs) -> None:
        super().__init__(**kwargs)
        if kind not in (
            "kb",
            "mitre",
            "nvd",
        ):
            raise AirflowException(f"Kind {kind} is not supported")
        self.kind = kind

    def get_repo_path(self):
        repo_path = {
            "kb": KB_LOCAL_REPO,
            "mitre": MITRE_LOCAL_REPO,
            "nvd": NVD_LOCAL_REPO
        }[self.kind]
        return pathlib.Path(repo_path)
