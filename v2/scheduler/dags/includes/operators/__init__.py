import pathlib

from airflow.exceptions import AirflowException
from airflow.models import Variable
from airflow.models.baseoperator import BaseOperator


class KindOperator(BaseOperator):
    def __init__(self, kind: str, **kwargs) -> None:
        super().__init__(**kwargs)
        if kind not in (
            "mitre",
            "nvd",
        ):
            raise AirflowException(f"Kind {kind} is not supported")
        self.kind = kind

    def get_repo_path(self):
        key = f"{self.kind}_repo_path"
        repo_path = Variable.get(key, default_var=None)
        if not repo_path:
            raise AirflowException(f"Variable {key} not found")
        return pathlib.Path(repo_path)
