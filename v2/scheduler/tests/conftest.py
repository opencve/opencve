import json
import os
import pathlib
import shutil

import git
import pendulum
import pytest

# Override Airflow configuration during tests
os.environ["AIRFLOW__CORE__LOAD_DEFAULT_CONNECTIONS"] = "False"
os.environ["AIRFLOW__CORE__LOAD_EXAMPLES"] = "False"
os.environ["AIRFLOW__CORE__UNIT_TEST_MODE"] = "True"
os.environ["AIRFLOW_HOME"] = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(autouse=True, scope="session")
def reset_db():
    from airflow.utils import db

    db.resetdb()
    yield

    # Cleanup temp files generated during tests
    os.remove(os.path.join(os.environ["AIRFLOW_HOME"], "unittests.cfg"))
    os.remove(os.path.join(os.environ["AIRFLOW_HOME"], "unittests.db"))


@pytest.fixture(scope="session")
def tests_path():
    return pathlib.Path(__file__).parent.resolve()


class TestRepo:
    def __init__(self, kind, tests_path, tmp_path_factory):
        self.kind = kind
        self.data_path = tests_path / f"data/{self.kind}/repo"
        self.repo_path = tmp_path_factory.mktemp(self.kind)
        # self.repo_path = pathlib.Path("/tmp/foobar")
        self.repo = git.Repo.init(self.repo_path)
        self.author = git.Actor("opencve", "opencve@example.com")
        self.initialize()

    def initialize(self):
        open(self.repo_path / ".gitkeep", "w").close()
        self.commit("initial", day=1, hour=0, minute=30)

    def commit(self, folder, day, hour, minute):
        if folder != "initial":
            shutil.copytree(self.data_path / folder, self.repo_path, dirs_exist_ok=True)
        date = pendulum.datetime(2023, 1, day, hour, minute, tz="UTC")
        self.repo.git.add(A=True)
        self.repo.index.commit(
            folder,
            author=self.author,
            committer=self.author,
            commit_date=date,
            author_date=date,
        )


@pytest.fixture(scope="session")
def mitre_repo(tests_path, tmp_path_factory):
    repo = TestRepo("mitre", tests_path, tmp_path_factory)
    repo.commit("a", day=1, hour=1, minute=30)
    repo.commit("b", day=1, hour=1, minute=40)
    repo.commit("c", day=1, hour=2, minute=10)
    repo.commit("d", day=1, hour=3, minute=15)
    return repo


@pytest.fixture(scope="session")
def nvd_repo(tests_path, tmp_path_factory):
    repo = TestRepo("nvd", tests_path, tmp_path_factory)
    repo.commit("a", day=1, hour=1, minute=30)
    repo.commit("b", day=1, hour=1, minute=40)
    repo.commit("c", day=1, hour=2, minute=10)
    repo.commit("d", day=1, hour=3, minute=15)
    return repo


@pytest.fixture
def get_commit(mitre_repo, nvd_repo):
    def wrapper(kind, folder):
        repos = {"mitre": mitre_repo.repo, "nvd": nvd_repo.repo}
        repo = repos.get(kind)
        return [c for c in repo.iter_commits() if c.message == folder][0]

    return wrapper


@pytest.fixture
def get_diff(get_commit):
    def wrapper(kind, folder, index):
        commit = get_commit(kind, folder)
        return commit.parents[0].diff(commit)[index]

    return wrapper


@pytest.fixture(scope="session")
def open_file(tests_path):
    def wrapper(path):
        with open(tests_path / f"data/{path}", "r") as f:
            data = json.load(f)
        return data

    return wrapper
