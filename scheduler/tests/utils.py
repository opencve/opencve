import pathlib
import shutil

import git
import pendulum


class TestRepo:
    __test__ = False

    def __init__(self, path, tests_path, tmp_path_factory):
        self.data_path = tests_path / f"data/{path}"
        self.repo_path = tmp_path_factory.mktemp("data")
        self.repo = git.Repo.init(self.repo_path)
        self.author = git.Actor("opencve", "opencve@example.com")
        self.initialize()

    def initialize(self):
        open(self.repo_path / ".gitkeep", "w").close()
        self.repo.git.add(A=True)

        return self.repo.index.commit(
            f"Initial Commit",
            author=self.author,
            committer=self.author,
            commit_date=pendulum.datetime(2024, 1, 1, 0, 0, tz="UTC"),
            author_date=pendulum.datetime(2024, 1, 1, 0, 0, tz="UTC"),
        )

    def commit(self, paths, hour, minute):
        for path in paths:
            if str(path).endswith("/"):
                shutil.copytree(
                    self.data_path / path, self.repo_path, dirs_exist_ok=True
                )
            else:
                if "/" in str(path):
                    folder = "/".join(path.split("/")[:-1])
                    pathlib.Path(self.repo_path / pathlib.Path(folder)).mkdir(
                        parents=True, exist_ok=True
                    )
                shutil.copy(self.data_path / path, self.repo_path / path)

        date = pendulum.datetime(2024, 1, 1, hour, minute, tz="UTC")
        self.repo.git.add(A=True)
        return self.repo.index.commit(
            f"Updates for {hour}:{minute}",
            author=self.author,
            committer=self.author,
            commit_date=date,
            author_date=date,
        )
