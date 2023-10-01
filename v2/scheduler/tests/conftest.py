import pathlib
import shutil
import git

import pendulum
import pytest


@pytest.fixture(scope="session")
def tests_path():
    return pathlib.Path(__file__).parent.resolve()


@pytest.fixture(scope="session")
def cvelistv5_repo(tests_path, tmp_path_factory):
    data_path = tests_path / "data/cvelistV5"
    repo_path = tmp_path_factory.mktemp("cvelistV5")
    repo_path = pathlib.Path("/tmp/foo")

    repo = git.Repo.init(repo_path)
    author = git.Actor("opencve", "opencve@example.com")
    committer = git.Actor("opencve", "opencve@example.com")

    def commit(day, hour, minute):
        date = pendulum.datetime(2023, 1, day, hour, minute, tz="UTC")
        repo.git.add(A=True)
        repo.index.commit(
            "update",
            author=author,
            committer=committer,
            commit_date=date,
            author_date=date
        )

    # Initial commit
    open(repo_path / ".gitkeep", "w").close()
    commit(day=1, hour=0, minute=30)

    # First update (Sun Jan 1 01:30:00 2023 +0000)
    #  cves/2023/4xxx/CVE-2023-4785.json | 178 ++++++++++++++++++++++++++++++++++++++++++++++
    #  1 file changed, 178 insertions(+)
    shutil.copytree(data_path / "a", repo_path, dirs_exist_ok=True)
    commit(day=1, hour=1, minute=30)

    # Second update (Sun Jan 1 01:40:00 2023 +0000)
    #  cves/2023/4xxx/CVE-2023-4785.json |   2 +-
    #  cves/2023/5xxx/CVE-2023-5301.json | 129 ++++++++++++++++++++++++++++++++++++++++++++++
    #  2 files changed, 130 insertions(+), 1 deletion(-)
    shutil.copytree(data_path / "b", repo_path, dirs_exist_ok=True)
    commit(day=1, hour=1, minute=40)

    # Third update (Sun Jan 1 02:10:00 2023 +0000)
    #  cves/2023/5xxx/CVE-2023-5301.json |   6 +++
    #  cves/2023/5xxx/CVE-2023-5305.json | 126 ++++++++++++++++++++++++++++++++++++++++++++++
    #  2 files changed, 132 insertions(+)
    shutil.copytree(data_path / "c", repo_path, dirs_exist_ok=True)
    commit(day=1, hour=2, minute=10)

    return repo
