import pathlib
from unittest.mock import PropertyMock, patch

import git
import pytest
from airflow.exceptions import AirflowException

from includes.operators.fetch_operator import GitFetchOperator
from utils import TestRepo


def _make_tracked_clone(tests_path, tmp_path, tmp_path_factory):
    """
    Bare origin + consumer clone with origin/main (or master) tracking configured.
    """
    bare_path = tmp_path / "origin.git"
    git.Repo.init(bare_path, bare=True)

    publisher = TestRepo("example", tests_path, tmp_path_factory)
    branch = publisher.repo.active_branch.name
    publisher.repo.create_remote("origin", str(bare_path))
    publisher.repo.remotes.origin.push(refspec=f"{branch}:{branch}")

    clone_path = tmp_path / "consumer"
    git.Repo.clone_from(str(bare_path), clone_path, branch=branch)

    return clone_path, publisher, branch


@patch("includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock)
def test_fetch_operator_repo_path_not_exists(mock):
    """GitFetchOperator fails when the configured repository path has no .git directory."""
    mock.return_value = {"mitre": "/foo/bar"}
    operator = GitFetchOperator(task_id="fetch_test", kind="mitre")
    message = "Repository /foo/bar seems empty or broken"
    with pytest.raises(AirflowException, match=message):
        operator.execute({})


@patch("git.Repo.remotes", new_callable=PropertyMock)
def test_fetch_operator_repo_no_remotes(mock, tests_path, tmp_path_factory):
    """GitFetchOperator fails when the local repository has no git remotes configured."""
    mock.return_value = []

    repo = TestRepo("", tests_path, tmp_path_factory)
    with patch(
        "includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock
    ) as mock_paths:
        mock_paths.return_value = {"mitre": repo.repo_path}

        operator = GitFetchOperator(task_id="fetch_test", kind="mitre")

        message = r"Repository .* has no remote"
        with pytest.raises(AirflowException, match=message):
            operator.execute({})


@patch("includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock)
def test_fetch_operator_no_change_when_remote_is_current(
    mock_paths, tests_path, tmp_path, tmp_path_factory, caplog
):
    """GitFetchOperator leaves HEAD unchanged and logs when origin already matches the clone."""
    clone_path, _, _ = _make_tracked_clone(tests_path, tmp_path, tmp_path_factory)
    mock_paths.return_value = {"kb": clone_path}

    repo_before = git.Repo(clone_path)
    head_before = repo_before.head.commit

    operator = GitFetchOperator(task_id="fetch_test", kind="kb")
    operator.execute({})

    repo_after = git.Repo(clone_path)
    assert repo_after.head.commit == head_before
    assert "No change detected" in caplog.text


@patch("includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock)
def test_fetch_operator_fetches_and_resets_to_remote(
    mock_paths, tests_path, tmp_path, tmp_path_factory, caplog
):
    """GitFetchOperator advances HEAD to match origin after new commits are pushed to the remote."""
    clone_path, publisher, branch = _make_tracked_clone(
        tests_path, tmp_path, tmp_path_factory
    )
    mock_paths.return_value = {"kb": clone_path}

    consumer = git.Repo(clone_path)
    head_before = consumer.head.commit

    publisher.commit(["a/"], hour=1, minute=0)
    publisher.repo.remotes.origin.push(refspec=f"{branch}:{branch}")

    operator = GitFetchOperator(task_id="fetch_test", kind="kb")
    operator.execute({})

    consumer = git.Repo(clone_path)
    assert consumer.head.commit != head_before
    assert consumer.head.commit == publisher.repo.head.commit
    assert "New HEAD is" in caplog.text


@patch("includes.operators.KindOperator.REPOS_PATH", new_callable=PropertyMock)
def test_fetch_operator_resets_local_divergence(
    mock_paths, tests_path, tmp_path, tmp_path_factory
):
    """GitFetchOperator hard-resets the clone to origin and drops local commits and working tree changes."""
    clone_path, publisher, branch = _make_tracked_clone(
        tests_path, tmp_path, tmp_path_factory
    )
    mock_paths.return_value = {"kb": clone_path}

    publisher.commit(["a/"], hour=1, minute=0)
    publisher.repo.remotes.origin.push(refspec=f"{branch}:{branch}")

    consumer = git.Repo(clone_path)
    (pathlib.Path(clone_path) / "local-only.txt").write_text("dirty")
    consumer.index.add(["local-only.txt"])
    consumer.index.commit(
        "local commit",
        author=git.Actor("test", "test@example.com"),
        committer=git.Actor("test", "test@example.com"),
    )
    assert consumer.head.commit != publisher.repo.head.commit

    GitFetchOperator(task_id="fetch_test", kind="kb").execute({})

    consumer = git.Repo(clone_path)
    assert consumer.head.commit == publisher.repo.head.commit
    assert not (pathlib.Path(clone_path) / "local-only.txt").exists()
