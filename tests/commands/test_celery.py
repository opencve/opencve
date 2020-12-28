from unittest.mock import patch

from opencve.commands.celery import beat, worker


@patch("opencve.commands.webserver.os.execvp")
def test_celery_worker_command(mock_execvp, app):
    mock_execvp.return_value = True
    runner = app.test_cli_runner()

    # Without arguments
    runner.invoke(worker, [])
    mock_execvp.assert_called_with(
        "celery", ["celery", "worker", "-A", "opencve.app:cel"]
    )

    # With custom arguments
    runner.invoke(worker, ["-l", "info"])
    mock_execvp.assert_called_with(
        "celery", ["celery", "worker", "-A", "opencve.app:cel", "-l", "info"]
    )


@patch("opencve.commands.webserver.os.execvp")
def test_celery_beat_command(mock_execvp, app):
    mock_execvp.return_value = True
    runner = app.test_cli_runner()

    # Without arguments
    runner.invoke(beat, [])
    mock_execvp.assert_called_with(
        "celery", ["celery", "beat", "-A", "opencve.app:cel"]
    )

    # With custom arguments
    runner.invoke(beat, ["-l", "info"])
    mock_execvp.assert_called_with(
        "celery", ["celery", "beat", "-A", "opencve.app:cel", "-l", "info"]
    )
