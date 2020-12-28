from unittest.mock import patch

from opencve.commands.webserver import webserver


@patch("opencve.commands.webserver.os.execvp")
def test_webserver_command(mock_execvp, app):
    mock_execvp.return_value = True
    runner = app.test_cli_runner()

    # Without arguments
    runner.invoke(webserver, [])
    mock_execvp.assert_called_with("gunicorn", ["gunicorn", "opencve.app:app"])

    # With custom arguments
    runner.invoke(webserver, ["-b", "0.0.0.0:80"])
    mock_execvp.assert_called_with(
        "gunicorn", ["gunicorn", "-b", "0.0.0.0:80", "opencve.app:app"]
    )
