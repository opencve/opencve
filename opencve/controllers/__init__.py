from pathlib import Path

from flask import send_from_directory
from flask import current_app as app

from opencve.controllers.main import main


@main.route("/favicon.ico")
def favicon():
    return send_from_directory(
        str(Path(app.root_path).resolve() / "static/img"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )
