import importlib
import pkgutil
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from opencve.api import api_bp
from opencve.context import _is_active
from opencve.controllers.main import main, welcome
from opencve.extensions import db
from opencve.settings import env_config


with open(Path(__file__).parent.resolve() / "VERSION", encoding="utf-8") as version:
    __version__ = version.readline().rstrip()


def not_found(e):
    """Handles 404 errors."""
    if request.path.startswith("/api"):
        return jsonify({"error": "Not found."}), 404
    return render_template("errors/404.html"), 404


def create_app(environment="production", custom_config={}):
    app = Flask(__name__)
    app.config.from_object(env_config[environment])

    # Customize configuration
    for conf, value in custom_config.items():
        app.config[conf] = value

    # Load extensions
    env_config[environment].init_app(app)
    app.extensions["mail"].debug = 0

    # Register the blueprints
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(main)
    app.register_blueprint(welcome)

    # Error handlers
    app.register_error_handler(404, not_found)

    @app.context_processor
    def is_active():
        return {"is_active": _is_active}

    return app


def import_submodules(package, modules_to_import):
    """Import all submodules of a module."""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}

    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        if not name.startswith("_"):
            full_name = package.__name__ + "." + name

            if any((x in package.__name__ for x in modules_to_import)):
                results[full_name] = importlib.import_module(full_name)

            elif any((x in name for x in modules_to_import)):
                results[full_name] = importlib.import_module(full_name)

            if is_pkg and name in modules_to_import:
                results.update(import_submodules(full_name, modules_to_import))
    return results


import_submodules(
    __name__,
    (
        "api",
        "checks",
        "controllers",
        "models",
        "tasks",
        "views",
    ),
)
