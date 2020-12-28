from unittest.mock import patch

from opencve.commands.upgrade_db import upgrade_db
from opencve.extensions import db
from opencve.models.cve import Cve


def test_upgrade_db_command(app):
    runner = app.test_cli_runner()
    result = runner.invoke(upgrade_db, [])

    # Migrations are executed
    assert (
        "INFO  [alembic.runtime.migration] Context impl PostgresqlImpl."
        in result.output
    )
    assert (
        "INFO  [alembic.runtime.migration] Will assume transactional DDL."
        in result.output
    )
    assert "INFO  [alembic.runtime.migration] Running upgrade" in result.output
