import arrow
import click
from flask.cli import with_appcontext

from opencve.commands import ensure_config, info, timed_operation
from opencve.commands.imports import cpe, cve, cwe
from opencve.extensions import db
from opencve.models.cve import Cve
from opencve.models.metas import Meta

CURRENT_YEAR = arrow.now().year
CVE_FIRST_YEAR = 2002


@click.command()
@click.option("--confirm", is_flag=True, help="Automatically confirm the prompt.")
@ensure_config
@with_appcontext
def import_data(confirm):
    """
    Perform initial imports (cve, cwe, cpe).
    """
    if Cve.query.first():
        info("Import already done.")
        return

    if not confirm:
        msg = (
            "This command will import initial data in your database. "
            "Do you want to continue ?".format(CVE_FIRST_YEAR, CURRENT_YEAR)
        )
        if not click.confirm(msg):
            info("Bye.")
            return

    # Import the CWE list
    cwe.run()

    # Import the CVE, then use the returned list of vendors
    # to merge them with the official CPE dictionnary list.
    vendors = cve.run()
    cpe.run(vendors)

    # Populate the metas table
    with timed_operation("Populating metas table..."):
        meta = Meta(name="nvd_last_sha256", value="default")
        db.session.add(meta)
        db.session.commit()
