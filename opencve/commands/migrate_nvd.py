import click
import requests
import time
from flask.cli import with_appcontext

from opencve.commands import ensure_config, error, info
from opencve.models.cve import Cve
from opencve.extensions import db


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@click.command()
@ensure_config
@with_appcontext
def migrate_nvd():
    """Migrate NVD data from JSON 4.0 to 5.0"""
    msg = (
        "This command will migrate all existing CVEs into the new NVD format. "
        "Do you want to continue ?"
    )
    if not click.confirm(msg):
        info("Bye.")
        return

    url_template = NVD_API_URL + "?startIndex={idx}"
    start_index = 0
    total_results = 0

    while start_index <= total_results:
        url = url_template.format(idx=start_index)
        info(f"Fetching {url}")
        resp = requests.get(url)

        # Break if status != 200
        if not resp.ok:
            info(f"Bad response: {resp.status_code}, sleeping before retrying...")
            time.sleep(10)
            continue

        data = resp.json()
        total_results = data.get("totalResults")

        for vulnerability in data.get("vulnerabilities"):
            cve_data = vulnerability.get("cve")
            cve_id = cve_data.get("id")

            cve_obj = Cve.query.filter_by(cve_id=cve_id).first()
            if cve_obj:
                cve_obj.json = cve_data

        # NVD requirement is 2000 CVE per page
        # and 6 seconds between requests.
        start_index += 2000
        time.sleep(6)

        if (start_index % 10_000 == 0) or (start_index >= total_results):
            db.session.flush()
            db.session.commit()
