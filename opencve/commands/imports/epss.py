import csv
import gzip
from io import BytesIO

import requests

from opencve.commands import header, info, timed_operation
from opencve.extensions import db
from opencve.models import get_uuid
from opencve.models.epss import Epss
from opencve.models.tasks import Task
from opencve.models.cve import Cve

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def run():
    """
    Import the EPSS data.
    """
    mappings = {"epss_scores": []}

    # Create the initial task
    task = Task()
    db.session.add(task)
    db.session.commit()
    task_id = task.id

    header("Importing EPSS data...")

    # Download the file
    with timed_operation("Downloading {}...".format(EPSS_URL)):
        resp = requests.get(EPSS_URL).content
    i = 0
    # Parse the CSV elements
    with timed_operation("Parsing CSV elements..."):
        raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
        del resp
        csv_content = csv.reader(raw.decode('utf-8').splitlines())
        # Skip the header
        next(csv_content)
        next(csv_content)

        with timed_operation("Creating model objects..."):
            for row in csv_content:
                cve_id, epss_score, percentile = row
                epss_score = float(epss_score)
                percentile = float(percentile)

                # Fetch the UUID of the CVE using its cve_id
                cve_uuid = Cve.query.filter_by(cve_id=cve_id).first().id

                # Create the EPSS mappings
                mappings["epss_scores"].append(
                    dict(
                        id=get_uuid(),
                        cve_id=cve_id,
                        cve_uuid=cve_uuid,  # Add the fetched UUID
                        score=epss_score,
                        percentile=percentile,
                        task_id=task_id,
                    )
                )
                i += 1
                if i == 5:
                    break


        # Insert the objects in database
        with timed_operation("Inserting EPSS data..."):
            db.session.bulk_insert_mappings(Epss, mappings["epss_scores"])
            db.session.commit()

        info("{} EPSS entries imported.".format(len(mappings["epss_scores"])))

        # Free the memory after the import
        del mappings["epss_scores"]

    return mappings
