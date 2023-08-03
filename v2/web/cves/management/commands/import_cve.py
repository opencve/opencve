import glob
import json
import pathlib
import re
import os
from textwrap import dedent

import arrow
import git
from psycopg2.extras import Json

from cves.management.commands import BaseCommand
from cves.utils import vendors_conf_to_flat, weaknesses_to_flat


class Command(BaseCommand):
    def get_mitre_files(self):
        return [
            f
            for f in glob.glob(self.mitre_path + "/**/*.json", recursive=True)
            if re.search(r"CVE-\d{4}-\d{4,7}", f)
        ]

    def get_nvd_cve_path(self, cve_id):
        cve_year = cve_id.split("-")[1]
        return pathlib.Path(self.nvd_path) / cve_year / f"{cve_id}.json"

    def get_nvd_data(self, cve_nvd_path):
        nvd_data = {
            "vendors": [],
            "cwes": [],
            "cvss": {"v20": None, "v30": None, "v31": None},
        }

        with open(cve_nvd_path) as f:
            cve_nvd_data = json.load(f)

        # Parse the CVE vendors
        nvd_data["vendors"] = vendors_conf_to_flat(cve_nvd_data.get("configurations"))

        # Parse the CVE CWEs
        nvd_data["cwes"] = weaknesses_to_flat(cve_nvd_data.get("weaknesses"))

        # Parse the CVE scores
        if "metrics" in cve_nvd_data:
            cvss_keys = {
                "v20": "cvssMetricV2",
                "v30": "cvssMetricV30",
                "v31": "cvssMetricV31",
            }
            for k, v in cvss_keys.items():
                if v in cve_nvd_data["metrics"]:
                    nvd_data["cvss"][k] = cve_nvd_data["metrics"][v][0]["cvssData"][
                        "baseScore"
                    ]

        return nvd_data

    def display_scheduler_commands(self):
        mitre_last_commit = git.Repo(self.mitre_path).head.commit
        nvd_last_commit = git.Repo(self.nvd_path).head.commit

        commands = dedent(
            f"""
        You can now launch the following commands in Airflow Scheduler:
        > {self.bold(f"airflow variables set mitre_last_commit {mitre_last_commit}")}
        > {self.bold(f"airflow variables set nvd_last_commit {nvd_last_commit}")}
        """
        )
        self.info(commands)

    def insert_cve(self, cve_file):
        sources = {"mitre": os.path.relpath(cve_file, self.mitre_path)}

        with open(cve_file) as f:
            cve_data = json.load(f)

        # All CVE have an associated ID
        metadata = cve_data["cveMetadata"]
        cve_id = metadata["cveId"]

        # Rejected CVEs doesn't have published date
        cve_created = metadata.get("datePublished") or metadata["dateReserved"]
        cve_created_utc = arrow.get(cve_created).to("utc").datetime.isoformat()

        # Recent CVEs doesn't have updated date
        cve_updated = metadata.get("dateUpdated") or cve_created
        cve_updated_utc = arrow.get(cve_updated).to("utc").datetime.isoformat()

        # If no descriptions, take the rejected reasons
        cna = cve_data["containers"]["cna"]
        descriptions = cna.get("descriptions") or cna["rejectedReasons"]

        # In case of multiple languages, keep the EN one
        if len(descriptions) > 1:
            descriptions = [d for d in descriptions if d["lang"] in ("en", "en-US")]
        description = descriptions[0]["value"]

        # Append the NVD data to this CVE
        cve_nvd_path = self.get_nvd_cve_path(cve_id)

        nvd_data = {
            "vendors": [],
            "cwes": [],
            "cvss": {"v20": None, "v30": None, "v31": None},
        }
        if pathlib.Path.exists(cve_nvd_path):
            nvd_data.update(self.get_nvd_data(cve_nvd_path))
            sources["nvd"] = os.path.relpath(str(cve_nvd_path), self.nvd_path)

        # Call the stored procedure which create the CVE and its associated objects
        self.call_procedure(
            procedure="cves",
            params={
                "cve": cve_id,
                "created": cve_created_utc,
                "updated": cve_updated_utc,
                "summary": description,
                "cvss": Json(nvd_data["cvss"]),
                "vendors": Json(nvd_data["vendors"]),
                "cwes": Json(nvd_data["cwes"]),
                "source": Json(sources),
            }
        )

    def handle(self, *args, **options):
        if not self.repos_exist([self.mitre_path, self.nvd_path]):
            self.error("The CVE repositories have to be cloned first")
            return

        self.info(f"Parsing CVE repository ({self.blue(self.mitre_path)})")
        cve_files = self.get_mitre_files()

        msg = f"Found {self.blue(len(cve_files))} CVEs, adding them in database"
        with self.timed_operation(msg):
            for cve_file in sorted(cve_files):
                self.insert_cve(cve_file)

        self.display_scheduler_commands()
