import arrow
from psycopg2.extras import Json

from constants import SQL_PROCEDURES
from events.nvd import NvdEvents
from utils import vendors_conf_to_flat, weaknesses_to_flat, run_sql

from includes.handlers import DiffHandler


class NvdHandler(DiffHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = "nvd"

    def validate_files(self):
        return not (self.path == "last.json")

    def get_data(self):
        """
        This method is the same as web/cves/management/commands/import_cves::get_nvd_sata
        """
        cve_data = {
            "vendors": vendors_conf_to_flat(self.right.get("configurations")),
            "cwes": weaknesses_to_flat(self.right.get("weaknesses")),
            "cvss": {"v20": None, "v30": None, "v31": None},
        }

        # Parse the CVE scores
        if "metrics" in cve_data:
            cvss_keys = {
                "v20": "cvssMetricV2",
                "v30": "cvssMetricV30",
                "v31": "cvssMetricV31",
            }
            for k, v in cvss_keys.items():
                if v in self.right.get("metrics"):
                    cve_data["cvss"][k] = self.right.get("metrics")[v][0]["cvssData"][
                        "baseScore"
                    ]
        return cve_data

    def execute(self):
        cve_data = self.get_data()

        # Created & updated dates
        created = arrow.get(self.right["published"]).to("utc").datetime.isoformat()
        updated = arrow.get(self.right["lastModified"]).to("utc").datetime.isoformat()

        run_sql(
            query=SQL_PROCEDURES.get("nvd"),
            parameters={
                "cve": self.right["id"],
                "created": created,
                "updated": updated,
                "cvss": Json(cve_data["cvss"]),
                "vendors": Json(cve_data["vendors"]),
                "cwes": Json(cve_data["cwes"]),
                "path": Json({"nvd": self.path}),
            },
        )

        self.create_change(self.right["id"], NvdEvents)
