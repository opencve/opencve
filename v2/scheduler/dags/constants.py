import pathlib

from airflow.configuration import conf


NVD_LOCAL_REPO = pathlib.Path(conf.get("opencve", "nvd_repo_path"))
MITRE_LOCAL_REPO = pathlib.Path(conf.get("opencve", "mitre_repo_path"))

SQL_PROCEDURES = {
    "events": "CALL change_events(%(cve)s, %(change_id)s, %(created)s, %(updated)s, %(commit)s, %(path)s, %(events)s);",
    "mitre": "CALL mitre_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(path)s);",
    "nvd": "CALL nvd_upsert(%(cve)s, %(created)s, %(updated)s, %(cvss)s, %(vendors)s, %(cwes)s, %(path)s);"
}
SQL_REPORTS = "CALL report_upsert(%(created)s, %(project)s, %(details)s, %(changes)s);"

SQL_VENDORS_PER_CHANGE = """
SELECT changes.id, cves.vendors
FROM opencve_cves AS cves
JOIN opencve_changes AS changes ON cves.id = changes.cve_id
WHERE changes.id IN %(changes)s;
"""
