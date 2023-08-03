import pathlib

from airflow.configuration import conf


NVD_LOCAL_REPO = pathlib.Path(conf.get("opencve", "nvd_repo_path"))
MITRE_LOCAL_REPO = pathlib.Path(conf.get("opencve", "mitre_repo_path"))

SQL_CVE = "CALL cve_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(cvss2)s, %(cvss3)s, %(vendors)s, %(cwes)s, %(source)s);"
SQL_EVENTS = "CALL change_events(%(cve)s, %(change_id)s, %(created)s, %(updated)s, %(commit)s, %(path)s, %(events)s);"
SQL_REPORTS = "CALL report_upsert(%(created)s, %(project)s, %(details)s, %(changes)s);"

SQL_VENDORS_PER_CHANGE = """
SELECT changes.id, cves.vendors
FROM opencve_cves AS cves
JOIN opencve_changes AS changes ON cves.id = changes.cve_id
WHERE changes.id IN %(changes)s;
"""
