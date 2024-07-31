import pathlib

from airflow.configuration import conf

NVD_LOCAL_REPO = pathlib.Path(conf.get("opencve", "nvd_repo_path"))
MITRE_LOCAL_REPO = pathlib.Path(conf.get("opencve", "mitre_repo_path"))
REDHAT_LOCAL_REPO = pathlib.Path(conf.get("opencve", "redhat_repo_path"))
VULNRICHMENT_LOCAL_REPO = pathlib.Path(conf.get("opencve", "vulnrichment_repo_path"))
KB_LOCAL_REPO = pathlib.Path(conf.get("opencve", "kb_repo_path"))

PRODUCT_SEPARATOR = "$PRODUCT$"

CHANGE_UPSERT_PROCEDURE = """
CALL change_upsert(
    %(cve)s, %(change)s, %(created)s, %(updated)s, %(commit_hash)s, %(file_path)s, %(event_types)s
);
"""

CVE_UPSERT_PROCEDURE = """
CALL cve_upsert(
    %(cve)s, %(created)s, %(updated)s, %(description)s, %(title)s, %(metrics)s, %(vendors)s, %(weaknesses)s
);
"""

REPORT_UPSERT_PROCEDURE = """
CALL report_upsert(
    %(report)s, %(project)s, %(day)s, %(changes)s
);
"""

SQL_CHANGE_WITH_VENDORS = """
SELECT
  changes.id AS change_id,
  changes.types AS change_types,
  changes.path AS change_path,
  cves.vendors AS cve_vendors,
  cves.cve_id AS cve_id,
  cves.metrics AS cve_metrics
FROM
  opencve_cves AS cves
  JOIN opencve_changes AS changes ON cves.id = changes.cve_id
WHERE
  changes.commit IN %(commits)s;
"""

SQL_PROJECT_WITH_SUBSCRIPTIONS = """
SELECT
  id,
  subscriptions
FROM
  opencve_projects
WHERE
  (active = 't')
  AND
  (
    subscriptions->'vendors' ?| %(vendors)s
    OR subscriptions->'products' ?| %(products)s
  );
"""

SQL_PROJECT_WITH_NOTIFICATIONS = """
SELECT
  projects.id,
  projects.name,
  organizations.name,
  notifications.name,
  notifications.type,
  notifications.configuration
FROM
  opencve_notifications AS notifications
  JOIN opencve_projects AS projects ON projects.id = notifications.project_id
  JOIN opencve_organizations AS organizations ON organizations.id = projects.organization_id
WHERE
  is_enabled = 't'
  AND projects.id IN %(projects)s;
"""

SQL_CHANGE_WITH_CVE = """
SELECT
  changes.id,
  cves.cve_id,
  cves.summary,
  cves.cvss,
FROM
  opencve_cves AS cves
  JOIN opencve_changes AS changes ON cves.id = changes.cve_id
WHERE
  changes.created_at >= %(start)s
  AND changes.created_at <= %(end)s;
"""
