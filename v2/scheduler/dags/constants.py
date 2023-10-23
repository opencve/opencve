PRODUCT_SEPARATOR = "$PRODUCT$"

SQL_PROCEDURES = {
    "change": "CALL change_upsert(%(cve)s, %(change)s, %(created)s, %(updated)s, %(commit_hash)s, %(file_path)s, %(events)s);",
    "mitre": "CALL mitre_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(path)s);",
    "nvd": "CALL nvd_upsert(%(cve)s, %(created)s, %(updated)s, %(cvss)s, %(vendors)s, %(cwes)s, %(path)s);",
    "report": "CALL report_upsert(%(report)s, %(project)s, %(day)s, %(changes)s);",
}

SQL_CHANGE_WITH_VENDORS = """
SELECT
  changes.id,
  cves.vendors
FROM
  opencve_cves AS cves
  JOIN opencve_changes AS changes ON cves.id = changes.cve_id
WHERE
  changes.created_at >= %(start)s
  AND changes.created_at <= %(end)s;
"""

SQL_PROJECT_WITH_SUBSCRIPTIONS = """
SELECT
  id,
  subscriptions
FROM
  opencve_projects
WHERE
  subscriptions->'vendors' ?| %(vendors)s
  OR subscriptions->'products' ?| %(products)s;
"""

SQL_PROJECT_WITH_NOTIFICATIONS = """
SELECT
  projects.id,
  notifications.type,
  notifications.configuration
FROM
  opencve_notifications AS notifications
  JOIN opencve_projects AS projects ON projects.id = notifications.project_id
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