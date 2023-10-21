PRODUCT_SEPARATOR = "$PRODUCT$"

SQL_PROCEDURES = {
    "change": "CALL change_upsert(%(cve)s, %(change_id)s, %(created)s, %(updated)s, %(commit)s, %(path)s, %(events)s);",
    "mitre": "CALL mitre_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(path)s);",
    "nvd": "CALL nvd_upsert(%(cve)s, %(created)s, %(updated)s, %(cvss)s, %(vendors)s, %(cwes)s, %(path)s);",
    "report": "CALL report_upsert(%(report)s, %(project)s, %(created)s, %(changes)s);",
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
