import pathlib

from airflow.configuration import conf

NVD_LOCAL_REPO = pathlib.Path(conf.get("opencve", "nvd_repo_path"))
MITRE_LOCAL_REPO = pathlib.Path(conf.get("opencve", "mitre_repo_path"))
REDHAT_LOCAL_REPO = pathlib.Path(conf.get("opencve", "redhat_repo_path"))
VULNRICHMENT_LOCAL_REPO = pathlib.Path(conf.get("opencve", "vulnrichment_repo_path"))
KB_LOCAL_REPO = pathlib.Path(conf.get("opencve", "kb_repo_path"))

PRODUCT_SEPARATOR = "$PRODUCT$"

CVE_UPSERT_PROCEDURE = """
CALL cve_upsert(
    %(cve)s, %(created)s, %(updated)s, %(description)s, %(title)s, %(metrics)s, %(vendors)s, %(weaknesses)s, %(changes)s
);
"""

REPORT_UPSERT_PROCEDURE = """
CALL report_upsert(
    %(report)s, %(project)s, %(day)s, %(changes)s
);
"""

VARIABLE_UPSERT_PROCEDURE = "CALL variable_upsert(%(p_name)s, %(p_value)s);"

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
  changes.created_at >= %(start)s
  AND
  changes.created_at <= %(end)s;
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

SQL_CVES_EVOLUTION_STATISTICS = """
WITH yearly_counts AS (
    SELECT
        CAST(SPLIT_PART(cve_id, '-', 2) AS INTEGER) AS year,
        COUNT(*) AS cve_count
    FROM
        opencve_cves
    GROUP BY
        CAST(SPLIT_PART(cve_id, '-', 2) AS INTEGER)
    ORDER BY
        year
),
cumulative_counts AS (
    SELECT
        year,
        cve_count,
        CAST(SUM(cve_count) OVER (ORDER BY year) AS INTEGER) AS cumulative_cve_count
    FROM
        yearly_counts
)
SELECT
    year,
    cve_count AS "CVEs for Year",
    cumulative_cve_count AS "Cumulative CVEs"
FROM
    cumulative_counts
ORDER BY
    year;
"""

SQL_CVSS_ROUNDED_SCORES = """
SELECT
    CAST(FLOOR((metrics->'{metric}'->'data'->>'score')::NUMERIC) AS INTEGER) AS score_round,
    COUNT(*) AS cve_count
FROM opencve_cves
WHERE metrics->'{metric}'->'data'->>'score' IS NOT NULL
GROUP BY score_round
ORDER BY score_round;
"""

SQL_CVSS_CATEGORIZED_SCORES = """
SELECT
    CASE
        WHEN (metrics->'{metric}'->'data'->>'score')::NUMERIC BETWEEN 0 AND 3.9 THEN 'Low'
        WHEN (metrics->'{metric}'->'data'->>'score')::NUMERIC BETWEEN 4.0 AND 6.9 THEN 'Medium'
        WHEN (metrics->'{metric}'->'data'->>'score')::NUMERIC BETWEEN 7.0 AND 8.9 THEN 'High'
        WHEN (metrics->'{metric}'->'data'->>'score')::NUMERIC BETWEEN 9.0 AND 10 THEN 'Critical'
    END AS score_category,
    COUNT(*) AS cve_count
FROM opencve_cves
WHERE metrics->'{metric}'->'data'->>'score' IS NOT NULL
GROUP BY score_category
ORDER BY score_category;
"""

SQL_CVES_TOP_VENDORS = """
SELECT
    vendor,
    COUNT(*) AS cve_count
FROM (
    SELECT
        jsonb_array_elements_text(vendors) AS vendor
    FROM
        opencve_cves
) subquery
WHERE vendor NOT LIKE '%$PRODUCT$%'
GROUP BY vendor
ORDER BY cve_count DESC
LIMIT 10;
"""

SQL_CVES_TOP_PRODUCTS = """
SELECT
    product,
    COUNT(*) AS cve_count
FROM (
    SELECT
        SPLIT_PART(vendor, '$PRODUCT$', 2) AS product
    FROM (
        SELECT
            jsonb_array_elements_text(vendors) AS vendor
        FROM
            opencve_cves
    ) subquery
    WHERE vendor LIKE '%$PRODUCT$%'
) product_subquery
GROUP BY product
ORDER BY cve_count DESC
LIMIT 10;
"""

SQL_CVES_COUNT_LAST_DAYS = """
SELECT
    -- Current count
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day') AS last_24h,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') AS last_7_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days') AS last_30_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days') AS last_90_days,

    -- Previous period
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '2 days' AND created_at < NOW() - INTERVAL '1 day') AS prev_24h,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '14 days' AND created_at < NOW() - INTERVAL '7 days') AS prev_7_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days' AND created_at < NOW() - INTERVAL '30 days') AS prev_30_days,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '180 days' AND created_at < NOW() - INTERVAL '90 days') AS prev_90_days,

    -- Percentage progress
    CASE
        WHEN COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '2 days' AND created_at < NOW() - INTERVAL '1 day') = 0 THEN NULL
        ELSE ROUND((COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day')::numeric /
                    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '2 days' AND created_at < NOW() - INTERVAL '1 day') - 1) * 100, 2)
    END AS pct_change_24h,
    CASE
        WHEN COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '14 days' AND created_at < NOW() - INTERVAL '7 days') = 0 THEN NULL
        ELSE ROUND((COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')::numeric /
                    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '14 days' AND created_at < NOW() - INTERVAL '7 days') - 1) * 100, 2)
    END AS pct_change_7_days,
    CASE
        WHEN COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days' AND created_at < NOW() - INTERVAL '30 days') = 0 THEN NULL
        ELSE ROUND((COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days')::numeric /
                    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '60 days' AND created_at < NOW() - INTERVAL '30 days') - 1) * 100, 2)
    END AS pct_change_30_days,
    CASE
        WHEN COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '180 days' AND created_at < NOW() - INTERVAL '90 days') = 0 THEN NULL
        ELSE ROUND((COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '90 days')::numeric /
                    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '180 days' AND created_at < NOW() - INTERVAL '90 days') - 1) * 100, 2)
    END AS pct_change_90_days
FROM
    opencve_cves;
"""
