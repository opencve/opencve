WITH invalid_organizations AS (
    SELECT o.id
    FROM opencve_organizations o
    JOIN opencve_billing_subscriptions bs
        ON bs.organization_id = o.id
    WHERE
        bs.features->>'is_over_quota' = 'true'
),
inactive_users AS (
    SELECT u.id
    FROM opencve_users u
    WHERE
        u.last_login IS NULL
        OR u.email LIKE '%.disabled'
),
invalid_organizations_with_only_inactive_users AS (
    SELECT m.organization_id
    FROM opencve_memberships m
    GROUP BY m.organization_id
    HAVING bool_and(m.user_id IN (SELECT id FROM inactive_users))
),
invalid_projects AS (
    SELECT p.id
    FROM opencve_projects p
    WHERE p.organization_id IN (
        SELECT io.id
        FROM invalid_organizations io
        JOIN invalid_organizations_with_only_inactive_users iou
            ON iou.organization_id = io.id
    )
),
invalid_reports AS (
    SELECT r.id
    FROM opencve_reports r
    WHERE r.project_id IN (SELECT id FROM invalid_projects)
)
SELECT
    (SELECT COUNT(*) FROM invalid_projects) AS projects,
    (SELECT COUNT(*) FROM invalid_reports) AS reports,
    (SELECT COUNT(*) FROM opencve_reports_changes rc
        WHERE rc.report_id IN (SELECT id FROM invalid_reports)
    ) AS reports_changes;
