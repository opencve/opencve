#!/bin/bash

DB_NAME="opencve_web_2026_03_19"
BATCH_SIZE=100000
SLEEP=0.2

echo "🚀 Starting cleanup..."

# -------------------------------
# 1. DELETE reports_changes
# -------------------------------
echo "🧹 Cleaning opencve_reports_changes..."

while true; do
  DELETED=$(psql -d "$DB_NAME" -Atc "
DO \$\$
DECLARE
  deleted_count INT;
BEGIN
  WITH to_delete AS (
    SELECT rc.ctid
    FROM opencve_reports_changes rc
    JOIN opencve_reports r ON r.id = rc.report_id
    JOIN opencve_projects p ON p.id = r.project_id
    JOIN opencve_billing_subscriptions bs ON bs.organization_id = p.organization_id
    WHERE bs.plan_id = 'aeb685fc-c0fe-445a-9413-9975bf7a517c'
    LIMIT $BATCH_SIZE
  )
  DELETE FROM opencve_reports_changes
  WHERE ctid IN (SELECT ctid FROM to_delete);

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE '%', deleted_count;
END
\$\$;
" 2>&1 | grep -oE '[0-9]+$')

  echo "Deleted $DELETED rows from reports_changes"

  if [ -z "$DELETED" ] || [ "$DELETED" -eq 0 ]; then
    break
  fi

  sleep $SLEEP
done

echo "✅ reports_changes cleaned"

# -------------------------------
# 2. DELETE reports
# -------------------------------
echo "🧹 Cleaning opencve_reports..."

while true; do
  DELETED=$(psql -d "$DB_NAME" -Atc "
DO \$\$
DECLARE
  deleted_count INT;
BEGIN
  WITH to_delete AS (
    SELECT r.ctid
    FROM opencve_reports r
    JOIN opencve_projects p ON p.id = r.project_id
    JOIN opencve_billing_subscriptions bs ON bs.organization_id = p.organization_id
    WHERE bs.plan_id = 'aeb685fc-c0fe-445a-9413-9975bf7a517c'
    LIMIT $BATCH_SIZE
  )
  DELETE FROM opencve_reports
  WHERE ctid IN (SELECT ctid FROM to_delete);

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RAISE NOTICE '%', deleted_count;
END
\$\$;
" 2>&1 | grep -oE '[0-9]+$')

  echo "Deleted $DELETED rows from reports"

  if [ -z "$DELETED" ] || [ "$DELETED" -eq 0 ]; then
    break
  fi

  sleep $SLEEP
done

echo "✅ reports cleaned"

echo "🎉 Cleanup finished!"
