# OpenCVE Scheduler

Apache Airflow workflows that keep vulnerability data up to date and run user automations (alerts and reports).

## What it does

### Main DAG: `opencve` (hourly)

Runs end-to-end processing for each hour:

1. **`kb_refresh`** — Fetch upstream CVE sources (MITRE, NVD, Red Hat, Vulnrichment, KB) and process them into the database; compute statistics.
2. **`report_inputs`** — Collect hourly CVE changes, resolve project subscriptions, load enabled automations into Redis.
3. **`automation_processing`**
   - **Alert** — `build_alert_work_items` evaluates alert automations and queues actions in Redis; `execute_alert_actions` runs those actions (notifications, assign user, change status, …).
   - **Report** — Build hourly report content, upsert reports, evaluate due schedules, send daily/weekly report notifications.

The DAG is defined in [`dags/opencve_dag.py`](dags/opencve_dag.py). Task logic lives under [`dags/includes/tasks/`](dags/includes/tasks/).

### Other DAGs

| DAG | Purpose |
|-----|---------|
| `check_smtp` | Verify SMTP configuration |
| `clean_reports` | Enforce report retention |
| `summarize_reports` | LLM summaries for reports |

Configuration is read from `airflow.cfg` (see [`airflow.cfg.example`](airflow.cfg.example)), especially the `[opencve]` section.

## Performance tuning

OpenCVE stores large hourly payloads in **Redis** (not XCom). The slow paths on busy instances are usually **`build_alert_work_items`** (SQL + filtering) and **`execute_alert_actions`** (notifications and DB writes).

Tune in this order:

1. **`max_notifications_per_task`** — Parallel `send_notification` calls **inside** one execute task (asyncio semaphore). Default in example: `10`. If prod uses `1`, emails run one after another; try `5` then `10` in staging and watch SMTP errors/rate limits.
2. **`max_automations_map_length`** — Splits the action queue into Redis chunks. When **`> 1`**, Airflow runs **one mapped `execute_alert_actions` task per chunk** in parallel (up to the number of chunks, capped by chunking rules). When **`1`**, a single execute task processes all chunks sequentially. Roll back to `1` to disable execute parallelism without redeploying code.
3. **Airflow infrastructure** — Worker count, `parallelism`, `max_active_tasks_per_dag`. The `opencve` DAG sets `max_active_runs=1` (one hourly run at a time).

### `[opencve]` settings (reference)

| Setting | Effect |
|---------|--------|
| `max_notifications_per_task` | Concurrent notifications per execute task |
| `max_automations_map_length` | Chunk size + mapped execute tasks when `> 1` |
| `notification_request_timeout` | HTTP timeout for webhook-style notifications |
| SMTP `notification_smtp_*` | Email delivery; raising concurrency may require higher provider limits |

Legacy installs without `max_automations_map_length` fall back to `max_notifications_map_length`.

### Symptom → what to change

| Symptom | Action |
|---------|--------|
| `build_alert_work_items` slow, many projects | Code batches tracker SQL; ensure scheduler image is current |
| `execute_alert_actions` slow, many emails | Increase `max_notifications_per_task` |
| `execute_alert_actions` slow, many queued actions | Increase `max_automations_map_length` (e.g. `10`) and ensure enough Airflow workers |
| SMTP throttling / bounces | Lower `max_notifications_per_task` or `max_automations_map_length` |
| Need safe rollback on execute parallelism | Set `max_automations_map_length = 1` |
