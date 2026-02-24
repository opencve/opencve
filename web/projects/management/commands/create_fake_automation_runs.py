"""
Create fake automation executions and results for testing the Activity tab and execution detail UI.
Executions are generated in a realistic way per automation type:
- Realtime (events): one execution per hour (e.g. 10:00, 11:00, 12:00).
- Scheduled daily: one execution per day (e.g. 2026-02-18, 2026-02-19).
- Scheduled weekly: one execution per week (e.g. 2026-02-16, 2026-02-23).
"""

import random
from datetime import datetime, timedelta, time

from django.utils import timezone

from opencve.commands import BaseCommand
from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    Project,
)
from projects.views import build_impact_chart_data_from_cves_table
from changes.models import Report


# Map automation action type (from configuration.actions[].type) to (output_type, label)
ACTION_TYPE_TO_OUTPUT = {
    "send_notification": ("notification_sent", "Notification sent"),
    "generate_report": ("report", "Report"),
    "generate_pdf": ("pdf", "PDF report"),
    "include_ai_summary": ("ai_summary", "AI Summary created"),
    "assign_user": ("assignment", "Assignments"),
    "change_status": ("status_change", "Status changes"),
}

RESULT_STATUS_CHOICES = [
    AutomationRunResult.STATUS_SUCCESS,
    AutomationRunResult.STATUS_SKIPPED,
    AutomationRunResult.STATUS_FAILED,
]


VENDORS_PRODUCTS = [
    "Microsoft",
    "Apache",
    "Linux Kernel",
    "Google",
    "Oracle",
    "Cisco",
    "Adobe",
    "IBM",
    "Red Hat",
    "Apple",
]

REASON_TEMPLATES = [
    "Vendor {}",
    "Product {}",
    "CVSS {} ≥ 7",
    "CVSS {} ≥ 9",
    "EPSS {} ≥ 0.5",
    "EPSS {} ≥ 0.8",
    "In KEV catalog",
]


def _make_aware(dt):
    """Ensure datetime is timezone-aware (for date-only builds)."""
    if timezone.is_naive(dt):
        return timezone.make_aware(dt)
    return dt


def _fake_conditions_tree(count=2):
    """Build a conditions tree with `count` leaf conditions (for list display)."""
    condition_nodes = [
        {"type": "cvss_gte", "value": {"version": "v3.1", "value": 7}},
        {"type": "cve_enters_project", "value": True},
        {"type": "kev_added", "value": True},
    ]
    children = [condition_nodes[i % len(condition_nodes)] for i in range(count)]
    return {"operator": "OR", "children": children}


def _fake_actions_scheduled():
    """Actions for a scheduled (daily) automation: report, PDF, notification, AI summary."""
    return [
        {"type": "generate_report", "value": True},
        {"type": "generate_pdf", "value": True},
        {"type": "send_notification", "value": "00000000-0000-0000-0000-000000000001"},
        {"type": "include_ai_summary", "value": True},
    ]


def _fake_actions_realtime():
    """Actions for a realtime automation: notification, assignment, status change."""
    return [
        {"type": "send_notification", "value": "00000000-0000-0000-0000-000000000001"},
        {"type": "assign_user", "value": ""},
        {"type": "change_status", "value": "to_evaluate"},
    ]


def _random_cves_table_data(num_cves):
    """Return list of num_cves fake CVE rows for cves_table_data."""
    if num_cves <= 0:
        return []
    year = random.choice([2023, 2024, 2025])
    used_ids = set()
    rows = []
    for _ in range(num_cves):
        while True:
            cve_id = f"CVE-{year}-{random.randint(1000, 99999)}"
            if cve_id not in used_ids:
                used_ids.add(cve_id)
                break
        cvss = round(random.uniform(0, 10), 1) if random.random() > 0.1 else None
        epss = round(random.random(), 2) if random.random() > 0.2 else None
        kev = random.choice([True, False, False])
        vp = random.choice(VENDORS_PRODUCTS) if random.random() > 0.2 else ""
        num_reasons = random.randint(1, 3)
        reasons = []
        for _ in range(num_reasons):
            t = random.choice(REASON_TEMPLATES)
            if "{}" in t:
                if "Vendor" in t or "Product" in t:
                    reasons.append(t.format(random.choice(VENDORS_PRODUCTS)))
                elif "CVSS" in t:
                    reasons.append(t.format(round(random.uniform(5, 10), 1)))
                else:
                    reasons.append(t.format(round(random.random(), 2)))
            else:
                reasons.append(t)
        rows.append(
            {
                "cve_id": cve_id,
                "cvss_31": cvss,
                "epss": epss,
                "kev": kev,
                "matched_vendor_or_product": vp or None,
                "reason_matched": reasons,
            }
        )
    return rows


def _output_details(output_type, run_matched_count, report=None):
    """Return details dict for AutomationRunResult by type. All result-specific
    data (report_day, url, size_mb, etc.) lives in this dict for the UI.
    """
    report_day = report.day.strftime("%Y-%m-%d") if report else None
    if output_type == "notification_sent":
        channels = ["Slack #security", "Slack #infra", "Teams #alerts", "Email"]
        statuses = ["delivered", "sent", "posted"]
        # HTTP status: mostly 200/201, sometimes 4xx/5xx for testing
        status_codes = [200, 200, 201, 204, 400, 401, 429, 500, 502]
        status_code = random.choice(status_codes)
        response_url = (
            f"https://example.com/msg/{random.randint(10000, 99999)}"
            if random.random() > 0.3 and status_code < 400
            else None
        )
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer xoxb-fake-"
            + "".join(random.choices("0123456789", k=24)),
            "User-Agent": "OpenCVE-Notification/1.0",
        }
        if random.random() > 0.5:
            request_headers["X-Request-ID"] = f"req-{random.randint(10000, 99999)}"
        request_payload = (
            '{"channel": "#infra", "text": "3 new CVEs matched your project. '
            '<https://opencve.io/report/2026-02-23|View report>", "unfurl_links": true}'
        )
        response_headers = {
            "Content-Type": "application/json",
            "Date": "Mon, 23 Feb 2026 14:32:10 GMT",
            "X-Slack-Req-Id": f"a1b2c3d4-{random.randint(1000, 9999)}",
        }
        if status_code >= 400:
            response_body = (
                '{"ok": false, "error": "channel_not_found", '
                '"response_metadata": {"messages": []}}'
            )
        else:
            response_body = (
                '{"ok": true, "channel": "C01234ABCD", "ts": "1645612330.000100", '
                '"message": {"type": "message", "text": "3 new CVEs matched..."}}'
            )
        return {
            "channel": random.choice(channels),
            "status": random.choice(statuses),
            "response_url": response_url,
            "status_code": status_code,
            "request_headers": request_headers,
            "request_payload": request_payload,
            "response_headers": response_headers,
            "response_body": response_body,
        }
    if output_type == "report":
        out = {
            "cve_count": (
                run_matched_count if run_matched_count else random.randint(0, 20)
            ),
        }
        if report_day:
            out["report_day"] = report_day
        return out
    if output_type == "pdf":
        return {
            "size_mb": round(random.uniform(0.2, 5.0), 1),
            "filename": f"report-{random.randint(1000, 9999)}.pdf",
            # No file_path: mock has no real file, so no download link
        }
    if output_type == "ai_summary":
        previews = [
            "Critical RCE in Apache HTTP Server. Patch immediately.",
            "Multiple CVEs in Microsoft Windows components. Review and deploy updates.",
            "High-severity issues in Oracle DB. Apply quarterly patch.",
        ]
        out = {"preview": random.choice(previews)}
        if report_day:
            out["report_day"] = report_day
        elif random.random() > 0.5:
            out["url"] = f"https://example.com/summary/{random.randint(10000, 99999)}"
        return out
    if output_type == "assignment":
        assignees = [
            "nicolas@opencve.io",
            "alice@company.com",
            "security-team@example.org",
            "bob@opencve.io",
        ]
        assignee = random.choice(assignees)
        n = run_matched_count or random.randint(1, 10)
        return {
            "assigned_count": n,
            "assignee": assignee,
            "summary": f'{n} CVEs assigned to "{assignee}"',
        }
    if output_type == "status_change":
        n = run_matched_count or random.randint(1, 8)
        transitions = [
            ("New", "In Review"),
            ("To evaluate", "Pending review"),
            ("Pending review", "Analysis in progress"),
            ("Analysis in progress", "Remediation in progress"),
            ("Remediation in progress", "Resolved"),
        ]
        from_label, to_label = random.choice(transitions)
        return {
            "updated_count": n,
            "from_status": from_label,
            "to_status": to_label,
            "summary": f'{n} CVEs moved from "{from_label}" → "{to_label}"',
        }
    return {}


class Command(BaseCommand):
    help = """
    Create fake automation executions and results to preview the Activity tab and execution detail.
    Options: --project (project name), --automation (automation name), --count (number of executions, default 10).
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "--project",
            type=str,
            default=None,
            help="Project name (default: first project)",
        )
        parser.add_argument(
            "--automation",
            type=str,
            default=None,
            help="Automation name (default: first automation of the project)",
        )
        parser.add_argument(
            "--count",
            type=int,
            default=10,
            help="Number of executions to create (default: 10)",
        )

    def _ensure_fake_automations(self, project):
        """Create 2 fake automations (scheduled + realtime) if the project has none.
        Each has conditions and actions so the list table shows correct counts.
        """
        existing = list(
            Automation.objects.filter(project=project).order_by("created_at")
        )
        if existing:
            return existing

        Automation.objects.create(
            project=project,
            name="Daily report (scheduled)",
            is_enabled=True,
            trigger_type=Automation.TRIGGER_SCHEDULED,
            frequency=Automation.FREQUENCY_DAILY,
            configuration={
                "conditions": _fake_conditions_tree(2),
                "actions": _fake_actions_scheduled(),
            },
        )
        Automation.objects.create(
            project=project,
            name="CVE events (realtime)",
            is_enabled=True,
            trigger_type=Automation.TRIGGER_REALTIME,
            frequency=None,
            configuration={
                "conditions": _fake_conditions_tree(2),
                "actions": _fake_actions_realtime(),
                "triggers": ["cve_enters_project", "cvss_increased"],
            },
        )
        self.info(
            f"Created 2 fake automations for project '{project.name}': "
            f"{self.blue('Daily report (scheduled)')} and {self.blue('CVE events (realtime)')}."
        )
        return list(Automation.objects.filter(project=project).order_by("created_at"))

    def _execution_times_realtime(self, now, count):
        """One execution per hour: 10:00, 11:00, 12:00, ... (most recent first)."""
        base = now.replace(minute=0, second=0, microsecond=0)
        for i in range(count):
            executed_at = base - timedelta(hours=i + 1)
            window_start = executed_at - timedelta(hours=1)
            window_end = executed_at - timedelta(minutes=1)
            yield _make_aware(executed_at), _make_aware(window_start), _make_aware(
                window_end
            )

    def _execution_times_daily(self, now, count):
        """One execution per day: 2026-02-18, 2026-02-19, ... (midnight)."""
        base = now.replace(hour=0, minute=0, second=0, microsecond=0)
        for i in range(count):
            executed_at = base - timedelta(days=i)
            window_start = executed_at
            window_end = executed_at + timedelta(days=1) - timedelta(seconds=1)
            yield _make_aware(executed_at), _make_aware(window_start), _make_aware(
                window_end
            )

    def _execution_times_weekly(self, now, count):
        """One execution per week: same weekday each time (e.g. 2026-02-16, 2026-02-23)."""
        base = now.replace(hour=0, minute=0, second=0, microsecond=0)
        for i in range(count):
            executed_at = base - timedelta(weeks=i)
            window_start = executed_at
            window_end = executed_at + timedelta(days=1) - timedelta(seconds=1)
            yield _make_aware(executed_at), _make_aware(window_start), _make_aware(
                window_end
            )

    def _create_executions_for_automation(
        self, automation, project, reports, count, now
    ):
        """Create count fake executions (and results) for the given automation. Returns number created."""
        if automation.trigger_type == Automation.TRIGGER_REALTIME:
            execution_times = self._execution_times_realtime(now, count)
        elif automation.trigger_type == Automation.TRIGGER_SCHEDULED:
            if automation.frequency == Automation.FREQUENCY_WEEKLY:
                execution_times = self._execution_times_weekly(now, count)
            else:
                execution_times = self._execution_times_daily(now, count)
        else:
            execution_times = self._execution_times_daily(now, count)

        created = 0
        for executed_at, window_start, window_end in execution_times:
            roll = random.random()
            if roll < 0.25:
                matched = 0
            elif roll < 0.7:
                matched = random.randint(1, 15)
            elif roll < 0.9:
                matched = random.randint(20, 80)
            else:
                matched = random.randint(80, 150)

            if matched == 0:
                impact_summary = None
                cves_table_data = []
            else:
                cves_table_data = _random_cves_table_data(matched)
                impact_summary = build_impact_chart_data_from_cves_table(
                    cves_table_data
                )

            execution = AutomationExecution.objects.create(
                automation=automation,
                executed_at=executed_at,
                window_start=window_start,
                window_end=window_end,
                matched_cves_count=matched,
            )
            execution.impact_summary = impact_summary
            execution.cves_table_data = cves_table_data
            execution.save(update_fields=["impact_summary", "cves_table_data"])

            if matched > 0:
                actions = automation.configuration.get("actions") or []
                for action in actions:
                    action_type = action.get("type")
                    if not action_type:
                        continue
                    output_type, label = ACTION_TYPE_TO_OUTPUT.get(
                        action_type,
                        (action_type, action_type.replace("_", " ").title()),
                    )
                    report = None
                    if output_type in ("report", "ai_summary") and reports:
                        report = random.choice(reports)
                    details = _output_details(output_type, matched, report=report)
                    result_status = random.choice(RESULT_STATUS_CHOICES)
                    AutomationRunResult.objects.create(
                        automation_execution=execution,
                        output_type=output_type,
                        label=label,
                        status=result_status,
                        details=details,
                    )
            created += 1
        return created

    def handle(self, *args, **options):
        project_name = options["project"]
        automation_name = options["automation"]
        count = options["count"]

        if project_name:
            project = Project.objects.filter(name=project_name).first()
            if not project:
                self.error(f"Project '{project_name}' not found.")
                return
        else:
            project = Project.objects.first()
            if not project:
                self.error("No project found. Create a project first.")
                return

        if automation_name:
            automation = Automation.objects.filter(
                project=project, name=automation_name
            ).first()
            if not automation:
                self.error(
                    f"Automation '{automation_name}' not found in project '{project.name}'."
                )
                return
            automations = [automation]
        else:
            automations = self._ensure_fake_automations(project)

        reports = list(Report.objects.filter(project=project).order_by("-day")[:5])
        if not reports:
            for d in range(3):
                day = (timezone.now() - timedelta(days=d)).date()
                if not Report.objects.filter(project=project, day=day).exists():
                    reports.append(Report.objects.create(project=project, day=day))
            self.info(
                f"Created {self.blue(len(reports))} fake report(s) for project '{project.name}' so Report results can be linked."
            )

        now = timezone.now()
        total_created = 0
        for automation in automations:
            n = self._create_executions_for_automation(
                automation, project, reports, count, now
            )
            total_created += n
            self.info(
                f"  {self.blue(n)} execution(s) for automation '{automation.name}'."
            )

        self.info(
            f"Done: {self.blue(total_created)} total fake execution(s) in project '{project.name}'."
        )
