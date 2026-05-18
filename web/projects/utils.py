from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string

from cves.utils import cvss_score_to_severity, get_highest_cvss

# Map automation result output_type to Font Awesome icon class
RESULT_TYPE_ICONS = {
    "notification_sent": "fa-envelope",
    "report": "fa-file-text-o",
    "assignment": "fa-users",
    "status_change": "fa-check-circle",
    "pdf": "fa-file-pdf-o",
    "ai_summary": "fa-lightbulb-o",
}


def build_impact_chart_data_from_cves_table(cves_table_data):
    """
    Build the impact summary dict from cves_table_data for the drawer and for
    pre-computation in the fake data command. Returns a dict to store in
    execution.impact_summary, or None if no data.
    """
    if not cves_table_data:
        return None
    cvss_version_keys = ("cvss_40", "cvss_31", "cvss_30", "cvss_20")
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    highest_cvss = None
    highest_cvss_version = None
    cvss_scores = []
    epss_values = []
    epss_distribution = {"high": 0, "medium": 0, "low": 0}  # >0.9, 0.7-0.9, <0.7
    kev_count = 0
    vendor_counts = {}

    for row in cves_table_data:
        scores_dict = {
            k: row.get(k) for k in cvss_version_keys if row.get(k) is not None
        }
        if not scores_dict and row.get("cvss_31") is not None:
            scores_dict = {"cvss_31": row["cvss_31"]}
        score, version = get_highest_cvss(scores_dict) if scores_dict else (None, None)
        if score is not None:
            severity = cvss_score_to_severity(score)
            if severity and severity in distribution:
                distribution[severity] += 1
            cvss_scores.append(score)
            if highest_cvss is None or score > highest_cvss:
                highest_cvss = score
                highest_cvss_version = version
        if row.get("epss") is not None:
            try:
                v = float(row["epss"])
                epss_values.append(v)
                if v > 0.9:
                    epss_distribution["high"] += 1
                elif v >= 0.7:
                    epss_distribution["medium"] += 1
                else:
                    epss_distribution["low"] += 1
            except (TypeError, ValueError):
                pass
        if row.get("kev"):
            kev_count += 1
        for vp in row.get("matched_vendors_or_products") or []:
            if vp and str(vp).strip():
                vendor_counts[vp] = vendor_counts.get(vp, 0) + 1

    epss_avg = round(sum(epss_values) / len(epss_values), 2) if epss_values else None
    epss_max = round(max(epss_values), 2) if epss_values else None
    if highest_cvss is not None:
        highest_cvss = round(highest_cvss, 1)
    average_cvss = (
        round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else None
    )
    cves_count = len(cves_table_data)
    kev_percent = int(round(100 * kev_count / cves_count)) if cves_count else 0
    top_vendors_products = [
        {"name": name, "count": count}
        for name, count in sorted(vendor_counts.items(), key=lambda x: -x[1])[:5]
    ]

    return {
        "cvss_distribution": distribution,
        "highest_cvss": highest_cvss,
        "highest_cvss_version": highest_cvss_version,
        "average_cvss": average_cvss,
        "epss_distribution": epss_distribution,
        "epss_avg": epss_avg,
        "epss_max": epss_max,
        "kev_count": kev_count,
        "cves_count": cves_count,
        "kev_percent": kev_percent,
        "top_vendors_products": top_vendors_products,
    }


def send_notification_confirmation_email(notification, request):
    """
    Send a confirmation email to the notification target address.
    The email states who created the notification and includes a confirmation link.
    """
    extras = notification.configuration.get("extras", {})
    email_to = extras.get("email")
    created_by_email = extras.get("created_by_email", "")
    confirmation_token = extras.get("confirmation_token")
    if not email_to or not confirmation_token:
        return

    confirm_url = request.build_absolute_uri(
        f"/notifications/confirm/{confirmation_token}/"
    )

    context = {
        "organization": notification.project.organization.name,
        "project": notification.project.name,
        "created_by_email": created_by_email,
        "confirm_url": confirm_url,
    }

    subject = (
        f"{settings.ACCOUNT_EMAIL_SUBJECT_PREFIX}Notification subscription confirmation"
    )

    text_content = render_to_string(
        "projects/emails/notification_confirmation.txt", context
    )
    msg = EmailMessage(
        subject=subject,
        body=text_content,
        from_email=(
            settings.DEFAULT_FROM_EMAIL
            if hasattr(settings, "DEFAULT_FROM_EMAIL")
            else None
        ),
        to=[email_to],
    )
    msg.send()
