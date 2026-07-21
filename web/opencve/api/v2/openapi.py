import opencve.api.v2.openapi_extensions  # noqa: F401 — register auth extension
from drf_spectacular.utils import OpenApiExample, OpenApiParameter
from drf_spectacular.views import (
    SpectacularAPIView as DrfSpectacularAPIView,
    SpectacularSwaggerView as DrfSpectacularSwaggerView,
)


ORGANIZATIONS_TAG = "organizations"
MEMBERS_TAG = "members"
AUDIT_LOGS_TAG = "audit-logs"
PROJECTS_TAG = "projects"
SUBSCRIPTIONS_TAG = "subscriptions"
TRACKER_TAG = "tracker"
NOTIFICATIONS_TAG = "notifications"
AUTOMATIONS_TAG = "automations"
REPORTS_TAG = "reports"
CVES_TAG = "cves"
VENDORS_TAG = "vendors"
WEAKNESSES_TAG = "weaknesses"


def _path_param(name):
    return OpenApiParameter(name, str, OpenApiParameter.PATH)


ORG_NAME = _path_param("organization_name")
PROJECT_NAME = _path_param("project_name")
CVE_ID = _path_param("cve_id")
VENDOR_NAME = _path_param("vendor_name")
PRODUCT_NAME = _path_param("name")
AUTOMATION_NAME = _path_param("automation_name")
REPORT_ID = _path_param("report_id")

ORG_PATH_PARAMS = [ORG_NAME]
ORG_PROJECT_PATH_PARAMS = [ORG_NAME, PROJECT_NAME]
ORG_PROJECT_CVE_PATH_PARAMS = [ORG_NAME, PROJECT_NAME, CVE_ID]
VENDOR_PRODUCT_PATH_PARAMS = [VENDOR_NAME, PRODUCT_NAME]
ORG_PROJECT_AUTOMATION_PATH_PARAMS = [
    ORG_NAME,
    PROJECT_NAME,
    AUTOMATION_NAME,
]
ORG_PROJECT_REPORT_PATH_PARAMS = [ORG_NAME, PROJECT_NAME, REPORT_ID]

CVE_ADVANCED_SEARCH_DOCS = "https://docs.opencve.io/guides/advanced_search/"

CVE_LIST_QUERY_PARAMS = [
    OpenApiParameter(
        name="q",
        type=str,
        location=OpenApiParameter.QUERY,
        required=False,
        description=f"Search CVEs with OpenCVE query syntax ([documentation]({CVE_ADVANCED_SEARCH_DOCS})).",
    ),
]

CVE_RETRIEVE_INCLUDE_FIELDS = frozenset({"nvd_cpe_configurations", "references"})

CVE_RETRIEVE_QUERY_PARAMS = [
    OpenApiParameter(
        name="include",
        type=str,
        location=OpenApiParameter.QUERY,
        required=False,
        description=(
            "Comma-separated extra fields: `nvd_cpe_configurations`, `references`."
        ),
    ),
]

CVE_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List CVEs",
    value={
        "created_at": "2026-04-04T00:38:35Z",
        "updated_at": "2026-06-02T14:45:10Z",
        "cve_id": "CVE-2026-35616",
        "description": (
            "A improper access control vulnerability in Fortinet FortiClientEMS "
            "7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute "
            "unauthorized code or commands via crafted requests."
        ),
        "title": (
            "Unauthorized Code Execution via Improper Access Control in "
            "FortiClientEMS 7.4.5-7.4.6"
        ),
    },
    response_only=True,
)

VENDOR_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List vendors item",
    value={
        "created_at": "2026-07-06T09:56:15.261Z",
        "updated_at": "2026-07-06T09:56:15.261Z",
        "name": "fortinet",
    },
    response_only=True,
)

PRODUCT_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List products item",
    value={
        "created_at": "2026-07-06T10:21:58.424Z",
        "updated_at": "2026-07-06T10:21:58.424Z",
        "name": "antivirus_engine",
    },
    response_only=True,
)

WEAKNESS_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List weaknesses item",
    value={
        "created_at": "2024-09-06T08:16:54Z",
        "updated_at": "2026-06-11T11:05:32Z",
        "cwe_id": "CWE-521",
        "name": "Weak Password Requirements",
        "description": (
            "The product does not require that users should have strong passwords."
        ),
    },
    response_only=True,
)

CVE_RETRIEVE_RESPONSE_EXAMPLE = OpenApiExample(
    "CVE detail",
    value={
        "created_at": "2026-04-04T00:38:35Z",
        "updated_at": "2026-06-02T14:45:10Z",
        "cve_id": "CVE-2026-35616",
        "description": (
            "A improper access control vulnerability in Fortinet FortiClientEMS "
            "7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute "
            "unauthorized code or commands via crafted requests."
        ),
        "title": (
            "Unauthorized Code Execution via Improper Access Control in "
            "FortiClientEMS 7.4.5-7.4.6"
        ),
        "metrics": {
            "kev": {
                "data": {
                    "dueDate": "2026-04-09T00:00:00+00:00",
                    "dateAdded": "2026-04-06T00:00:00+00:00",
                },
                "provider": "cisa",
            },
            "epss": {
                "data": {"score": 0.35653},
                "provider": "first",
            },
            "ssvc": {
                "data": {
                    "options": {
                        "Automatable": "yes",
                        "Exploitation": "active",
                        "Technical Impact": "total",
                    },
                    "version": "2.0.3",
                },
                "provider": "vulnrichment",
            },
            "cvssV2_0": {"data": {}, "provider": None},
            "cvssV3_0": {"data": {}, "provider": None},
            "cvssV3_1": {
                "data": {
                    "score": 9.1,
                    "vector": (
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
                    ),
                },
                "provider": "mitre",
            },
            "cvssV4_0": {"data": {}, "provider": None},
            "threat_severity": {"data": None, "provider": None},
        },
        "weaknesses": ["CWE-284"],
        "vendors": [
            "fortinet",
            "fortinet$PRODUCT$forticlientems",
        ],
    },
    response_only=True,
)

PROJECT_CVE_DETAIL_RESPONSE_EXAMPLE = OpenApiExample(
    "Project CVE detail",
    value={
        "created_at": "2026-06-01T07:51:56Z",
        "updated_at": "2026-06-02T18:49:13Z",
        "cve_id": "CVE-2026-41084",
        "description": (
            "A bug in Apache Airflow's bulk Task Instances API allows an authenticated "
            "user with edit permission on one Dag to mutate Task Instance state in any "
            "other Dag via the request body."
        ),
        "title": (
            "Apache Airflow: API authorization bypass: bulk TaskInstances allows "
            "cross-DAG mutation"
        ),
        "metrics": {
            "kev": {"data": {}, "provider": None},
            "epss": {"data": {"score": 0.0008}, "provider": "first"},
            "ssvc": {
                "data": {
                    "options": {
                        "Automatable": "yes",
                        "Exploitation": "none",
                        "Technical Impact": "partial",
                    },
                    "version": "2.0.3",
                },
                "provider": "vulnrichment",
            },
            "cvssV2_0": {"data": {}, "provider": None},
            "cvssV3_0": {"data": {}, "provider": None},
            "cvssV3_1": {
                "data": {
                    "score": 7.5,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                },
                "provider": "vulnrichment",
            },
            "cvssV4_0": {"data": {}, "provider": None},
            "threat_severity": {"data": None, "provider": None},
        },
        "tracker": {
            "status": "to_evaluate",
            "assignee": {"email": "user@example.com"},
            "assigned_at": "2026-07-03T09:14:59Z",
            "updated_at": "2026-07-03T09:15:01Z",
        },
    },
    response_only=True,
)

PROJECT_CVE_TRACKER_UPDATE_REQUEST_EXAMPLE = OpenApiExample(
    "Update project CVE tracker",
    value={
        "status": "to_evaluate",
        "assignee": "user@example.com",
    },
    request_only=True,
)


PROJECT_CREATE_EXAMPLE = OpenApiExample(
    "Create project",
    value={
        "name": "production",
        "description": "Production infrastructure monitoring",
        "active": True,
    },
    request_only=True,
)

PROJECT_CREATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Created project",
    value={
        "id": "e9f53830-1a88-4292-9995-0748d2d7bcfb",
        "created_at": "2026-06-29T10:31:05.417496Z",
        "updated_at": "2026-06-29T10:31:05.417496Z",
        "name": "production",
        "description": "Production infrastructure monitoring",
        "active": True,
        "subscriptions_count": 0,
        "subscriptions": {
            "vendors": [],
            "products": {},
        },
    },
    response_only=True,
)

PROJECT_UPDATE_EXAMPLE = OpenApiExample(
    "Update project",
    value={
        "name": "production",
        "description": "Updated description",
        "active": False,
    },
    request_only=True,
)

PROJECT_UPDATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Updated project",
    value={
        "name": "production",
        "description": "Updated description",
        "active": False,
    },
    response_only=True,
)

PROJECT_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List projects",
    value={
        "id": "0c05fee9-ae88-4fc0-9f45-5e0ec861cc9e",
        "created_at": "2025-11-03T14:28:36.003066Z",
        "updated_at": "2026-06-29T10:27:55.587006Z",
        "name": "production",
        "description": "Production infrastructure monitoring",
        "active": True,
        "subscriptions_count": 3,
    },
    response_only=True,
)

PROJECT_DETAIL_RESPONSE_EXAMPLE = OpenApiExample(
    "Project detail",
    value={
        "id": "e9f53830-1a88-4292-9995-0748d2d7bcfb",
        "created_at": "2026-06-29T10:31:05.417496Z",
        "updated_at": "2026-06-29T10:36:38.084220Z",
        "name": "production",
        "description": "Production infrastructure monitoring",
        "active": True,
        "subscriptions_count": 4,
        "subscriptions": {
            "vendors": ["fortinet"],
            "products": {
                "apache": ["log4j"],
                "debian": ["debian_linux"],
                "cisco": ["cisco_ios"],
            },
        },
    },
    response_only=True,
)

SUBSCRIPTION_LIST_RESPONSE_EXAMPLE = OpenApiExample(
    "Project subscriptions",
    value={
        "vendors": [
            "fortinet",
            "python",
        ],
        "products": {
            "apache": [
                "airflow",
                "log4j",
            ],
            "debian": [
                "debian_linux",
            ],
        },
    },
    response_only=True,
)

SUBSCRIPTION_CREATE_REQUEST_EXAMPLE = OpenApiExample(
    "Add product subscription",
    value={
        "vendor": "apache",
        "product": "airflow",
    },
    request_only=True,
)

SUBSCRIPTION_REPLACE_REQUEST_EXAMPLE = OpenApiExample(
    "Replace all subscriptions",
    value={
        "vendors": ["python"],
        "products": {
            "apache": ["airflow"],
        },
    },
    request_only=True,
)

SUBSCRIPTION_DELETE_QUERY_PARAMS = [
    OpenApiParameter(
        "vendor",
        str,
        OpenApiParameter.QUERY,
        required=True,
        description="Vendor slug to unsubscribe from.",
    ),
    OpenApiParameter(
        "product",
        str,
        OpenApiParameter.QUERY,
        required=False,
        description="Product slug. Omit to unsubscribe from the whole vendor.",
    ),
]

AUTOMATION_REPORT_CONFIGURATION_EXAMPLE = {
    "actions": [
        {
            "type": "generate_report",
            "value": True,
        }
    ],
    "conditions": {
        "children": [
            {
                "children": [
                    {"type": "kev_present", "value": True},
                ],
                "operator": "AND",
            }
        ],
        "operator": "OR",
    },
}

AUTOMATION_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List automations",
    value={
        "id": "17c80661-fec3-45e2-9027-303f6a5c4a60",
        "created_at": "2026-06-29T13:10:33.567313Z",
        "updated_at": "2026-06-29T13:10:33.585596Z",
        "name": "Weekly KEV report",
        "is_enabled": True,
        "trigger_type": "report",
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_time": "09:00:00",
        "schedule_weekday": "monday",
        "last_execution_at": None,
        "conditions_count": 1,
    },
    response_only=True,
)

AUTOMATION_CREATE_REQUEST_EXAMPLE = OpenApiExample(
    "Create automation",
    value={
        "name": "Weekly KEV report",
        "is_enabled": True,
        "trigger_type": "report",
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_time": "09:00:00",
        "schedule_weekday": "monday",
        "configuration": AUTOMATION_REPORT_CONFIGURATION_EXAMPLE,
    },
    request_only=True,
)

AUTOMATION_CREATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Created automation",
    value={
        "id": "f432bcf7-411b-4391-9c67-dc354fff8ce2",
        "created_at": "2026-06-29T13:30:41.522934Z",
        "updated_at": "2026-06-29T13:30:41.522982Z",
        "name": "Weekly KEV report",
        "is_enabled": True,
        "trigger_type": "report",
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_time": "09:00:00",
        "schedule_weekday": "monday",
        "last_execution_at": None,
        "conditions_count": 1,
        "configuration": AUTOMATION_REPORT_CONFIGURATION_EXAMPLE,
    },
    response_only=True,
)

AUTOMATION_DETAIL_RESPONSE_EXAMPLE = OpenApiExample(
    "Automation detail",
    value={
        "id": "17c80661-fec3-45e2-9027-303f6a5c4a60",
        "created_at": "2026-06-29T13:10:33.567313Z",
        "updated_at": "2026-06-29T13:10:33.585596Z",
        "name": "Weekly KEV report",
        "is_enabled": True,
        "trigger_type": "report",
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_time": "09:00:00",
        "schedule_weekday": "monday",
        "last_execution_at": None,
        "conditions_count": 1,
        "configuration": AUTOMATION_REPORT_CONFIGURATION_EXAMPLE,
    },
    response_only=True,
)

AUTOMATION_UPDATE_REQUEST_EXAMPLE = OpenApiExample(
    "Update automation",
    value={
        "name": "Edited automation",
        "is_enabled": True,
        "trigger_type": "report",
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_time": "09:00:00",
        "schedule_weekday": "monday",
        "configuration": AUTOMATION_REPORT_CONFIGURATION_EXAMPLE,
    },
    request_only=True,
)

AUTOMATION_UPDATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Updated automation",
    value={
        "id": "bc7e1491-4604-4f54-a939-91d8d16831ff",
        "created_at": "2026-06-29T14:52:09.465418Z",
        "updated_at": "2026-06-29T14:54:09.761635Z",
        "name": "Edited automation",
        "is_enabled": True,
        "trigger_type": "report",
        "frequency": "weekly",
        "schedule_timezone": "UTC",
        "schedule_time": "09:00:00",
        "schedule_weekday": "monday",
        "last_execution_at": None,
        "conditions_count": 1,
        "configuration": AUTOMATION_REPORT_CONFIGURATION_EXAMPLE,
    },
    response_only=True,
)

AUTOMATION_EXECUTION_EXAMPLE = {
    "id": "f0118a9e-f336-432f-8f83-b8cf6381d839",
    "created_at": "2026-06-05T11:02:18.436991Z",
    "executed_at": "2026-06-05T10:59:59Z",
    "window_start": "2026-06-05T10:00:00Z",
    "window_end": "2026-06-05T10:59:59Z",
    "matched_cves_count": 1,
    "impact_summary": {
        "epss_avg": 0,
        "epss_max": 0,
        "kev_count": 0,
        "cves_count": 1,
        "kev_percent": 0,
        "average_cvss": 6.3,
        "highest_cvss": 6.3,
        "cvss_distribution": {
            "Low": 0,
            "High": 0,
            "Medium": 1,
            "Critical": 0,
        },
        "epss_distribution": {
            "low": 1,
            "high": 0,
            "medium": 0,
        },
        "highest_cvss_version": "cvss_40",
        "top_vendors_products": [
            {
                "name": "python",
                "count": 1,
            }
        ],
    },
    "cves_table_data": [
        {
            "kev": False,
            "epss": 0.00042,
            "cve_id": "CVE-2026-3276",
            "cvss_20": None,
            "cvss_30": None,
            "cvss_31": 5.3,
            "cvss_40": 6.3,
            "matched_vendors_or_products": ["python"],
        }
    ],
}

AUTOMATION_EXECUTION_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List automation executions",
    value=AUTOMATION_EXECUTION_EXAMPLE,
    response_only=True,
)

AUTOMATION_EXECUTION_DETAIL_RESPONSE_EXAMPLE = OpenApiExample(
    "Automation execution detail",
    value={
        **AUTOMATION_EXECUTION_EXAMPLE,
        "results": [
            {
                "id": "a48bfdb2-66d2-445a-ad44-0f3c99389f36",
                "output_type": "notification_sent",
                "label": "Notification sent",
                "status": "success",
                "details": {
                    "status": "delivered",
                    "channel": "Mail to Security team",
                    "response_body": "2.0.0 Ok: queued as 7A5062033D",
                },
                "created_at": "2026-06-05T11:02:18.593269Z",
            }
        ],
    },
    response_only=True,
)

ORGANIZATION_LIST_ITEM_EXAMPLE = OpenApiExample(
    "List organizations",
    value={
        "id": "578bc805-be77-4fab-8709-e074e44d3108",
        "created_at": "2026-06-15T14:22:31Z",
        "updated_at": "2026-06-28T09:15:42Z",
        "name": "acme",
        "members_count": 3,
        "projects_count": 5,
    },
    response_only=True,
)

ORGANIZATION_UPDATE_REQUEST_EXAMPLE = OpenApiExample(
    "Update organization",
    value={"name": "acme"},
    request_only=True,
)

ORGANIZATION_UPDATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Updated organization",
    value={"name": "acme"},
    response_only=True,
)

AUDIT_LOG_LIST_ITEM_EXAMPLE = OpenApiExample(
    "Audit log entry",
    value={
        "id": 1103894,
        "timestamp": "2026-06-29T10:12:51.028182Z",
        "action": 1,
        "actor": "admin",
        "resource": "Organization",
        "object_repr": "acme",
        "changes": {
            "name": [
                "acme-corp",
                "acme",
            ]
        },
    },
    response_only=True,
)

NOTIFICATION_LIST_ITEM_EXAMPLE = OpenApiExample(
    "Notification list item",
    value={
        "id": "4c05bb40-eae7-4797-b105-54fd482484dd",
        "created_at": "2025-11-10T14:02:23.597126Z",
        "updated_at": "2026-06-04T13:05:25.569338Z",
        "name": "Mail to Security team",
        "type": "email",
        "is_enabled": False,
        "configuration": {
            "email": "user@example.com",
        },
        "is_pending_email_confirmation": False,
    },
    response_only=True,
)

CVE_CHANGE_LIST_ITEM_EXAMPLE = {
    "id": "0cb50971-e21e-4495-ad23-27734cf6a2a1",
    "created_at": "2026-06-02T15:00:00Z",
    "updated_at": "2026-06-02T15:00:00Z",
    "cve_id": "CVE-2026-35616",
    "types": ["title", "description"],
}

CVE_CHANGE_LIST_RESPONSE_EXAMPLE = OpenApiExample(
    "CVE change list",
    value={
        "count": 1,
        "next": None,
        "previous": None,
        "results": [CVE_CHANGE_LIST_ITEM_EXAMPLE],
    },
    response_only=True,
)

CVE_CHANGE_DETAIL_RESPONSE_EXAMPLE = OpenApiExample(
    "CVE change detail",
    value={
        **CVE_CHANGE_LIST_ITEM_EXAMPLE,
        "types": ["title"],
        "change_data": {
            "created": "2026-06-02T15:00:00+00:00",
            "data": [
                {
                    "details": {
                        "new": (
                            "Unauthorized Code Execution via Improper Access Control in "
                            "FortiClientEMS 7.4.5-7.4.6"
                        ),
                        "old": None,
                    },
                    "type": "title",
                }
            ],
            "id": "0cb50971-e21e-4495-ad23-27734cf6a2a1",
        },
    },
    response_only=True,
)

NOTIFICATION_RESPONSE_EXAMPLE = OpenApiExample(
    "Notification detail",
    value={
        "id": "251999b0-a081-4a1e-a0c2-1eef7a1130d7",
        "created_at": "2026-07-03T10:14:51.419117Z",
        "updated_at": "2026-07-03T10:14:51.419151Z",
        "name": "Mail to Security team",
        "type": "email",
        "is_enabled": True,
        "configuration": {
            "email": "security@example.com",
        },
        "is_pending_email_confirmation": True,
    },
    response_only=True,
)

NOTIFICATION_CREATE_REQUEST_EXAMPLE = OpenApiExample(
    "Create email notification",
    value={
        "name": "Mail to Security team",
        "type": "email",
        "configuration": {
            "email": "security@example.com",
        },
    },
    request_only=True,
)

NOTIFICATION_UPDATE_REQUEST_EXAMPLE = OpenApiExample(
    "Update email notification",
    value={
        "name": "Mail to Security team",
        "configuration": {
            "email": "security@example.com",
        },
    },
    request_only=True,
)

MEMBERSHIP_CREATE_REQUEST_EXAMPLE = OpenApiExample(
    "Invite member",
    value={
        "role": "member",
        "email": "user@example.com",
    },
    request_only=True,
)

MEMBERSHIP_CREATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Invited member",
    value={
        "id": 37756,
        "role": "member",
        "email": "user@example.com",
        "date_invited": "2026-06-29T10:16:53.085248Z",
        "date_joined": None,
        "is_invited": True,
    },
    response_only=True,
)

MEMBERSHIP_UPDATE_REQUEST_EXAMPLE = OpenApiExample(
    "Update member role",
    value={"role": "owner"},
    request_only=True,
)

MEMBERSHIP_UPDATE_RESPONSE_EXAMPLE = OpenApiExample(
    "Updated member",
    value={
        "id": 37756,
        "role": "owner",
        "email": "user@example.com",
        "date_invited": "2026-06-29T10:16:53.085248Z",
        "date_joined": None,
        "is_invited": True,
    },
    response_only=True,
)


REPORT_LIST_ITEM_EXAMPLE = OpenApiExample(
    "Report list item",
    value={
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "created_at": "2026-07-01T09:00:00Z",
        "updated_at": "2026-07-01T09:00:00Z",
        "day": "2026-07-01",
        "period_type": "daily",
        "period_timezone": "UTC",
        "cves_count": 2,
    },
    response_only=True,
)

REPORT_DETAIL_RESPONSE_EXAMPLE = OpenApiExample(
    "Report detail",
    value={
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "created_at": "2026-07-01T09:00:00Z",
        "updated_at": "2026-07-01T09:00:00Z",
        "day": "2026-07-01",
        "period_type": "daily",
        "period_timezone": "UTC",
        "cves_count": 2,
        "ai_summary": {
            "html": (
                "Two vulnerabilities were detected during this period, "
                "including one critical issue."
            ),
        },
        "cves": [
            {
                "created_at": "2026-04-04T00:38:35Z",
                "updated_at": "2026-06-02T14:45:10Z",
                "cve_id": "CVE-2026-35616",
                "description": (
                    "A improper access control vulnerability in Fortinet FortiClientEMS "
                    "7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute "
                    "unauthorized code or commands via crafted requests."
                ),
                "title": (
                    "Unauthorized Code Execution via Improper Access Control in "
                    "FortiClientEMS 7.4.5-7.4.6"
                ),
            },
            {
                "created_at": "2026-03-10T12:00:00Z",
                "updated_at": "2026-05-20T08:30:00Z",
                "cve_id": "CVE-2026-12345",
                "description": "An example vulnerability description.",
                "title": "Example vulnerability title",
            },
        ],
    },
    response_only=True,
)


def preprocessing_filter(endpoints):
    return [endpoint for endpoint in endpoints if endpoint[0].startswith("/api/v2/")]


class SpectacularAPIView(DrfSpectacularAPIView):
    custom_settings = {
        "TITLE": "OpenCVE API v2",
        "VERSION": "2026-06-24",
        "DESCRIPTION": (
            "OpenCVE API v2 provides read and write access to the CVE catalog, "
            "organizations, projects, subscriptions, CVE triage, notifications, "
            "automations, reports, and audit logs.\n\n"
            "All endpoints are available under `/api/v2/` and require an "
            "Organization API Token using Bearer authentication.\n\n"
            "[Read the API documentation →](https://docs.opencve.io/api/)\n\n"
            "Use the **Authorize** button to authenticate and try requests directly "
            "from this page."
        ),
        "PREPROCESSING_HOOKS": [
            "opencve.api.v2.openapi.preprocessing_filter",
        ],
        "SERVERS": [{"url": "/api/v2"}],
        "SCHEMA_PATH_PREFIX": "/api/v2",
        "SCHEMA_PATH_PREFIX_TRIM": True,
        "PARSER_WHITELIST": ["rest_framework.parsers.JSONParser"],
        "TAGS": [
            {"name": CVES_TAG},
            {"name": VENDORS_TAG},
            {"name": WEAKNESSES_TAG},
            {"name": ORGANIZATIONS_TAG, "description": "Organization settings."},
            {"name": MEMBERS_TAG, "description": "Organization members."},
            {
                "name": AUDIT_LOGS_TAG,
                "description": "Organization audit log entries.",
            },
            {"name": PROJECTS_TAG, "description": "Project settings."},
            {
                "name": SUBSCRIPTIONS_TAG,
                "description": "Vendor and product subscriptions for a project.",
            },
            {
                "name": TRACKER_TAG,
                "description": "CVE tracking within a project (status, assignee).",
            },
            {
                "name": NOTIFICATIONS_TAG,
                "description": "Notification channels configured for a project.",
            },
            {
                "name": AUTOMATIONS_TAG,
                "description": "Automation rules and execution history.",
            },
            {
                "name": REPORTS_TAG,
                "description": "Reports generated by report automations.",
            },
        ],
        "SWAGGER_UI_SETTINGS": {
            "persistAuthorization": True,
            "tryItOutEnabled": True,
        },
        "ENUM_NAME_OVERRIDES": {
            "PeriodFrequencyEnum": "changes.models.Report.PERIOD_CHOICES",
        },
    }


class SpectacularSwaggerView(DrfSpectacularSwaggerView):
    title = "OpenCVE API v2"
