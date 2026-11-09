PRODUCT_SEPARATOR = "$PRODUCT$"

CVSS_SCORES = [
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
    (4, 4),
    (5, 5),
    (6, 6),
    (7, 7),
    (8, 8),
    (9, 9),
]

CVSS_VERSIONS = [
    ("v4.0", "v4.0"),
    ("v3.1", "v3.1"),
    ("v3.0", "v3.0"),
    ("v2.0", "v2.0"),
]

CVSS_NAME_MAPPING = {
    "v4": {
        "AV": "Attack Vector",
        "AC": "Attack Complexity",
        "AT": "Attack Requirements",
        "PR": "Privileges Required",
        "UI": "User Interaction",
        "VC": "VS Confidentiality",
        "VI": "VS Integrity",
        "VA": "VS Availability",
        "SC": "SS Confidentiality",
        "SI": "SS Integrity",
        "SA": "SS Availability",
    },
    "v3": {
        "AC": "Attack Complexity",
        "AV": "Attack Vector",
        "A": "Availability Impact",
        "C": "Confidentiality Impact",
        "I": "Integrity Impact",
        "PR": "Privileges Required",
        "S": "Scope",
        "UI": "User Interaction",
    },
    "v2": {
        "AC": "Access Complexity",
        "AV": "Access Vector",
        "Au": "Authentication",
        "A": "Availability Impact",
        "C": "Confidentiality Impact",
        "I": "Integrity Impact",
    },
}

CVSS_VECTORS_MAPPING = {
    "v4": {
        "AV": {
            "N": {"weight": 2, "label": "Network"},
            "A": {"weight": 1, "label": "Adjacent Network"},
            "L": {"weight": 1, "label": "Local"},
            "P": {"weight": 0, "label": "Physical"},
        },
        "AC": {"L": {"weight": 2, "label": "Low"}, "H": {"weight": 1, "label": "High"}},
        "AT": {
            "N": {"weight": 2, "label": "None"},
            "P": {"weight": 1, "label": "Present"},
        },
        "PR": {
            "N": {"weight": 2, "label": "None"},
            "L": {"weight": 1, "label": "Low"},
            "H": {"weight": 0, "label": "High"},
        },
        "UI": {
            "N": {"weight": 2, "label": "None"},
            "P": {"weight": 1, "label": "Passive"},
            "A": {"weight": 0, "label": "Active"},
        },
        "VC": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "VI": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "VA": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "SC": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "SI": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "SA": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
    },
    "v3": {
        "AC": {"L": {"weight": 2, "label": "Low"}, "H": {"weight": 1, "label": "High"}},
        "AV": {
            "N": {"weight": 2, "label": "Network"},
            "A": {"weight": 1, "label": "Adjacent Network"},
            "L": {"weight": 1, "label": "Local"},
            "P": {"weight": 0, "label": "Physical"},
        },
        "A": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "C": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "I": {
            "H": {"weight": 2, "label": "High"},
            "L": {"weight": 1, "label": "Low"},
            "N": {"weight": 0, "label": "None"},
        },
        "PR": {
            "N": {"weight": 2, "label": "None"},
            "L": {"weight": 1, "label": "Low"},
            "H": {"weight": 0, "label": "High"},
        },
        "S": {
            "C": {"weight": 2, "label": "Changed"},
            "U": {"weight": 0, "label": "Unchanged"},
        },
        "UI": {
            "N": {"weight": 2, "label": "None"},
            "R": {"weight": 1, "label": "Required"},
        },
    },
    "v2": {
        "AC": {
            "L": {"weight": 2, "label": "Low"},
            "M": {"weight": 1, "label": "Medium"},
            "H": {"weight": 0, "label": "High"},
        },
        "AV": {
            "N": {"weight": 2, "label": "Network"},
            "A": {"weight": 1, "label": "Adjacent Network"},
            "L": {"weight": 0, "label": "Local"},
        },
        "Au": {
            "N": {"weight": 2, "label": "None"},
            "S": {"weight": 1, "label": "Single"},
            "M": {"weight": 0, "label": "Multiple"},
        },
        "A": {
            "C": {"weight": 2, "label": "Complete"},
            "P": {"weight": 1, "label": "Partial"},
            "N": {"weight": 0, "label": "None"},
        },
        "C": {
            "C": {"weight": 2, "label": "Complete"},
            "P": {"weight": 1, "label": "Partial"},
            "N": {"weight": 0, "label": "None"},
        },
        "I": {
            "C": {"weight": 2, "label": "Complete"},
            "P": {"weight": 1, "label": "Partial"},
            "N": {"weight": 0, "label": "None"},
        },
    },
}

CVSS_CHART_BACKGROUNDS = {
    "info": {"color": "rgba(0,192,239,1)", "alpha": "rgba(0,192,239,0.2)"},
    "warning": {"color": "rgba(243,156,18,1)", "alpha": "rgba(243,156,18,0.2)"},
    "danger": {"color": "rgba(221,75,57,1)", "alpha": "rgba(221,75,57,0.2)"},
    "critical": {"color": "rgba(151,43,30,1)", "alpha": "rgba(151,43,30,0.2)"},
}

CVSS_HUMAN_SCORE = {
    "info": "low",
    "warning": "medium",
    "danger": "high",
    "critical": "critical",
}

# Vendors and products frequently associated with a high number of CVEs.
# A warning icon is displayed in the UI when subscribing to these entries.
#
# This list has been curated by the OpenCVE team by analyzing the vendors and
# products most frequently associated with CVEs (currently top 30 entries)

TOP_VENDORS_PRODUCTS = frozenset(
    [
        "redhat",
        "microsoft",
        "linux",
        "linux$PRODUCT$linux_kernel",
        "redhat$PRODUCT$enterprise_linux",
        "google",
        "apple",
        "oracle",
        "debian",
        "debian$PRODUCT$debian_linux",
        "wordpress",
        "wordpress$PRODUCT$wordpress",
        "microsoft$PRODUCT$windows",
        "google$PRODUCT$android",
        "ibm",
        "adobe",
        "cisco",
        "apple$PRODUCT$mac_os_x",
        "fedoraproject",
        "fedoraproject$PRODUCT$fedora",
        "apple$PRODUCT$macos",
        "microsoft$PRODUCT$windows_server_2016",
        "microsoft$PRODUCT$windows_server_2019",
        "canonical",
        "microsoft$PRODUCT$windows_10",
        "apple$PRODUCT$iphone_os",
        "canonical$PRODUCT$ubuntu_linux",
        "microsoft$PRODUCT$windows_server_2008",
        "microsoft$PRODUCT$windows_server_2012",
        "google$PRODUCT$chrome",
    ]
)

CVE_SIDEBAR_VIEWS_PREVIEW = 6
CVE_SIDEBAR_QUICK_SEARCHES_PREVIEW = 6
CVE_TRACKING_SUBSCRIPTION_MATCHES_PREVIEW = 3

CVE_QUICK_SEARCH_GROUPS = [
    {
        "label": "Prioritization",
        "items": [
            {"label": "CVEs in KEV", "query": "kev:true", "icon": "fa-shield"},
            {"label": "EPSS ≥ 80%", "query": "epss>=80", "icon": "fa-line-chart"},
            {
                "label": "Critical vulnerabilities",
                "query": "cvss40>=9",
                "icon": "fa-exclamation-triangle",
            },
            {
                "label": "High (CVSS 3.1)",
                "query": "cvss31>=7 AND cvss31<9",
                "icon": "fa-tachometer",
            },
        ],
    },
    {
        "label": "Recent activity",
        "items": [
            {
                "label": "Created in the last day",
                "query": "created<=1d",
                "icon": "fa-calendar-plus-o",
            },
            {
                "label": "Recently updated",
                "query": "updated<=7d",
                "icon": "fa-clock-o",
            },
        ],
    },
    {
        "label": "Vendors & products",
        "items": [
            {
                "label": "Apache Struts",
                "query": "vendor:apache AND product:struts",
                "icon": "fa-search",
            },
            {
                "label": "High Apache",
                "query": "vendor:apache AND cvss31>=7",
                "icon": "fa-search",
            },
            {
                "label": "Linux Kernel",
                "query": "vendor:linux AND product:linux_kernel",
                "icon": "fa-search",
            },
            {
                "label": "Microsoft critical",
                "query": "vendor:microsoft AND cvss31>=9",
                "icon": "fa-search",
            },
        ],
    },
    {
        "label": "Vulnerability types",
        "items": [
            {
                "label": "RCE (Remote Code Execution)",
                "query": "description:'remote code execution'",
                "icon": "fa-code",
            },
            {
                "label": "SQL Injection (CWE-89)",
                "query": "cwe:CWE-89",
                "icon": "fa-code",
            },
            {"label": "XSS (CWE-79)", "query": "cwe:CWE-79", "icon": "fa-code"},
        ],
    },
    {
        "label": "User tags",
        "items": [
            {
                "label": "CVEs to check",
                "query": "userTag:tocheck",
                "icon": "fa-tag",
            },
        ],
    },
]


def build_cve_quick_search_sidebar_entries(groups, preview):
    """Flatten grouped quick searches for the CVE list sidebar (headings + links)."""
    entries = []
    item_index = 0
    for group in groups:
        section_links = []
        for item in group["items"]:
            item_index += 1
            section_links.append(
                {
                    "kind": "link",
                    "hidden": item_index > preview,
                    **item,
                }
            )
        section_hidden = all(link["hidden"] for link in section_links)
        entries.append(
            {
                "kind": "heading",
                "label": group["label"],
                "hidden": section_hidden,
            }
        )
        entries.extend(section_links)
    return entries, item_index
