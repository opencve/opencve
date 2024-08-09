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
