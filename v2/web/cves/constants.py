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

CVSS_METRICS = {
    "v3": {
        "attackComplexity": {"low": 2, "high": 1},
        "attackVector": {"network": 2, "adjacent": 1, "adjacent_network": 1, "local": 1, "physical": 0},
        "availabilityImpact": {"high": 2, "low": 1, "none": 0},
        "confidentialityImpact": {"high": 2, "low": 1, "none": 0},
        "integrityImpact": {"high": 2, "low": 1, "none": 0},
        "privilegesRequired": {"none": 2, "low": 1, "high": 0},
        "scope": {"changed": 2, "unchanged": 0},
        "userInteraction": {"none": 2, "required": 1},
    },
    "v2": {
        "accessComplexity": {"low": 2, "medium": 1, "high": 0},
        "accessVector": {"network": 2, "adjacent_network": 1, "local": 0},
        "authentication": {"none": 2, "single": 1, "multiple": 0},
        "availabilityImpact": {"complete": 2, "partial": 1, "none": 0},
        "confidentialityImpact": {"complete": 2, "partial": 1, "none": 0},
        "integrityImpact": {"complete": 2, "partial": 1, "none": 0},
    }
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
