def get_default_configuration():
    return {
        "cvss": 0,
        "events": [
            "new_cve",
            "first_time",
            "references",
            "cvss",
            "cpes",
            "summary",
            "cwes",
        ],
    }
