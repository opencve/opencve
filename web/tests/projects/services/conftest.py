MINIMAL_ALERT_CONFIGURATION = {
    "triggers": ["cve_enters_project"],
    "conditions": {"operator": "OR", "children": []},
    "actions": [{"type": "send_notification", "value": "notif-1"}],
}
