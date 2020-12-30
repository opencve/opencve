# Used in the Events and Alerts tables
EVENT_TYPES = [
    ("new_cve", "New CVE"),
    ("references", "References changed"),
    ("cpes", "CPEs changed"),
    ("cvss", "CVSS changed"),
    ("summary", "Summary changed"),
    ("cwes", "CWEs changed"),
]

# Used in the users model
FREQUENCIES_TYPES = [
    ("once", "Once a day"),
    ("always", "As soon as a change is detected"),
]

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

PRODUCT_SEPARATOR = "$PRODUCT$"

# This is the message sent by Flask-User in the `flash` function
EMAIL_CONFIRMATION_MESSAGE = (
    "Your email address has not yet been confirmed. Check your email Inbox "
    'and Spam folders for the confirmation email or <a href="/account/resend-'
    'email-confirmation">Re-send confirmation email</a>.'
)
