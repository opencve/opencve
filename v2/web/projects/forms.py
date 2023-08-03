from django import forms

from cves.constants import CVSS_SCORES
from projects.models import Notification

FORM_MAPPING = {"slack": ["url"], "webhook": ["url", "headers"]}


class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ["name", "is_enabled"]

    # Custom fields used for the configuration
    new_cve = forms.BooleanField(required=False)
    first_time = forms.BooleanField(required=False)
    cvss = forms.BooleanField(required=False)
    cpes = forms.BooleanField(required=False)
    summary = forms.BooleanField(required=False)
    cwes = forms.BooleanField(required=False)
    references = forms.BooleanField(required=False)
    cvss_score = forms.ChoiceField(
        choices=CVSS_SCORES,
        label="Be alerted when the CVSSv3 score is greater than or equal to :",
        initial=0,
    )

    def __init__(self, *args, **kwargs):
        super(NotificationForm, self).__init__(*args, **kwargs)


class EmailForm(NotificationForm):
    def __init__(self, *args, **kwargs):
        super(EmailForm, self).__init__(*args, **kwargs)


class SlackForm(NotificationForm):
    url = forms.URLField()


class WebhookForm(NotificationForm):
    url = forms.URLField()
    headers = forms.JSONField(required=False, initial={})
