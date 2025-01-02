from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Button, Div, Field, Layout, Submit
from django import forms
from django.conf import settings

from cves.constants import CVSS_SCORES
from projects.models import Notification, Project

FORM_MAPPING = {"email": ["email"], "webhook": ["url", "headers"]}


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ["name", "description", "active"]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super(ProjectForm, self).__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "description",
            "active",
            FormActions(
                HTML(
                    """
                    <a href="{% url 'list_projects' org_name=request.user_organization.name %}" class="btn btn-default">
                    Cancel
                    </a>
                    """
                ),
                Submit("save", "Save"),
                css_class="pull-right",
            ),
        )

    def clean_name(self):
        name = self.cleaned_data["name"]

        # Check if the project is not a reserved keyword
        if name in ("add",):
            raise forms.ValidationError("This project is reserved.")

        # In case of update, check if the user tried to change the name
        if (bool(self.instance.name)) and (self.instance.name != name):
            raise forms.ValidationError("Existing projects can't be renamed.")

        # Check if the project already exists for this user
        if self.instance.name != name:
            if Project.objects.filter(
                organization=self.request.user_organization, name=name
            ).exists():
                raise forms.ValidationError("This project already exists.")

        return name


class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ["name", "is_enabled"]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        self.project = kwargs.pop("project")
        super(NotificationForm, self).__init__(*args, **kwargs)

    created = forms.BooleanField(required=False)
    description = forms.BooleanField(required=False)
    title = forms.BooleanField(required=False)
    first_time = forms.BooleanField(required=False)
    weaknesses = forms.BooleanField(required=False)
    cpes = forms.BooleanField(required=False)
    vendors = forms.BooleanField(required=False)
    references = forms.BooleanField(required=False)
    metrics = forms.BooleanField(required=False)

    cvss31_score = forms.ChoiceField(
        choices=CVSS_SCORES,
        label="Be alerted when the CVSSv3.1 score is greater than or equal to :",
        initial=0,
    )

    def clean_name(self):
        name = self.cleaned_data["name"]

        # Check if the project is not a reserved keyword
        if name in ("add",):
            raise forms.ValidationError("This name is reserved.")

        # Check if the project already exists for this user
        if self.instance.name != name:
            if Notification.objects.filter(project=self.project, name=name).exists():
                raise forms.ValidationError("This name already exists.")

        return name


class EmailForm(NotificationForm):
    email = forms.EmailField(required=True)


class WebhookForm(NotificationForm):
    url = forms.URLField(assume_scheme="http" if settings.DEBUG else "https")
    headers = forms.JSONField(required=False, initial={})

    def clean_headers(self):
        headers = self.cleaned_data["headers"]

        if not headers:
            headers = {}

        else:
            # Simple parsing to check if headers are valid key=value pairs
            keys = [k for k in headers.keys() if not isinstance(k, str)]
            values = [v for v in headers.values() if not isinstance(v, str)]

            if keys or values:
                raise forms.ValidationError(
                    "HTTP headers must be in a simple key-value format"
                )

        return headers
