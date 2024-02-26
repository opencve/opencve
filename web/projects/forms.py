from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Button, Div, Field, Layout, Submit
from django import forms

from cves.constants import CVSS_SCORES
from projects.models import Notification, Project

FORM_MAPPING = {"email": ["email"], "webhook": ["url", "headers"]}


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ["name", "description"]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super(ProjectForm, self).__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "description",
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

    # Custom fields used for the configuration
    mitre_new = forms.BooleanField(required=False)
    mitre_summary = forms.BooleanField(required=False)

    nvd_new = forms.BooleanField(required=False)
    nvd_summary = forms.BooleanField(required=False)
    nvd_first_time = forms.BooleanField(required=False)
    nvd_cvss = forms.BooleanField(required=False)
    nvd_cwes = forms.BooleanField(required=False)
    nvd_references = forms.BooleanField(required=False)
    nvd_cpes = forms.BooleanField(required=False)

    cvss_score = forms.ChoiceField(
        choices=CVSS_SCORES,
        label="Be alerted when the CVSSv3 score is greater than or equal to :",
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
    url = forms.URLField()
    headers = forms.JSONField(required=False, initial={})
