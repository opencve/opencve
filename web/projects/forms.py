from django import forms
from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Button, Div, Field, Layout, Submit

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
                    """<a href="{% url 'list_projects' orgname=request.user_organization.name %}" class="btn btn-default">Cancel</a> """
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
            if Project.objects.filter(organization=self.request.user_organization, name=name).exists():
                raise forms.ValidationError("This project already exists.")

        return name


class NotificationForm(forms.ModelForm):
    class Meta:
        model = Notification
        fields = ["name", "is_enabled"]

    # Custom fields used for the configuration
    new_cve = forms.BooleanField(required=False)
    first_time = forms.BooleanField(required=False)
    cvss = forms.BooleanField(required=False)
    cpes = forms.BooleanField(required=False)
    description = forms.BooleanField(required=False)
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
    email = forms.EmailField(required=True)


class WebhookForm(NotificationForm):
    url = forms.URLField()
    headers = forms.JSONField(required=False, initial={})
