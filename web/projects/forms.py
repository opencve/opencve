from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Button, Div, Field, Layout, Submit
from django import forms
from django.conf import settings
from django.db.models import Q

from cves.constants import CVSS_SCORES
from projects.models import Notification, Project, CveTracker
from users.models import User
from views.models import View as SavedView

FORM_MAPPING = {
    "email": ["email"],
    "webhook": ["url", "headers"],
    "slack": ["webhook_url"],
}


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ["name", "description", "active"]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super(ProjectForm, self).__init__(*args, **kwargs)

        # Add help text to name field only when editing
        if self.instance and not self.instance._state.adding:
            self.fields["name"].help_text = (
                "Renaming the project will break any external links to it, as the URL changes."
            )

        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "description",
            "active",
            FormActions(
                HTML(
                    """
                    <a href="{% url 'list_projects' org_name=request.current_organization.name %}" class="btn btn-default">
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

        # Check if the project already exists for this user
        if self.instance.name != name:
            if Project.objects.filter(
                organization=self.request.current_organization, name=name
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
        # Hide "Enabled" on create; on edit, hide for email until confirmation
        # Use _state.adding because UUID primary key is set before save()
        if self.instance._state.adding:
            self.fields.pop("is_enabled", None)
        elif self.instance.type == "email":
            extras = self.instance.configuration.get("extras") or {}
            if extras.get("confirmation_token"):
                self.fields.pop("is_enabled", None)

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


class CveTrackerFilterForm(forms.Form):
    """Form for filtering CVEs by assignee, status, and query"""

    assignee = forms.ChoiceField(
        choices=[],
        required=False,
        widget=forms.Select(attrs={"class": "form-control select2-assignee"}),
    )

    status = forms.ChoiceField(
        choices=[("", "All statuses")] + CveTracker.STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={"class": "form-control select2-status"}),
    )

    query = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "e.g., kev:true AND cvss31>=8",
            }
        ),
    )

    view = forms.ChoiceField(
        choices=[],
        required=False,
        widget=forms.Select(attrs={"class": "form-control select2-view"}),
    )

    def __init__(self, *args, **kwargs):
        organization = kwargs.pop("organization", None)
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)

        if organization:
            # Only show organization members in the assignee dropdown
            members = (
                User.objects.filter(
                    membership__organization=organization,
                    membership__date_joined__isnull=False,
                )
                .distinct()
                .order_by("username")
            )
            self.fields["assignee"].choices = [("", "All assignees")] + [
                (user.username, user.username) for user in members
            ]

            # Show available views (public and user's private views)
            views = SavedView.objects.filter(
                Q(privacy="public", organization=organization)
                | Q(
                    privacy="private",
                    user=user,
                    organization=organization,
                )
            ).order_by("name")

            self.fields["view"].choices = [("", "All views")] + [
                (str(view.id), view.name) for view in views
            ]


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


class SlackForm(NotificationForm):
    webhook_url = forms.URLField(
        required=True,
        assume_scheme="https",
        label="Slack Webhook URL",
        help_text="Enter your Slack incoming webhook URL",
    )
