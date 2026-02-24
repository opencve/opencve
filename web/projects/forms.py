from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Button, Div, Field, Layout, Submit
from django import forms
from django.conf import settings
from django.db.models import Q

from cves.constants import CVSS_SCORES
from projects.models import Automation, Notification, Project, CveTracker
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

    NO_STATUS_VALUE = "__no_status__"

    assignee = forms.ChoiceField(
        choices=[],
        required=False,
        widget=forms.Select(attrs={"class": "form-control select2-assignee"}),
    )

    status = forms.MultipleChoiceField(
        choices=CveTracker.STATUS_CHOICES + [(NO_STATUS_VALUE, "No status")],
        required=False,
        widget=forms.SelectMultiple(attrs={"class": "form-control select2-status"}),
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


class AutomationOverviewForm(forms.ModelForm):
    """Form for updating only name and is_enabled from the Overview page."""

    class Meta:
        model = Automation
        fields = ["name", "is_enabled"]

    def __init__(self, *args, **kwargs):
        self.project = kwargs.pop("project", None)
        kwargs.pop("request", None)
        super().__init__(*args, **kwargs)

    def clean_name(self):
        name = self.cleaned_data["name"]
        if name in ("add",):
            raise forms.ValidationError("This name is reserved.")
        if self.project and (not self.instance.pk or self.instance.name != name):
            if Automation.objects.filter(project=self.project, name=name).exists():
                raise forms.ValidationError("This name already exists.")
        return name


class AutomationForm(forms.ModelForm):
    class Meta:
        model = Automation
        fields = ["name", "is_enabled", "trigger_type", "frequency"]

    configuration_json = forms.CharField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request", None)
        self.project = kwargs.pop("project", None)
        super(AutomationForm, self).__init__(*args, **kwargs)
        self.fields["trigger_type"].required = True
        self.fields["frequency"].required = False
        self.fields["frequency"].widget = forms.RadioSelect(
            choices=Automation.FREQUENCY_CHOICES
        )

        if self.instance and self.instance.pk:
            import json

            self.fields["configuration_json"].initial = json.dumps(
                self.instance.configuration
            )
            self.fields["trigger_type"].widget = forms.HiddenInput()
            self.fields["frequency"].widget = forms.HiddenInput()
        else:
            self.fields["trigger_type"].widget = forms.HiddenInput()

    def clean_name(self):
        name = self.cleaned_data["name"]

        # Check if the name is not a reserved keyword
        if name in ("add",):
            raise forms.ValidationError("This name is reserved.")

        # Check if the automation already exists for this project
        if self.project and (not self.instance.pk or self.instance.name != name):
            if Automation.objects.filter(project=self.project, name=name).exists():
                raise forms.ValidationError("This name already exists.")

        return name

    def clean(self):
        data = super().clean()
        trigger = data.get("trigger_type")
        frequency = data.get("frequency")
        if trigger == Automation.TRIGGER_SCHEDULED and not frequency:
            self.add_error(
                "frequency", "Frequency is required when trigger type is scheduled."
            )
        if trigger == Automation.TRIGGER_REALTIME:
            data["frequency"] = None
        return data

    def _validate_conditions_tree(self, node):
        """Validate conditions tree: { operator: OR|AND, children: [...] } or leaf { type, value }."""
        if not isinstance(node, dict):
            raise forms.ValidationError("Condition node must be an object.")
        if "operator" in node:
            if node["operator"] not in ("OR", "AND"):
                raise forms.ValidationError("Operator must be OR or AND.")
            children = node.get("children")
            if not isinstance(children, list):
                raise forms.ValidationError("Children must be a list.")
            for child in children:
                self._validate_conditions_tree(child)
        elif "type" in node:
            if "value" not in node:
                raise forms.ValidationError("Condition leaf must have 'value'.")
        else:
            raise forms.ValidationError(
                "Condition node must have 'operator' and 'children' or 'type' and 'value'."
            )

    def clean_configuration_json(self):
        import json

        config_json = self.cleaned_data.get("configuration_json", "{}")
        if not config_json:
            config_json = (
                '{"conditions": {"operator": "OR", "children": []}, "actions": []}'
            )

        try:
            config = json.loads(config_json)
            # Validate structure
            if not isinstance(config, dict):
                raise forms.ValidationError("Invalid configuration format.")
            if "conditions" not in config or "actions" not in config:
                raise forms.ValidationError(
                    "Configuration must contain 'conditions' and 'actions'."
                )
            self._validate_conditions_tree(config["conditions"])
            if not isinstance(config["actions"], list):
                raise forms.ValidationError("Actions must be a list.")
            if "triggers" in config:
                if not isinstance(config["triggers"], list):
                    raise forms.ValidationError("Triggers must be a list.")
                for t in config["triggers"]:
                    if not isinstance(t, str):
                        raise forms.ValidationError("Each trigger must be a string.")
            return config
        except json.JSONDecodeError:
            raise forms.ValidationError("Invalid JSON format.")

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.project:
            instance.project = self.project

        # Set configuration from the JSON field
        config = self.cleaned_data.get("configuration_json")
        if config:
            instance.configuration = config

        if commit:
            instance.save()
        return instance
