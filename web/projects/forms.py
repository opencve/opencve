from zoneinfo import available_timezones

from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Layout, Submit
from django import forms
from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from django.core.exceptions import ValidationError as DjangoValidationError

from projects.models import Automation, Notification, Project, CveTracker
from projects.services.automations import (
    SCHEDULE_FIELDS,
    normalize_automation_schedule_fields,
    validate_automation_configuration,
    validate_automation_name,
    validate_automation_schedule,
)
from projects.services.notifications import (
    validate_notification_name,
    validate_notification_outbound_url,
)
from projects.services.projects import validate_project_name
from users.models import User
from views.models import View as SavedView

COMMON_TIMEZONES = [
    "UTC",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "Asia/Singapore",
    "Asia/Kolkata",
    "Australia/Sydney",
    "Pacific/Auckland",
]

TIMEZONE_CHOICES = [
    ("", ""),
    ("Common", [(tz, tz) for tz in COMMON_TIMEZONES]),
    (
        "All timezones",
        [
            (tz, tz)
            for tz in sorted(available_timezones())
            if tz not in COMMON_TIMEZONES
        ],
    ),
]

FORM_MAPPING = {
    "email": ["email"],
    "webhook": ["url", "headers"],
    "slack": ["webhook_url"],
}

NOTIFICATION_TYPE_CHOICES = [
    (type_key, type_key.capitalize()) for type_key in FORM_MAPPING
]


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
        try:
            validate_project_name(
                name,
                organization=self.request.current_organization,
                exclude_project=None if self.instance._state.adding else self.instance,
            )
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc
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

    def clean_name(self):
        name = self.cleaned_data["name"]
        exclude = None if self.instance._state.adding else self.instance
        try:
            validate_notification_name(
                name,
                project=self.project,
                exclude_notification=exclude,
            )
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc
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

    def clean_url(self):
        try:
            return validate_notification_outbound_url(self.cleaned_data["url"])
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc


class SlackForm(NotificationForm):
    webhook_url = forms.URLField(
        required=True,
        assume_scheme="https",
        label="Slack Webhook URL",
        help_text="Enter your Slack incoming webhook URL",
    )

    def clean_webhook_url(self):
        try:
            return validate_notification_outbound_url(self.cleaned_data["webhook_url"])
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc


class AutomationForm(forms.ModelForm):
    class Meta:
        model = Automation
        fields = [
            "name",
            "is_enabled",
            "trigger_type",
            "frequency",
            "schedule_timezone",
            "schedule_time",
            "schedule_weekday",
        ]

    configuration_json = forms.CharField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        kwargs.pop("request", None)
        self.project = kwargs.pop("project", None)
        super(AutomationForm, self).__init__(*args, **kwargs)
        self.fields["trigger_type"].required = True
        self.fields["frequency"].required = False
        self.fields["schedule_timezone"] = forms.ChoiceField(
            choices=TIMEZONE_CHOICES,
            required=False,
            widget=forms.Select(attrs={"class": "form-control select2-timezone"}),
        )
        self.fields["schedule_time"].required = False
        self.fields["schedule_weekday"].required = False
        self.fields["schedule_weekday"].choices = Automation.WEEKDAY_CHOICES
        self.fields["frequency"].widget = forms.RadioSelect(
            choices=Automation.FREQUENCY_CHOICES
        )

        if self.instance and self.instance.pk:
            import json

            self.fields["configuration_json"].initial = json.dumps(
                self.instance.configuration
            )
            self.fields["trigger_type"].widget = forms.HiddenInput()
            self.fields["frequency"].widget = forms.Select(
                choices=Automation.FREQUENCY_CHOICES
            )
        else:
            self.fields["trigger_type"].widget = forms.HiddenInput()

    def clean_name(self):
        name = self.cleaned_data["name"]
        exclude = self.instance if self.instance.pk else None
        try:
            validate_automation_name(
                name,
                project=self.project,
                exclude_automation=exclude,
            )
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc
        return name

    def clean(self):
        data = super().clean()
        trigger = data.get("trigger_type")
        if not trigger:
            return data

        try:
            validate_automation_schedule(data, trigger_type=trigger)
        except DjangoValidationError as exc:
            for field, messages in exc.message_dict.items():
                for message in messages:
                    self.add_error(field, message)
            return data

        normalized = normalize_automation_schedule_fields(data, trigger_type=trigger)
        for field in SCHEDULE_FIELDS:
            data[field] = normalized[field]
        return data

    def _get_trigger_type(self):
        trigger = self.cleaned_data.get("trigger_type")
        if trigger:
            return trigger
        if self.instance and self.instance.pk:
            return self.instance.trigger_type
        return self.data.get("trigger_type")

    def clean_configuration_json(self):
        import json

        config_json = self.cleaned_data.get("configuration_json", "{}")
        if not config_json:
            config_json = (
                '{"conditions": {"operator": "OR", "children": []}, "actions": []}'
            )

        try:
            config = json.loads(config_json)
        except json.JSONDecodeError:
            raise forms.ValidationError("Invalid JSON format.")

        trigger_type = self._get_trigger_type()
        try:
            return validate_automation_configuration(
                config,
                trigger_type=trigger_type or Automation.TRIGGER_ALERT,
            )
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc

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


class AutomationAdminForm(AutomationForm):
    """Admin form for Automation with project and configuration fields."""

    class Meta(AutomationForm.Meta):
        fields = [
            "project",
            "name",
            "is_enabled",
            "trigger_type",
            "frequency",
            "schedule_timezone",
            "schedule_time",
            "schedule_weekday",
            "configuration",
            "last_execution_at",
            "created_at",
            "updated_at",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop("configuration_json", None)
        self.fields["last_execution_at"].required = False
        self.fields["created_at"].required = False
        self.fields["updated_at"].required = False
        self.fields["trigger_type"].widget = forms.Select(
            choices=Automation.TRIGGER_CHOICES
        )
        self.fields["frequency"].widget = forms.Select(
            choices=[("", "---------"), *Automation.FREQUENCY_CHOICES]
        )
        self.fields["schedule_timezone"] = forms.CharField(
            required=False,
            max_length=64,
            widget=forms.TextInput(attrs={"class": "vTextField"}),
        )
        if not self.instance._state.adding and self.instance.project_id:
            self.project = self.instance.project

    def clean(self):
        cleaned_data = super().clean()

        project = cleaned_data.get("project")
        if not project and not self.instance._state.adding and self.instance.project_id:
            project = self.instance.project

        if project:
            self.project = project

        name = cleaned_data.get("name")
        if project and name:
            try:
                validate_automation_name(
                    name,
                    project=project,
                    exclude_automation=self.instance if self.instance.pk else None,
                )
            except DjangoValidationError as exc:
                self.add_error("name", list(exc.messages)[0])

        return cleaned_data

    def clean_configuration(self):
        config = self.cleaned_data.get("configuration")
        trigger_type = self._get_trigger_type()
        try:
            return validate_automation_configuration(
                config,
                trigger_type=trigger_type or Automation.TRIGGER_ALERT,
            )
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc

    def save(self, commit=True):
        instance = forms.ModelForm.save(self, commit=False)
        instance._skip_auto_updated_at = True

        if instance._state.adding:
            if not self.cleaned_data.get("created_at"):
                instance.created_at = timezone.now()
            if not self.cleaned_data.get("updated_at"):
                instance.updated_at = timezone.now()

        if commit:
            instance.save()

        return instance
