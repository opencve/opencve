from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Div, Field, Layout, Submit
from django import forms
from django.core.exceptions import ValidationError as DjangoValidationError

from django.conf import settings
from django.utils.module_loading import import_string

from organizations.models import Membership, Organization, OrganizationAPIToken
from organizations.services.organizations import validate_organization_name


def get_organization_token_form_class():
    return import_string(settings.ORGANIZATION_TOKEN_FORM_CLASS)


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = [
            "name",
        ]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super(OrganizationForm, self).__init__(*args, **kwargs)

        # Add help text to name field only when editing
        if self.instance and not self.instance._state.adding:
            self.fields["name"].help_text = (
                "Renaming the organization will break any external links to it, as the URL changes."
            )

        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            FormActions(
                Submit("save", "Save"),
                css_class="pull-right",
            ),
        )

    def clean_name(self):
        name = self.cleaned_data["name"]
        instance = None if self.instance._state.adding else self.instance
        try:
            validate_organization_name(name, exclude_organization=instance)
        except DjangoValidationError as exc:
            raise forms.ValidationError(list(exc.messages)) from exc
        return name


class MembershipForm(forms.Form):
    email = forms.EmailField(label="Email")
    role = forms.ChoiceField(choices=Membership.ROLES)

    def __init__(self, *args, **kwargs):
        super(MembershipForm, self).__init__(*args, **kwargs)
        self.fields["email"].widget.attrs["placeholder"] = self.fields["email"].label
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            Div(Field("email"), css_class="col-md-6"),
            Div(Field("role"), css_class="col-md-4"),
            Div(
                FormActions(
                    Submit("save", "Add"),
                ),
                css_class="col-md-2",
            ),
        )


class OrganizationAPITokenForm(forms.Form):
    name = forms.CharField(
        max_length=100,
        required=True,
        label="Token Name",
        help_text="A descriptive name for this token (e.g., 'Production API', 'CI/CD Pipeline')",
    )
    description = forms.CharField(
        max_length=255,
        required=False,
        label="Description",
        help_text="Optional description for this token",
    )
    access_mode = forms.ChoiceField(
        choices=[
            ("read", "Read-only"),
            ("write", "Read-write"),
        ],
        initial=OrganizationAPIToken.AccessMode.READ,
        required=False,
        label="Access mode",
        help_text="Read-only tokens cannot create or modify resources via the API.",
    )

    def __init__(self, *args, **kwargs):
        # Pop request if passed (from RequestViewMixin)
        kwargs.pop("request", None)
        super(OrganizationAPITokenForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "description",
            "access_mode",
            FormActions(
                Submit("save", "Create Token"),
                css_class="pull-right",
            ),
        )

    def get_token_create_kwargs(self):
        return {
            "name": self.cleaned_data["name"],
            "description": self.cleaned_data.get("description") or None,
            "access_mode": (
                self.cleaned_data.get("access_mode")
                or OrganizationAPIToken.AccessMode.READ
            ),
            "scopes": self.cleaned_data.get("scopes", []),
        }
