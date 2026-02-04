import json

from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Layout, Submit
from django import forms
from django.conf import settings

from cves.constants import CVSS_SCORES, PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from opencve.validators import slug_regex_validator
from organizations.models import Organization


MAX_SUBSCRIPTIONS = 5


class OnboardingForm(forms.Form):
    # Step 1
    organization = forms.CharField(validators=[slug_regex_validator])
    project = forms.CharField(validators=[slug_regex_validator])

    # Step 2 (hidden, populated by JS)
    selected_subscriptions = forms.CharField(required=False, widget=forms.HiddenInput())

    # Step 3
    enable_email_notification = forms.BooleanField(required=False, initial=False)
    notification_email = forms.EmailField(required=False)
    cvss31_min = forms.ChoiceField(
        choices=CVSS_SCORES,
        required=False,
        initial=0,
        label="Minimum CVSS v3.1 score to be alerted",
    )

    def __init__(self, *args, **kwargs):
        super(OnboardingForm, self).__init__(*args, **kwargs)
        self.fields["organization"].widget.attrs["placeholder"] = "Acme"
        self.fields["organization"].help_text = (
            "The organization is the main place to manage members and projects. "
            "Tip: if you don't have one, you can use your username instead."
        )
        self.fields["project"].widget.attrs["placeholder"] = "Default"
        self.fields["project"].help_text = (
            "Projects let you organize your subscriptions and notifications "
            "based on your own categories."
        )
        self.helper = FormHelper()
        self.helper.form_tag = True
        self.helper.layout = Layout(
            "organization",
            "project",
            "selected_subscriptions",
            "enable_email_notification",
            "notification_email",
            "cvss31_min",
            FormActions(
                HTML(
                    """<a href="{% url 'settings_profile' %}" class="btn btn-default">Settings</a>"""
                ),
                Submit("save", "Finish account creation", css_class="pull-right"),
            ),
        )

    def clean_organization(self):
        name = self.cleaned_data["organization"]

        if name in ("add",):
            raise forms.ValidationError("This organization is reserved.")

        if Organization.objects.filter(name=name).exists():
            raise forms.ValidationError("This organization name is not available.")

        return name

    def clean_project(self):
        name = self.cleaned_data["project"]

        if name in ("add",):
            raise forms.ValidationError("This project is reserved.")

        return name

    def clean_selected_subscriptions(self):
        raw = self.cleaned_data.get("selected_subscriptions") or ""
        if not raw.strip():
            return []

        try:
            items = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raise forms.ValidationError("Invalid subscriptions data.")

        if not isinstance(items, list):
            raise forms.ValidationError("Invalid subscriptions data.")

        if len(items) > MAX_SUBSCRIPTIONS:
            raise forms.ValidationError(
                f"You can select at most {MAX_SUBSCRIPTIONS} vendors or products."
            )
        result = []
        for item in items:
            if not isinstance(item, str) or not item.strip():
                continue
            item = item.strip()
            if PRODUCT_SEPARATOR in item:
                parts = item.split(PRODUCT_SEPARATOR, 1)
                if len(parts) != 2:
                    raise forms.ValidationError(f"Invalid product format: {item!r}")
                vendor_name, product_name = parts[0].strip(), parts[1].strip()
                if not Product.objects.filter(
                    vendor__name=vendor_name, name=product_name
                ).exists():
                    raise forms.ValidationError(
                        f"Product does not exist: {vendor_name} / {product_name}"
                    )
                result.append(item)
            else:
                if not Vendor.objects.filter(name=item).exists():
                    raise forms.ValidationError(f"Vendor does not exist: {item!r}")
                result.append(item)

        return result

    def clean(self):
        data = super().clean()
        if data.get("enable_email_notification"):
            if not data.get("notification_email"):
                self.add_error(
                    "notification_email",
                    forms.ValidationError(
                        "Email is required when enabling notifications."
                    ),
                )
        return data
