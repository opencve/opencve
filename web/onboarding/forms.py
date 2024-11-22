from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Layout, Submit
from django import forms

from opencve.validators import slug_regex_validator
from organizations.models import Organization


class OnboardingForm(forms.Form):
    organization = forms.CharField(validators=[slug_regex_validator])
    project = forms.CharField(validators=[slug_regex_validator])

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
        self.helper.layout = Layout(
            "organization",
            "project",
            FormActions(
                HTML(
                    """<a href="{% url 'settings_profile' %}" class="btn btn-default">Settings</a>"""
                ),
                Submit("save", "Continue", css_class="pull-right"),
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
