from crispy_forms.helper import FormHelper
from django import forms

VIEW_CHOICES = (
    ("all", "View All CVE Changes"),
    ("subscriptions", "View Project Subscription Changes"),
)


class ActivitiesViewForm(forms.Form):
    view = forms.ChoiceField(
        widget=forms.RadioSelect(attrs={"onchange": "this.form.submit();"}),
        choices=VIEW_CHOICES,
    )

    def __init__(self, *args, **kwargs):
        super(ActivitiesViewForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_show_labels = False
