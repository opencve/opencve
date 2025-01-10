from django.utils.safestring import mark_safe
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout
from django import forms

from cves.search import Search


class SearchForm(forms.Form):
    q = forms.CharField(
        required=False,
        help_text=mark_safe(
            "Use the syntax <code>description:python AND cvss31>=8</code>. "
            'For more details, check the <a href="https://docs.opencve.io/guides/advanced_search/">Advanced Search</a> documentation.'
        ),
    )

    def __init__(self, *args, **kwargs):
        super(SearchForm, self).__init__(*args, **kwargs)
        self.fields["q"].widget.attrs["placeholder"] = "Search in CVEs database"
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "q",
        )

    def clean_q(self):
        q = self.cleaned_data["q"]

        search = Search(q=q)
        if not search.validate_parsing():
            raise forms.ValidationError(search.error)

        return q
