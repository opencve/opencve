from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Layout, Submit
from django import forms

from cves.search import Search
from views.models import View


class ViewForm(forms.ModelForm):
    class Meta:
        model = View
        fields = ["name", "query", "privacy"]
        widgets = {"query": forms.TextInput()}

    def __init__(self, *args, **kwargs):
        super(ViewForm, self).__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "query",
            "privacy",
            FormActions(
                HTML(
                    """
                    <a href="{% url 'list_views' org_name=request.current_organization.name %}" class="btn btn-default">
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

        # Check if the name is not a reserved keyword
        if name in ("add",):
            raise forms.ValidationError("This view is reserved.")

        return name

    def clean_query(self):
        query = self.cleaned_data["query"]

        search = Search(q=query)
        if not search.validate_parsing():
            raise forms.ValidationError(search.error)

        return query
