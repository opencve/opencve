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
        self.request = kwargs.pop("request")
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

    def clean(self):
        cleaned_data = super().clean()

        name = cleaned_data.get("name")
        privacy = cleaned_data.get("privacy")

        # Check if the name is not a reserved keyword
        if name in ("add",):
            self.add_error("name", "This view is reserved.")
            return

        # If the view is public, check if the name is unique in the organization
        if privacy == "public":
            exists = (
                View.objects.filter(
                    name=name,
                    organization=self.request.current_organization,
                    privacy="public",
                )
                .exclude(pk=self.instance.pk)
                .exists()
            )
            if exists:
                self.add_error(
                    "name",
                    "A public view with this name already exists in this organization.",
                )

        # If the view is private, check if the name is unique in the organization for the user
        elif privacy == "private":
            exists = (
                View.objects.filter(
                    name=name,
                    organization=self.request.current_organization,
                    privacy="private",
                    user=self.request.user,
                )
                .exclude(pk=self.instance.pk)
                .exists()
            )
            if exists:
                self.add_error(
                    "name",
                    "You already have a private view with this name in this organization.",
                )

    def clean_query(self):
        query = self.cleaned_data["query"]

        search = Search(q=query)
        if not search.validate_parsing():
            raise forms.ValidationError(search.error)

        return query
