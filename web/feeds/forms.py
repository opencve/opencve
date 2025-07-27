from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit

from feeds.models import FeedToken


class FeedTokenForm(forms.ModelForm):
    """Form for creating a new feed token."""
    
    class Meta:
        model = FeedToken
        fields = ["name"]
        
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super(FeedTokenForm, self).__init__(*args, **kwargs)
        
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.add_input(Submit("submit", "Create Token"))
        
    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
        return instance