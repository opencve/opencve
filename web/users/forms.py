from allauth.account.forms import LoginForm as BaseLoginForm
from allauth.account.forms import ResetPasswordForm, ResetPasswordKeyForm, SignupForm
from crispy_forms.bootstrap import FormActions
from crispy_forms.helper import FormHelper
from crispy_forms.layout import HTML, Button, Field, Layout, Submit
from django import forms
from django.contrib.auth.forms import PasswordChangeForm as BasePasswordChangeForm

from users.models import User, UserTag


class LoginForm(BaseLoginForm):
    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)

        self.fields["login"].widget.attrs.update({"placeholder": "Username"})
        self.fields["password"].widget.attrs.update({"placeholder": "Password"})
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "login",
            "password",
            Submit("submit", "Sign In", css_class="pull-right btn-flat"),
        )


class RegisterForm(SignupForm):
    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)

        self.fields["username"].widget.attrs.update({"placeholder": "Username"})
        self.fields["email"].widget.attrs.update({"placeholder": "Email"})
        self.fields["password1"].widget.attrs.update({"placeholder": "Password"})
        self.fields["password2"].widget.attrs.update(
            {"placeholder": "Confirm Password"}
        )
        self.fields["username"].help_text = None
        self.fields["email"].help_text = None
        self.fields["password1"].help_text = None
        self.fields["password2"].help_text = None
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "username",
            "email",
            "password1",
            "password2",
            Submit("submit", "Register", css_class="btn-block btn-flat"),
        )


class ProfileChangeForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name"]

    def __init__(self, *args, **kwargs):
        super(ProfileChangeForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            "first_name",
            "last_name",
            FormActions(
                Submit("save", "Save"),
                css_class="pull-right",
            ),
        )


class PasswordChangeForm(BasePasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super(PasswordChangeForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            "old_password",
            "new_password1",
            "new_password2",
            FormActions(
                Submit("save", "Save"),
                css_class="pull-right",
            ),
        )


class PasswordResetForm(ResetPasswordForm):
    def __init__(self, *args, **kwargs):
        super(PasswordResetForm, self).__init__(*args, **kwargs)
        self.fields["email"].widget.attrs.update({"placeholder": "Email"})
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "email",
            Submit("submit", "Reset Password", css_class="btn-block btn-flat"),
        )


class SetPasswordForm(ResetPasswordKeyForm):
    def __init__(self, *args, **kwargs):
        super(SetPasswordForm, self).__init__(*args, **kwargs)
        self.fields["password1"].widget.attrs.update({"placeholder": "Password"})
        self.fields["password2"].widget.attrs.update(
            {"placeholder": "Confirm Password"}
        )
        self.fields["password1"].help_text = None
        self.fields["password2"].help_text = None
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "password1",
            "password2",
            Submit("submit", "Reset Password", css_class="btn-block btn-flat"),
        )


class UserTagForm(forms.ModelForm):
    class Meta:
        model = UserTag
        fields = ["name", "description", "color"]

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super(UserTagForm, self).__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "description",
            FormActions(
                Field("color", css_class="colorpicker"),
                Button(
                    "generate",
                    "Generate",
                    css_class="btn btn-default btn-flat",
                    css_id="genNew",
                ),
                HTML(
                    """<span class="label label-tag preview-tag" style="color: #fff; background-color: {{form.color.value}};">preview</span>"""
                ),
            ),
            FormActions(
                HTML(
                    """<a href="{% url 'tags' %}" class="btn btn-default">Cancel</a> """
                ),
                Submit("save", "Save"),
                css_class="pull-right",
            ),
        )

    def clean_name(self):
        name = self.cleaned_data["name"]

        # Check if the tag is not a reserved keyword
        if name in ("add",):
            raise forms.ValidationError("This tag is reserved.")

        # In case of update, check if the user tried to change the name
        if (bool(self.instance.name)) and (self.instance.name != name):
            raise forms.ValidationError("Existing tags can't be renamed.")

        # Check if the tag already exists for this user
        if self.instance.name != name:
            if UserTag.objects.filter(user=self.request.user, name=name).exists():
                raise forms.ValidationError("This tag already exists.")

        return name
