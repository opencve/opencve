from auditlog.context import disable_auditlog
from allauth.account.views import LoginView, SignupView
from allauth.socialaccount.views import ConnectionsView
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import (
    CreateView,
    DeleteView,
    ListView,
    UpdateView,
    TemplateView,
)

from opencve.mixins import RequestViewMixin
from organizations.mixins import Membership
from users.forms import PasswordChangeForm, ProfileChangeForm, UserTagForm
from users.mixin import SocialProvidersMixin
from users.models import CveTag, UserTag, User


class TagsListView(LoginRequiredMixin, ListView):
    context_object_name = "tags"
    template_name = "users/settings/tags.html"

    def get_queryset(self):
        query = UserTag.objects.filter(user=self.request.user).all()
        return query.order_by("name")


class TagCreateView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, CreateView
):
    form_class = UserTagForm
    template_name = "users/settings/tag_create_update.html"
    success_url = reverse_lazy("tags")
    success_message = "The tag has been successfully created."

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)


class TagEditView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, UpdateView
):
    model = UserTag
    form_class = UserTagForm
    template_name = "users/settings/tag_create_update.html"
    success_url = reverse_lazy("tags")
    success_message = "The tag has been successfully updated."
    slug_field = "name"
    slug_url_kwarg = "name"

    def get_object(self, queryset=None):
        return get_object_or_404(
            UserTag, user=self.request.user, name=self.kwargs["name"]
        )

    def get_form(self, form_class=None):
        form = super(TagEditView, self).get_form()
        form.fields["name"].disabled = True
        return form


class TagDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = UserTag
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "users/settings/delete_tag.html"
    success_message = "The tag has been deleted."
    success_url = reverse_lazy("tags")

    def get(self, request, *args, **kwargs):
        count = CveTag.objects.filter(
            user=self.request.user, tags__contains=kwargs["name"]
        ).count()
        if count:
            messages.error(
                self.request,
                f"The tag {kwargs['name']} is still associated to {count} CVE(s), detach them before removing the tag.",
            )
            return redirect("tags")

        return super().get(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return get_object_or_404(
            UserTag, user=self.request.user, name=self.kwargs["name"]
        )


# PROFILE views


class SettingsProfileView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    form_class = ProfileChangeForm
    template_name = "users/settings/settings_profile.html"
    success_url = reverse_lazy("settings_profile")
    success_message = "Your profile has been updated."

    def get_object(self, queryset=None):
        return self.request.user


class SettingsAccountView(LoginRequiredMixin, TemplateView):
    template_name = "users/settings/account.html"


class SettingsDeleteAccountView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = User
    template_name = "users/settings/delete_account.html"
    success_url = reverse_lazy("account_login")
    success_message = "Your account has been deleted."

    def get(self, request, *args, **kwargs):
        memberships = Membership.objects.filter(
            user=request.user, role=Membership.OWNER
        ).all()
        if memberships:
            orga_names = ", ".join([m.organization.name for m in memberships])
            message = f"""
            Your account is currently owner of the following organizations: {orga_names}.
            You must remove yourself, transfer ownership or delete these organizations before removing your account.
            """
            messages.error(self.request, message)
            return redirect("settings_account")

        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        with disable_auditlog():
            return super().post(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return self.request.user


class SettingsPasswordView(LoginRequiredMixin, SuccessMessageMixin, PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = "users/settings/settings_password.html"
    success_url = reverse_lazy("settings_password")
    success_message = "Your password has been updated."


class CustomLoginView(SocialProvidersMixin, LoginView):
    pass


class CustomSignupView(SocialProvidersMixin, SignupView):
    pass


class CustomConnectionView(LoginRequiredMixin, SocialProvidersMixin, ConnectionsView):
    success_url = reverse_lazy("settings_social")
