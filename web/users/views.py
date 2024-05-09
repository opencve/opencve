from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, ListView, UpdateView

from opencve.mixins import RequestViewMixin
from users.forms import PasswordChangeForm, ProfileChangeForm, UserTagForm
from users.models import CveTag, UserTag


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


class SettingsPasswordView(LoginRequiredMixin, SuccessMessageMixin, PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = "users/settings/settings_password.html"
    success_url = reverse_lazy("settings_password")
    success_message = "Your password has been updated."
