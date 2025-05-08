from django.contrib.messages.views import SuccessMessageMixin
from django.db import models
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import (
    CreateView,
    DeleteView,
    ListView,
    UpdateView,
)

from opencve.mixins import RequestViewMixin
from organizations.mixins import (
    OrganizationIsMemberMixin,
)
from views.forms import ViewForm
from views.models import View


class ViewListView(OrganizationIsMemberMixin, ListView):
    model = View
    template_name = "views/list.html"
    context_object_name = "views"

    def get_queryset(self):
        return View.objects.filter(
            models.Q(privacy="public", organization=self.request.current_organization)
            | models.Q(
                privacy="private",
                user=self.request.user,
                organization=self.request.current_organization,
            )
        ).order_by("privacy")


class ViewCreateView(
    OrganizationIsMemberMixin, SuccessMessageMixin, RequestViewMixin, CreateView
):
    form_class = ViewForm
    template_name = "views/save.html"
    success_message = "The view has been successfully created."

    def form_valid(self, form):
        form.instance.organization = self.request.current_organization

        # Link the user for private views
        if form.cleaned_data["privacy"] == "private":
            form.instance.user = self.request.user

        # Public view, no associated user
        else:
            form.instance.user = None

        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy(
            "list_views", kwargs={"org_name": self.request.current_organization.name}
        )


class ViewUpdateView(
    OrganizationIsMemberMixin, SuccessMessageMixin, RequestViewMixin, UpdateView
):
    model = View
    form_class = ViewForm
    template_name = "views/save.html"
    success_message = "The view has been successfully updated."

    def get_object(self, queryset=None):
        view = get_object_or_404(
            View,
            id=self.kwargs["view_id"],
            organization=self.request.current_organization,
        )

        # Check permission
        if view.user and view.user != self.request.user:
            raise Http404()

        return view

    def get_form(self, form_class=None):
        form = super().get_form()
        form.fields["privacy"].disabled = True
        return form

    def form_valid(self, form):
        view = self.get_object()

        if form.instance.privacy != view.privacy:
            form.add_error("privacy", "You cannot change the privacy of a view.")
            return self.form_invalid(form)

        return super().form_valid(form)

    def get_success_url(self):
        return reverse_lazy(
            "list_views", kwargs={"org_name": self.request.current_organization.name}
        )


class ViewDeleteView(OrganizationIsMemberMixin, SuccessMessageMixin, DeleteView):
    model = View
    template_name = "views/delete.html"
    success_message = "The view has been successfully deleted."
    context_object_name = "view"

    def get_object(self, queryset=None):
        view = get_object_or_404(
            View,
            id=self.kwargs["view_id"],
            organization=self.request.current_organization,
        )

        # Check permission
        if view.user and view.user != self.request.user:
            raise Http404()

        return view

    def get_success_url(self):
        return reverse_lazy(
            "list_views", kwargs={"org_name": self.request.current_organization.name}
        )
