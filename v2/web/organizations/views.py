from django.http import JsonResponse
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import CreateView, DetailView, ListView, UpdateView, DeleteView, FormView
from django.views.generic.detail import SingleObjectMixin
from django.urls import reverse, reverse_lazy
from django.http import HttpResponseForbidden

from organizations.models import Organization, Membership
from organizations.forms import OrganizationForm, MembershipForm

# TODO: bouger ça dans un opencve/mixins.py
from users.views import RequestViewMixin


class OrganizationsListView(LoginRequiredMixin, ListView):
    context_object_name = "organizations"
    template_name = "organizations/list_organizations.html"

    def get_queryset(self):
        query = Organization.objects.filter(members=self.request.user).all()
        return query.order_by("name")


class OrganizationCreateView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, CreateView
):
    model = Organization
    form_class = OrganizationForm
    template_name = "organizations/create_organization.html"
    success_message = "The organization has been successfully created."

    def form_valid(self, form):
        response = super(OrganizationCreateView, self).form_valid(form)
        Membership.objects.create(
            user=self.request.user,
            organization=self.object,
            role=Membership.OWNER,
        )
        return response

    def get_success_url(self):
        return reverse("edit_organization", kwargs={"name": self.object.name})


class OrganizationEditView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, UpdateView
):
    model = Organization
    form_class = OrganizationForm
    template_name = "organizations/edit_organization.html"
    success_message = "The organization has been successfully updated."
    slug_field = "name"
    slug_url_kwarg = "name"
    context_object_name = "organization"

    def get_object(self, queryset=None):
        return get_object_or_404(
            Organization, members=self.request.user, name=self.kwargs["name"]
        )

    def get_form(self, form_class=None):
        form = super().get_form()
        form.fields["name"].disabled = True
        return form

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["members"] = Membership.objects.filter(organization=self.get_object())
        context["members_form"] = MembershipForm(initial={"role": Membership.MEMBER})
        return context

    def get_success_url(self):
        return reverse("edit_organization", kwargs={"name": self.object.name})


class OrganizationDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = Organization
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "organizations/delete_organization.html"
    success_message = "The organization has been deleted."
    success_url = reverse_lazy("list_organizations")

    def get_object(self, queryset=None):
        return get_object_or_404(
            Organization, members=self.request.user, name=self.kwargs["name"]
        )


class OrganizationMembersFormView(LoginRequiredMixin, SingleObjectMixin, SuccessMessageMixin, FormView):
    http_method_names = ["post"]
    form_class = MembershipForm
    model = Organization
    slug_field = "name"
    slug_url_kwarg = "name"
    success_message = "The new member has been added."

    def post(self, request, *args, **kwargs):
        object = self.get_object()
        if not Membership.objects.filter(user=request.user, organization=object, role=Membership.OWNER).exists():
            return redirect(reverse("list_organizations"))

        # TODO: check if membership already exist

        form = self.get_form_class()(request.POST)
        if not form.is_valid():
            messages.error(request, "Error in the form")
            return redirect(reverse("edit_organization", kwargs={"name": object.name}))

        print("yes ça le fait")
        return super().post(request, *args, **kwargs)

    def get_success_url(self):
        object = self.get_object()
        return reverse("edit_organization", kwargs={"name": object.name})


def change_organization(request):
    """
    This handler receive an AJAX payload and save the
    wanted organization ID in session.
    """
    if not request.method == "POST":
        return JsonResponse({"status": "error"})

    # Handle the parameters
    organization_name = request.POST.get("organization")
    if not organization_name:
        return JsonResponse({"status": "error"})

    # Check if the user is member of the organization
    organization = Organization.objects.filter(members=request.user, name=organization_name).first()
    if not organization:
        return JsonResponse({"status": "error"})

    # Save this organization in session
    request.session["user_organization_id"] = str(organization.id)
    return JsonResponse({"status": "ok"})
