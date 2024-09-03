from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from django.views.generic import (
    CreateView,
    DeleteView,
    FormView,
    ListView,
    UpdateView,
    View,
)
from django.views.generic.detail import SingleObjectMixin

from opencve.mixins import RequestViewMixin
from organizations.forms import MembershipForm, OrganizationForm
from organizations.mixins import OrganizationIsOwnerMixin
from organizations.models import Membership, Organization
from users.models import User


class OrganizationsListView(LoginRequiredMixin, ListView):
    context_object_name = "memberships"
    template_name = "organizations/list_organizations.html"

    def get_queryset(self):
        query = Membership.objects.filter(user=self.request.user).all()
        return query.order_by("organization__name")


class OrganizationCreateView(
    LoginRequiredMixin, SuccessMessageMixin, RequestViewMixin, CreateView
):
    model = Organization
    form_class = OrganizationForm
    template_name = "organizations/create_organization.html"
    success_message = "The organization has been successfully created."

    def form_valid(self, form):
        response = super(OrganizationCreateView, self).form_valid(form)
        date_now = now()
        Membership.objects.create(
            user=self.request.user,
            organization=self.object,
            role=Membership.OWNER,
            date_invited=date_now,
            date_joined=date_now,
        )
        return response

    def get_success_url(self):
        return reverse("edit_organization", kwargs={"org_name": self.object.name})


class OrganizationEditView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    UpdateView,
):
    model = Organization
    form_class = OrganizationForm
    template_name = "organizations/edit_organization.html"
    success_message = "The organization has been successfully updated."
    slug_field = "name"
    slug_url_kwarg = "org_name"
    context_object_name = "organization"

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
        return reverse("edit_organization", kwargs={"org_name": self.object.name})


class OrganizationDeleteView(
    LoginRequiredMixin, OrganizationIsOwnerMixin, SuccessMessageMixin, DeleteView
):
    model = Organization
    slug_field = "name"
    slug_url_kwarg = "org_name"
    template_name = "organizations/delete_organization.html"
    success_message = "The organization has been deleted."
    success_url = reverse_lazy("list_organizations")


class OrganizationMembersFormView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    SingleObjectMixin,
    SuccessMessageMixin,
    FormView,
):
    http_method_names = ["post"]
    form_class = MembershipForm
    model = Organization
    slug_field = "name"
    slug_url_kwarg = "org_name"
    success_message = "The new member has been added."

    def post(self, request, *args, **kwargs):
        object = self.get_object()

        # Check the form validity
        form = self.get_form_class()(request.POST)
        if not form.is_valid():
            messages.error(request, "Error in the form")
            return redirect(
                reverse("edit_organization", kwargs={"org_name": object.name})
            )

        # Check if the invited user exists
        user = User.objects.filter(email=form.cleaned_data["email"]).first()
        if not user:
            messages.error(request, "User not found")
            return redirect(
                reverse("edit_organization", kwargs={"org_name": object.name})
            )

        # Check if the member already exists
        if Membership.objects.filter(user=user, organization=object).exists():
            messages.error(request, "Member already exist")
            return redirect(
                reverse("edit_organization", kwargs={"org_name": object.name})
            )

        # Create the membership
        Membership.objects.create(
            user=user,
            organization=object,
            role=form.cleaned_data["role"],
            key=get_random_string(64).lower(),
        )

        return super().post(request, *args, **kwargs)

    def get_success_url(self):
        object = self.get_object()
        return reverse("edit_organization", kwargs={"org_name": object.name})


class OrganizationMemberDeleteView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    SuccessMessageMixin,
    DeleteView,
):
    model = Membership
    template_name = "organizations/delete_member.html"
    success_message = "The member has been removed."
    slug_url_kwarg = "member_id"

    def dispatch(self, request, *args, **kwargs):
        member = self.get_object()
        organization = member.organization
        owners = organization.membership_set.filter(role=Membership.OWNER).all()

        if len(owners) == 1 and owners[0] == member:
            messages.error(
                request, "You cannot leave this organization as you are the only owner."
            )
            return redirect(
                reverse("edit_organization", kwargs={"org_name": organization.name})
            )

        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return get_object_or_404(
            self.model,
            organization__name=self.kwargs["org_name"],
            id=self.kwargs["member_id"],
        )

    def get_success_url(self):
        removed_user = self.get_object().user

        # The current user can no longer access the organization if he removed himself
        if removed_user == self.request.user:
            return reverse_lazy("list_organizations")

        return reverse_lazy(
            "edit_organization", kwargs={"org_name": self.kwargs["org_name"]}
        )


class OrganizationInvitationView(LoginRequiredMixin, SingleObjectMixin, View):
    model = Membership

    def get(self, *args, **kwargs):
        object = self.get_object()
        object.key = None
        object.date_joined = now()
        object.save()

        messages.success(self.request, "The invitation has been accepted")

        return redirect("list_organizations")

    def get_object(self, queryset=None):
        return get_object_or_404(
            self.model, user=self.request.user, key=self.kwargs["key"].lower()
        )


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
    organization = Organization.objects.filter(
        members=request.user, name=organization_name
    ).first()
    if not organization:
        return JsonResponse({"status": "error"})

    # Save this organization in session
    request.session["user_organization_id"] = str(organization.id)
    return JsonResponse({"status": "ok"})
