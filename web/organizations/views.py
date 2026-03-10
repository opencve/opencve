from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from django.views.generic import (
    CreateView,
    DeleteView,
    ListView,
    TemplateView,
    UpdateView,
    View,
)
from django.views.generic.detail import SingleObjectMixin

from opencve.mixins import RequestViewMixin
from organizations.forms import (
    MembershipForm,
    OrganizationAPITokenForm,
    OrganizationForm,
)
from organizations.mixins import OrganizationIsOwnerMixin
from organizations.models import Membership, Organization, OrganizationAPIToken
from organizations.auditlog import (
    apply_audit_log_get_filters,
    build_audit_log_queryset,
    extend_audit_log_pks_with_deleted,
    get_audit_log_display_data,
    get_audit_log_filter_choices,
    get_organization_audit_log_pks,
)
from organizations.utils import (
    send_organization_invitation_email,
    send_organization_signup_invitation_email,
)
from users.models import User


class OrganizationsListView(LoginRequiredMixin, ListView):
    context_object_name = "memberships"
    template_name = "organizations/list_organizations.html"

    def get_queryset(self):
        query = (
            Membership.objects.filter(user=self.request.user)
            .select_related("organization")
            .prefetch_related("organization__membership_set__user")
            .all()
        )
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
    template_name = "organizations/edit_organization_general.html"
    success_message = "The organization has been successfully updated."
    slug_field = "name"
    slug_url_kwarg = "org_name"
    context_object_name = "organization"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["active_tab"] = "general"
        context["organization"] = self.object
        return context

    def get_success_url(self):
        return reverse(
            "edit_organization",
            kwargs={"org_name": self.object.name},
        )


class OrganizationEditMembersView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    TemplateView,
):
    template_name = "organizations/edit_organization_members.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization = self.request.current_organization
        context["organization"] = organization
        context["active_tab"] = "members"
        context["members"] = Membership.objects.filter(organization=organization)
        context["members_form"] = kwargs.get("members_form") or MembershipForm(
            initial={"role": Membership.MEMBER}
        )
        return context

    def post(self, request, *args, **kwargs):
        organization = request.current_organization

        # Check the form validity
        form = MembershipForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Error in the form")
            context = self.get_context_data(members_form=form)
            return self.render_to_response(context)

        email = form.cleaned_data["email"]

        # Check if the invited user exists
        user = User.objects.filter(email=email).first()

        # The user exists
        if user:
            # Check if he's already a member of the organization
            if Membership.objects.filter(user=user, organization=organization).exists():
                messages.error(request, "Member already exist")
                context = self.get_context_data(members_form=form)
                return self.render_to_response(context)

            # Create the membership for existing user
            membership = Membership.objects.create(
                user=user,
                organization=organization,
                role=form.cleaned_data["role"],
                key=get_random_string(64).lower(),
            )

            # Send invitation email
            send_organization_invitation_email(membership, request)
            messages.success(
                request,
                f"Invitation email has been sent to {email}",
            )

        # The user doesn't exist
        else:
            # Check if there's already a pending invitation for this email
            if Membership.objects.filter(
                email=email, organization=organization, user__isnull=True
            ).exists():
                messages.error(
                    request,
                    "An invitation has already been sent to this email address",
                )
                context = self.get_context_data(members_form=form)
                return self.render_to_response(context)

            # Create the membership with email only
            membership = Membership.objects.create(
                user=None,
                email=email,
                organization=organization,
                role=form.cleaned_data["role"],
                key=get_random_string(64).lower(),
            )

            # Send signup invitation email
            send_organization_signup_invitation_email(membership, request)
            messages.success(
                request,
                f"Signup invitation email has been sent to {email}",
            )

        return redirect(
            reverse(
                "edit_organization_members",
                kwargs={"org_name": organization.name},
            )
        )


class OrganizationEditAuditLogsView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    TemplateView,
):
    template_name = "organizations/edit_organization_audit_logs.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization = self.request.current_organization
        request = self.request

        # Collect all object primary keys related to this organization (including soft-deleted ones).
        pks_dict = get_organization_audit_log_pks(organization)
        pks_dict = extend_audit_log_pks_with_deleted(organization, pks_dict)

        # Build the base audit log queryset for all these objects.
        entries_qs = build_audit_log_queryset(pks_dict)

        users_choices, resources_choices, action_choices = get_audit_log_filter_choices(
            entries_qs
        )

        # Apply GET filters (user/resource/action/date range) to the queryset.
        entries_qs, filters = apply_audit_log_get_filters(entries_qs, request.GET)

        paginator = Paginator(entries_qs, 50)
        page_obj = paginator.get_page(request.GET.get("page"))

        # Precompute human-friendly display data and attach it to each entry instance.
        display_data = get_audit_log_display_data(page_obj.object_list)
        for entry in page_obj.object_list:
            d = display_data[entry.id]
            entry.display_changes_dict = d["display_changes_dict"]
            entry.display_object_repr = d["display_object_repr"]
            entry.resource_label = d["resource_label"]

        query_params = request.GET.copy()
        if "page" in query_params:
            del query_params["page"]

        context["organization"] = organization
        context["active_tab"] = "audit-logs"
        context["page_obj"] = page_obj
        context["paginator"] = paginator
        context["users_choices"] = users_choices
        context["resources_choices"] = resources_choices
        context["action_choices"] = action_choices
        context["filters"] = filters
        context["base_querystring"] = query_params.urlencode()

        return context


class OrganizationEditTokensView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    RequestViewMixin,
    TemplateView,
):
    template_name = "organizations/edit_organization_tokens.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization = self.request.current_organization
        context["organization"] = organization
        context["active_tab"] = "tokens"
        context["api_tokens"] = OrganizationAPIToken.objects.filter(
            organization=organization
        ).order_by("-created_at")
        context["token_form"] = kwargs.get("token_form") or OrganizationAPITokenForm()

        # Retrieve the new token from the session and display it if it exists
        new_token = self.request.session.pop("new_token", None)
        new_token_name = self.request.session.pop("new_token_name", None)
        if new_token:
            context["new_token"] = new_token
            context["new_token_name"] = new_token_name
            messages.success(
                self.request,
                f"The token {new_token_name} has been created",
            )

        return context

    def post(self, request, *args, **kwargs):
        organization = request.current_organization
        form = OrganizationAPITokenForm(request.POST)

        if form.is_valid():
            token_string = OrganizationAPIToken.create_token(
                organization=organization,
                name=form.cleaned_data["name"],
                description=form.cleaned_data["description"] or None,
                created_by=request.user,
            )

            # Store the new token in the session to display it in the template
            request.session["new_token"] = token_string
            request.session["new_token_name"] = form.cleaned_data["name"]

            # Redirect to the tokens page to display the new token
            return redirect(
                reverse(
                    "edit_organization_tokens",
                    kwargs={"org_name": organization.name},
                )
            )
        context = self.get_context_data(token_form=form)
        return self.render_to_response(context)


class OrganizationDeleteView(
    LoginRequiredMixin, OrganizationIsOwnerMixin, SuccessMessageMixin, DeleteView
):
    model = Organization
    slug_field = "name"
    slug_url_kwarg = "org_name"
    template_name = "organizations/delete_organization.html"
    success_message = "The organization has been deleted."
    success_url = reverse_lazy("list_organizations")


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
        owners = request.current_organization.membership_set.filter(
            role=Membership.OWNER,
            date_joined__isnull=False,
        ).all()

        if len(owners) == 1 and owners[0] == member:
            messages.error(
                request, "You cannot leave this organization as you are the only owner."
            )
            return redirect(
                reverse(
                    "edit_organization_members",
                    kwargs={"org_name": request.current_organization.name},
                )
            )

        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return get_object_or_404(
            self.model,
            organization=self.request.current_organization,
            id=self.kwargs["member_id"],
        )

    def get_success_url(self):
        removed_user = self.get_object().user

        # The current user can no longer access the organization if he removed himself
        if removed_user == self.request.user:
            return reverse_lazy("list_organizations")

        return reverse_lazy(
            "edit_organization_members",
            kwargs={"org_name": self.request.current_organization.name},
        )


class OrganizationMemberRoleUpdateView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    SingleObjectMixin,
    View,
):
    """Allow owners to update the role of a member who has already joined."""

    model = Membership
    http_method_names = ["post"]

    def get_object(self, queryset=None):
        return get_object_or_404(
            self.model,
            organization=self.request.current_organization,
            id=self.kwargs["member_id"],
        )

    def check_role_update_errors(self, request, membership, new_role):
        """
        Checks all possible errors before updating a member's role in the organization.
        """
        # Check if a role has been provided in the request
        if not new_role:
            return JsonResponse(
                {"status": "error", "message": "Role is required."},
                status=400,
            )

        # Check if the provided role is valid
        valid_roles = [r[0] for r in Membership.ROLES]
        if new_role not in valid_roles:
            return JsonResponse(
                {"status": "error", "message": "Invalid role."},
                status=400,
            )

        # Prevent changing role for members who have not yet joined
        if not membership.date_joined:
            return JsonResponse(
                {
                    "status": "error",
                    "message": "Cannot change role for pending invitations.",
                },
                status=400,
            )

        # Get all owners in the organization
        owners = request.current_organization.membership_set.filter(
            role=Membership.OWNER
        ).all()

        # Prevent demoting the only owner to member
        if (
            membership.role == Membership.OWNER
            and len(owners) == 1
            and new_role == Membership.MEMBER
        ):
            return JsonResponse(
                {
                    "status": "error",
                    "message": "You cannot demote the only owner of the organization.",
                },
                status=400,
            )
        return None

    def post(self, request, *args, **kwargs):
        membership = self.get_object()
        role = request.POST.get("role")

        # Run all the necessary checks before updating the role
        errors = self.check_role_update_errors(request, membership, role)
        if errors:
            return errors

        # All checks passed, update the role and save
        membership.role = role
        membership.save(update_fields=["role"])

        return JsonResponse(
            {"status": "ok", "message": "Role has been updated successfully."}
        )


class OrganizationInvitationView(LoginRequiredMixin, SingleObjectMixin, View):
    model = Membership

    def get(self, *args, **kwargs):
        membership = self.get_object()

        # Complete the invitation
        membership.key = None
        membership.date_joined = now()
        membership.save()

        messages.success(self.request, "The invitation has been accepted")

        # Change the current organization
        self.request.session["current_organization_id"] = str(
            membership.organization.id
        )

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
    request.session["current_organization_id"] = str(organization.id)
    return JsonResponse({"status": "ok"})


class OrganizationTokenDeleteView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    SuccessMessageMixin,
    DeleteView,
):
    model = OrganizationAPIToken
    template_name = "organizations/delete_token.html"
    success_message = "The API token has been revoked."
    slug_url_kwarg = "token_id"
    slug_field = "token_id"

    def get_object(self, queryset=None):
        return get_object_or_404(
            self.model,
            token_id=self.kwargs["token_id"],
            organization=self.request.current_organization,
        )

    def post(self, request, *args, **kwargs):
        """Revoke the token instead of deleting it."""
        self.object = self.get_object()
        self.object.revoke(revoked_by=request.user)
        messages.success(self.request, self.success_message)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return reverse(
            "edit_organization_tokens",
            kwargs={"org_name": self.request.current_organization.name},
        )
