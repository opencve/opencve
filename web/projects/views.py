import importlib
import json
import secrets
from datetime import datetime

import pyparsing as pp
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db.models import Count, Exists, OuterRef, Prefetch, Q
from django.http import Http404, JsonResponse
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import (
    CreateView,
    DeleteView,
    DetailView,
    ListView,
    TemplateView,
    UpdateView,
    View,
)

from changes.models import Change, Report
from cves.export import CVE_CSV_EXPORT_MAX_ROWS, build_cve_csv_response
from cves.models import Cve
from cves.search import Search, BadQueryException, MaxFieldsExceededException
from opencve.mixins import RequestViewMixin
from organizations.mixins import (
    OrganizationIsMemberMixin,
    OrganizationIsOwnerMixin,
)
from projects.forms import FORM_MAPPING, ProjectForm, CveTrackerFilterForm
from projects.mixins import ProjectObjectMixin, ProjectIsActiveMixin
from projects.models import Notification, Project, CveComment, CveTracker
from projects.notifications import run_notification_try
from projects.utils import send_notification_confirmation_email
from users.models import User
from views.models import View as SavedView

NOTIFICATION_TYPES = [
    "cpes",
    "created",
    "description",
    "first_time",
    "metrics",
    "references",
    "title",
    "vendors",
    "weaknesses",
]


class ProjectsListView(LoginRequiredMixin, OrganizationIsMemberMixin, ListView):
    context_object_name = "projects"
    template_name = "projects/list_projects.html"

    def get_queryset(self):
        query = Project.objects.filter(
            organization=self.request.current_organization
        ).all()
        return query.order_by("name")


class ProjectDetailView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    # TODO: change this view into a ListView based on Changes,
    #  so we'll have a pagination instead of [:10]
    model = Project
    template_name = "projects/dashboard.html"

    def _get_cve_tracking_stats(self):
        # Assignee statistics
        assignee_stats = (
            CveTracker.objects.filter(project=self.project)
            .exclude(assignee__isnull=True)
            .values("assignee__username", "assignee__id")
            .annotate(count=Count("id"))
            .order_by("-count")[:10]
        )

        # Status statistics
        status_stats = (
            CveTracker.objects.filter(project=self.project)
            .exclude(status__isnull=True)
            .values("status")
            .annotate(count=Count("id"))
            .order_by("-count")
        )

        # Prepare status display names
        status_choices_dict = dict(CveTracker.STATUS_CHOICES)
        status_stats_dict = {}
        for stat in status_stats:
            status_stats_dict[stat["status"]] = {
                "status": stat["status"],
                "status_display": status_choices_dict.get(
                    stat["status"], stat["status"]
                ),
                "count": stat["count"],
            }

        # Order status stats
        status_stats_with_labels = []
        for status_key, status_label in CveTracker.STATUS_CHOICES:
            if status_key in status_stats_dict:
                status_stats_with_labels.append(status_stats_dict[status_key])

        return {
            "assignee_stats": assignee_stats,
            "status_stats": status_stats_with_labels,
        }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project

        # Get the list of vendors and products
        vendors = (
            self.object.subscriptions["vendors"] + self.object.subscriptions["products"]
        )

        if vendors:
            query = Change.objects.select_related("cve")
            query = query.filter(cve__vendors__has_any_keys=vendors)
            context["changes"] = query.all().order_by("-created_at")[:10]
            context["cve_tracking_stats"] = self._get_cve_tracking_stats()

        # Last reports
        query = (
            Report.objects.filter(project=self.project)
            .prefetch_related("changes")
            .all()
        )
        context["reports"] = query.order_by("-created_at")[:10]

        return context


class ProjectCreateView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    CreateView,
):
    model = Project
    form_class = ProjectForm
    template_name = "projects/create_update.html"
    success_message = "The project has been successfully created."

    def form_valid(self, form):
        form.instance.organization = self.request.current_organization
        return super().form_valid(form)


class ProjectEditView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    RequestViewMixin,
    SuccessMessageMixin,
    UpdateView,
):
    model = Project
    form_class = ProjectForm
    template_name = "projects/create_update.html"
    success_message = "The project has been successfully updated."

    def get_success_url(self):
        return reverse_lazy(
            "list_projects", kwargs={"org_name": self.request.current_organization}
        )


class ProjectDeleteView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    SuccessMessageMixin,
    DeleteView,
):
    model = Project
    template_name = "projects/delete_project.html"
    success_message = "The project has been deleted."

    def get_success_url(self):
        return reverse_lazy(
            "list_projects", kwargs={"org_name": self.request.current_organization}
        )


class ProjectVulnerabilitiesView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    ListView,
):
    model = Cve
    context_object_name = "cves"
    template_name = "projects/vulnerabilities.html"
    paginate_by = 20

    def _apply_search_query(self, base_queryset, query):
        """
        Returns the filtered queryset or base_queryset if query is invalid.
        """
        if not query:
            return base_queryset

        try:
            # Validate the query parsing
            search = Search(query, self.request)
            if not search.validate_parsing():
                return base_queryset

            else:

                # Apply the search query to the base queryset
                search_queryset = search.query
                return base_queryset & search_queryset

        except (BadQueryException, MaxFieldsExceededException):
            return base_queryset
        except pp.ParseException:
            return base_queryset

    def _apply_status_filter(self, queryset, statuses):
        if not statuses:
            return queryset

        include_no_status = CveTrackerFilterForm.NO_STATUS_VALUE in statuses
        selected_statuses = [
            status
            for status in statuses
            if status and status != CveTrackerFilterForm.NO_STATUS_VALUE
        ]

        status_filter = Q()
        if selected_statuses:
            status_filter |= Q(
                trackers__project=self.project,
                trackers__status__in=selected_statuses,
            )
        if include_no_status:
            # "No status" must also match CVEs that do not have a tracker yet
            project_trackers = CveTracker.objects.filter(
                project=self.project, cve=OuterRef("pk")
            )
            project_trackers_with_status = project_trackers.exclude(
                Q(status__isnull=True) | Q(status="")
            )

            queryset = queryset.annotate(
                has_project_tracker=Exists(project_trackers),
                has_project_tracker_with_status=Exists(project_trackers_with_status),
            )
            # Keep CVEs with no tracker, or trackers where every status is empty.
            status_filter |= Q(has_project_tracker=False) | Q(
                has_project_tracker_with_status=False
            )

        if status_filter:
            queryset = queryset.filter(status_filter)

        return queryset

    def get_queryset(self):
        vendors = (
            self.project.subscriptions["vendors"]
            + self.project.subscriptions["products"]
        )
        if not vendors:
            return self.model.objects.none()

        # Base queryset filtered by project vendors
        base_queryset = (
            Cve.objects.select_related()
            .prefetch_related(
                Prefetch(
                    "trackers",
                    queryset=CveTracker.objects.filter(
                        project=self.project
                    ).select_related("assignee"),
                    to_attr="project_trackers",
                )
            )
            .filter(vendors__has_any_keys=vendors)
        )

        # Apply advanced search query if provided
        query = self.request.GET.get("query", "").strip()
        queryset = self._apply_search_query(base_queryset, query)

        # Apply filters
        assignee_username = self.request.GET.get("assignee")
        statuses = self.request.GET.getlist("status")

        if assignee_username:
            queryset = queryset.filter(
                trackers__project=self.project,
                trackers__assignee__username=assignee_username,
            )

        queryset = self._apply_status_filter(queryset, statuses)

        return queryset.order_by("-updated_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project

        # Add filter form
        filter_form = CveTrackerFilterForm(
            data=self.request.GET or None,
            organization=self.request.current_organization,
            user=self.request.user,
        )

        # Validate query if provided
        query = self.request.GET.get("query", "").strip()
        if query:
            try:
                search = Search(query, self.request)
                _ = search.query
                if not search.validate_parsing():
                    filter_form.add_error("query", search.error)
            except (BadQueryException, MaxFieldsExceededException) as e:
                filter_form.add_error("query", str(e))
            except pp.ParseException as e:
                filter_form.add_error("query", "Invalid query syntax.")

        context["filter_form"] = filter_form

        # Add organization members for dropdowns
        context["organization_members"] = (
            User.objects.filter(
                membership__organization=self.request.current_organization,
                membership__date_joined__isnull=False,
            )
            .distinct()
            .order_by("username")
        )

        # Add status choices
        context["status_choices"] = CveTracker.STATUS_CHOICES

        # Add views with their queries for JavaScript
        views = SavedView.objects.filter(
            Q(privacy="public", organization=self.request.current_organization)
            | Q(
                privacy="private",
                user=self.request.user,
                organization=self.request.current_organization,
            )
        ).order_by("name")

        context["views_data"] = [
            {"id": str(view.id), "name": view.name, "query": view.query}
            for view in views
        ]

        return context


class ProjectVulnerabilitiesCsvExportView(ProjectVulnerabilitiesView):
    """
    Export the current project vulnerabilities list (same queryset as
    ProjectVulnerabilitiesView) as CSV. Redirects with an error message if the
    result set exceeds CVE_CSV_EXPORT_MAX_ROWS.
    """

    def get(self, request, *args, **kwargs):
        self.object_list = self.get_queryset()
        count = self.object_list.count()
        if count > CVE_CSV_EXPORT_MAX_ROWS:
            messages.error(
                request,
                f"Export limit exceeded: {count} CVEs match your query. "
                "Please refine your search to export 10,000 CVEs or fewer.",
            )
            url = reverse(
                "project_vulnerabilities",
                kwargs={
                    "org_name": kwargs["org_name"],
                    "project_name": kwargs["project_name"],
                },
            )
            if request.GET:
                url += "?" + request.GET.urlencode()
            return redirect(url)
        filename = f"project-{self.project.name}-cves-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        return build_cve_csv_response(self.object_list, filename)


class ReportsView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    ListView,
):
    model = Report
    context_object_name = "reports"
    template_name = "projects/reports.html"
    paginate_by = 20

    def get_queryset(self):
        changes_with_cve_prefetch = Prefetch(
            "changes",
            queryset=Change.objects.select_related("cve"),
        )
        query = (
            Report.objects.filter(project=self.project)
            .prefetch_related(changes_with_cve_prefetch)
            .all()
        )
        return query.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        return context


class ReportView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    model = Report
    template_name = "projects/report.html"

    @staticmethod
    def get_report_statistics(report):
        changes = {}

        for db_change in report.changes.all():

            # A CVE can have several changes in one day
            if db_change.cve not in changes:
                score = db_change.cve.cvssV3_1["score"] if db_change.cve.cvssV3_1 else 0
                changes[db_change.cve] = {
                    "cve": db_change.cve,
                    "score": score,
                    "kb_changes": [],
                }

            # Parse the KB changes and select the good one
            kb_change = db_change.change_data
            if kb_change:
                changes[db_change.cve]["kb_changes"].append(
                    [db_change.created_at, kb_change]
                )

        return {"report": report, "changes": changes.values()}

    def get_object(self, queryset=None):
        # Optimize the query to return the associated events and CVE
        changes_with_cve_prefetch = Prefetch(
            "changes",
            queryset=Change.objects.select_related("cve"),
        )
        queryset = self.model.objects.prefetch_related(changes_with_cve_prefetch)

        # Return the daily report
        report = get_object_or_404(
            queryset,
            project=self.project,
            day=self.kwargs["day"],
        )

        return self.get_report_statistics(report)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        return context


class SubscriptionsView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    model = Project
    template_name = "projects/subscriptions.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        return context


class NotificationFormTryMixin:
    """
    Handle POST action=try: validate form, send test notification, re-render without saving.
    """

    def post(self, request, *args, **kwargs):
        if request.POST.get("action") == "try":
            return self._handle_notification_try(request, *args, **kwargs)
        return super().post(request, *args, **kwargs)

    def _notification_type_for_try(self) -> str:
        raise NotImplementedError

    def _prepare_object_for_try_form(self):
        """Create: no instance yet. Update: load object for ModelForm."""
        if isinstance(self, UpdateView):
            self.object = self.get_object()
        else:
            self.object = None

    def _handle_notification_try(self, request, *args, **kwargs):
        self._prepare_object_for_try_form()

        form = self.get_form()
        if not form.is_valid():
            return self.form_invalid(form)

        ntype = self._notification_type_for_try()
        extras = {
            field: form.cleaned_data[field] for field in FORM_MAPPING.get(ntype, [])
        }

        try_result = run_notification_try(
            ntype,
            extras,
            project_name=self.project.name,
            organization_name=request.current_organization.name,
            notification_name=form.cleaned_data.get("name", "Test notification"),
            project_subscriptions=(
                self.project.subscriptions.get("vendors", [])
                + self.project.subscriptions.get("products", [])
            ),
            triggered_by_email=getattr(request.user, "email", "") or "",
        )

        context = self.get_context_data()
        context["try_result"] = try_result.as_template_dict()
        return self.render_to_response(context)


class NotificationsView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    model = Project
    template_name = "projects/notifications/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["notifications"] = (
            Notification.objects.filter(project=self.project).order_by("name").all()
        )
        return context


class NotificationCreateView(
    NotificationFormTryMixin,
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    CreateView,
):
    model = Notification
    template_name = "projects/notifications/save.html"
    success_message = "The notification has been successfully created."

    def get(self, request, *args, **kwargs):
        if request.GET.get("type") not in ["email", "webhook", "slack"]:
            raise Http404()
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        types = [
            k for k, v in form.cleaned_data.items() if k in NOTIFICATION_TYPES and v
        ]

        # Extra configuration
        extras = {}
        custom_fields = FORM_MAPPING.get(self.request.GET["type"], [])
        for field in custom_fields:
            extras[field] = form.cleaned_data[field]

        notification_type = self.request.GET["type"]
        if notification_type == "email":
            form.instance.is_enabled = False
            extras["created_by_email"] = self.request.user.email
            extras["confirmation_token"] = secrets.token_urlsafe(32)
        else:
            form.instance.is_enabled = True

        # Create the notification
        form.instance.project = self.project
        form.instance.type = notification_type
        form.instance.configuration = {
            "types": types,
            "metrics": {"cvss31": form.cleaned_data["cvss31_score"]},
            "extras": extras,
        }

        response = super().form_valid(form)
        if notification_type == "email":
            send_notification_confirmation_email(form.instance, self.request)
        return response

    def get_form_class(self):
        return getattr(
            importlib.import_module("projects.forms"),
            f"{self.request.GET['type'].capitalize()}Form",
        )

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["project"] = self.project
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["type"] = self.request.GET["type"]
        context.setdefault("try_result", None)
        return context

    def _notification_type_for_try(self) -> str:
        return self.request.GET["type"]


class NotificationUpdateView(
    NotificationFormTryMixin,
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    UpdateView,
):
    model = Notification
    template_name = "projects/notifications/save.html"
    success_message = "The notification has been successfully updated."

    def get_object(self, queryset=None):
        return get_object_or_404(
            Notification,
            project=self.project,
            name=self.kwargs["notification"],
        )

    def form_valid(self, form):
        types = [
            k for k, v in form.cleaned_data.items() if k in NOTIFICATION_TYPES and v
        ]

        # Extra configuration
        extras = {}
        custom_fields = FORM_MAPPING.get(form.instance.type, [])
        for field in custom_fields:
            extras[field] = form.cleaned_data[field]

        # Preserve email-specific extras; re-trigger confirmation if email changed
        email_changed_send_confirm = False
        if form.instance.type == "email":
            existing_extras = form.instance.configuration.get("extras") or {}
            # Preserve tokens: confirmation_token (pending) or unsubscribe_token (confirmed)
            for key in ("created_by_email", "confirmation_token", "unsubscribe_token"):
                if key in existing_extras:
                    extras[key] = existing_extras[key]
            new_email = form.cleaned_data.get("email")
            old_email = existing_extras.get("email")
            if new_email and new_email != old_email:
                form.instance.is_enabled = False
                extras["confirmation_token"] = secrets.token_urlsafe(32)
                extras.pop("unsubscribe_token", None)
                email_changed_send_confirm = True

        # Create the notification
        form.instance.project = self.project
        form.instance.configuration = {
            "types": types,
            "metrics": {"cvss31": form.cleaned_data["cvss31_score"]},
            "extras": extras,
        }

        response = super().form_valid(form)
        if email_changed_send_confirm:
            send_notification_confirmation_email(form.instance, self.request)
        return response

    def get_form_class(self):
        return getattr(
            importlib.import_module("projects.forms"),
            f"{self.object.type.capitalize()}Form",
        )

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["project"] = self.project
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["type"] = self.object.type
        extras = self.object.configuration.get("extras") or {}
        context["email_pending_confirmation"] = self.object.type == "email" and bool(
            extras.get("confirmation_token")
        )

        # Transform JSON field into dedicated fields
        context["form"].initial["cvss31_score"] = self.object.configuration["metrics"][
            "cvss31"
        ]
        for _type in self.object.configuration["types"]:
            context["form"].initial[_type] = True

        custom_fields = FORM_MAPPING.get(self.object.type, [])
        for field in custom_fields:
            context["form"].initial[field] = self.object.configuration["extras"][field]

        context.setdefault("try_result", None)
        return {**context, **{"type": self.object.type}}

    def _notification_type_for_try(self) -> str:
        return self.object.type


class NotificationDeleteView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    DeleteView,
):
    model = Notification
    template_name = "projects/notifications/delete.html"
    success_message = "The notification has been successfully removed."

    def get_object(self, queryset=None):
        return get_object_or_404(
            Notification,
            project=self.project,
            name=self.kwargs["notification"],
        )

    def get_success_url(self):
        return reverse(
            "notifications",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
            },
        )


class NotificationResendConfirmationView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    View,
):
    """Resend the confirmation email for an email notification pending validation."""

    def get(self, request, *args, **kwargs):
        notification = get_object_or_404(
            Notification,
            project=self.project,
            name=self.kwargs["notification"],
        )
        if notification.type != "email":
            messages.error(request, "This notification is not an email notification.")
            return redirect(
                "edit_notification",
                org_name=request.current_organization.name,
                project_name=self.project.name,
                notification=notification.name,
            )
        extras = notification.configuration.get("extras") or {}
        if not extras.get("confirmation_token"):
            messages.info(
                request,
                "This notification is already confirmed or does not require confirmation.",
            )
            return redirect(
                "edit_notification",
                org_name=request.current_organization.name,
                project_name=self.project.name,
                notification=notification.name,
            )
        send_notification_confirmation_email(notification, request)
        messages.success(
            request,
            "A new confirmation email has been sent to %s."
            % extras.get("email", "the configured address"),
        )
        return redirect(
            "edit_notification",
            org_name=request.current_organization.name,
            project_name=self.project.name,
            notification=notification.name,
        )


class NotificationConfirmView(TemplateView):
    """
    Public view to confirm an email notification subscription (no auth required).
    """

    template_name = "projects/notifications/confirm_success.html"

    def get(self, request, *args, **kwargs):
        token = kwargs.get("token")
        notification = Notification.objects.filter(
            type="email",
            configuration__extras__confirmation_token=token,
        ).first()

        if not notification:
            return render(
                request,
                "projects/notifications/confirm_error.html",
                status=404,
            )

        notification.is_enabled = True
        config = dict(notification.configuration)
        extras = dict(config.get("extras", {}))
        extras.pop("confirmation_token", None)
        extras["unsubscribe_token"] = secrets.token_urlsafe(32)
        config["extras"] = extras
        notification.configuration = config
        notification.save(update_fields=["is_enabled", "configuration"])

        return render(
            request,
            self.template_name,
            {"notification": notification},
        )


class NotificationUnsubscribeView(TemplateView):
    """
    Public view to unsubscribe from an email notification (no auth required).
    First shows a confirmation page, then processes the unsubscribe on POST.
    """

    template_name = "projects/notifications/unsubscribe_confirm.html"

    def get_notification(self, token):
        return Notification.objects.filter(
            configuration__extras__unsubscribe_token=token,
        ).first()

    def get(self, request, *args, **kwargs):
        token = kwargs.get("token")
        notification = self.get_notification(token)

        if not notification:
            return render(
                request,
                "projects/notifications/unsubscribe_error.html",
                status=404,
            )

        # Show confirmation page; actual unsubscribe happens on POST
        return render(
            request,
            self.template_name,
            {"notification": notification},
        )

    def post(self, request, *args, **kwargs):
        token = kwargs.get("token")
        notification = self.get_notification(token)

        if not notification:
            return render(
                request,
                "projects/notifications/unsubscribe_error.html",
                status=404,
            )

        notification.is_enabled = False
        config = dict(notification.configuration)
        extras = dict(config.get("extras", {}))
        extras.pop("unsubscribe_token", None)
        extras["confirmation_token"] = secrets.token_urlsafe(32)
        config["extras"] = extras
        notification.configuration = config
        notification.save(update_fields=["is_enabled", "configuration"])

        return render(
            request,
            "projects/notifications/unsubscribe_success.html",
            {"notification": notification},
        )


class AssignCveUserView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectObjectMixin, View
):
    """AJAX endpoint to assign a user to a CVE"""

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON payload"}, status=400
            )

        cve_id = data.get("cve_id")
        assignee_id = data.get("assignee_id")

        # Get the CVE
        cve = get_object_or_404(Cve, cve_id=cve_id)

        # Get assignee if provided
        assignee = None
        if assignee_id:
            assignee = get_object_or_404(
                User,
                id=assignee_id,
                membership__organization=self.request.current_organization,
                membership__date_joined__isnull=False,
            )

        # Update tracker (will delete if no status and no assignee)
        tracker = CveTracker.update_tracker(
            project=self.project, cve=cve, assignee=assignee
        )

        if tracker is None:
            return JsonResponse(
                {
                    "success": True,
                    "assignee_username": None,
                    "status": None,
                }
            )

        return JsonResponse(
            {
                "success": True,
                "assignee_username": (
                    tracker.assignee.username if tracker.assignee else None
                ),
                "status": tracker.get_status_display() if tracker.status else None,
            }
        )


class UpdateCveStatusView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectObjectMixin, View
):
    """AJAX endpoint to update CVE status"""

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON payload"}, status=400
            )

        cve_id = data.get("cve_id")
        status = data.get("status")

        # Validate status (allow None/empty to clear status)
        if status:
            valid_statuses = [choice[0] for choice in CveTracker.STATUS_CHOICES]
            if status not in valid_statuses:
                return JsonResponse(
                    {"success": False, "error": "Invalid status"}, status=400
                )

        # Get the CVE
        cve = get_object_or_404(Cve, cve_id=cve_id)

        # Update tracker (will delete if no status and no assignee)
        tracker = CveTracker.update_tracker(
            project=self.project, cve=cve, status=status
        )

        if tracker is None:
            return JsonResponse(
                {
                    "success": True,
                    "status": None,
                }
            )

        return JsonResponse(
            {
                "success": True,
                "status": tracker.get_status_display() if tracker.status else None,
            }
        )


class CreateCveCommentView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectObjectMixin, View
):
    """AJAX endpoint to create a comment for a CVE within a project"""

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON payload"}, status=400
            )

        cve_id = data.get("cve_id")
        body = (data.get("body") or "").strip()
        parent_id = data.get("parent_id")

        # Check if the comment body is empty
        if not cve_id or not body:
            return JsonResponse(
                {"success": False, "error": "Comment body is required"}, status=400
            )

        cve = get_object_or_404(Cve, cve_id=cve_id)

        # Get the parent comment if provided
        parent = None
        if parent_id:
            parent = get_object_or_404(
                CveComment,
                id=parent_id,
                project=self.project,
                cve=cve,
            )
            # Only allow one level of replies
            if parent.parent_id:
                return JsonResponse(
                    {
                        "success": False,
                        "error": "You can only reply to top-level comments.",
                    },
                    status=400,
                )

        comment = CveComment.objects.create(
            cve=cve,
            project=self.project,
            author=request.user,
            body=body,
            parent=parent,
        )

        return JsonResponse(
            {
                "success": True,
                "comment": {
                    "id": str(comment.id),
                    "author": comment.author.username,
                    "created_at": comment.created_at.strftime("%Y-%m-%d %H:%M"),
                    "edited": False,
                    "body": comment.body,
                    "parent_id": str(parent.id) if parent else None,
                },
            }
        )


class UpdateCveCommentView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectObjectMixin, View
):
    """AJAX endpoint to update an existing CVE comment/reply"""

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON payload"}, status=400
            )

        cve_id = data.get("cve_id")
        comment_id = data.get("comment_id")
        body = (data.get("body") or "").strip()

        # Check if the comment body is empty
        if not cve_id or not comment_id or not body:
            return JsonResponse(
                {"success": False, "error": "Comment body is required"}, status=400
            )

        cve = get_object_or_404(Cve, cve_id=cve_id)
        comment = get_object_or_404(
            CveComment,
            id=comment_id,
            project=self.project,
            cve=cve,
        )

        # Check if the user is the author of the comment
        if comment.author_id != request.user.id:
            return JsonResponse({"success": False, "error": "Forbidden"}, status=403)

        comment.body = body
        comment.edited = True
        comment.save(update_fields=["body", "edited", "updated_at"])

        return JsonResponse(
            {
                "success": True,
                "comment": {
                    "id": str(comment.id),
                    "body": comment.body,
                    "display_at": comment.updated_at.strftime("%Y-%m-%d %H:%M"),
                    "edited": True,
                },
            }
        )


class DeleteCveCommentView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectObjectMixin, View
):
    """AJAX endpoint to delete an existing CVE comment/reply"""

    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON payload"}, status=400
            )

        cve_id = data.get("cve_id")
        comment_id = data.get("comment_id")

        # Check if the comment id is provided
        if not cve_id or not comment_id:
            return JsonResponse(
                {"success": False, "error": "Missing comment id"}, status=400
            )

        cve = get_object_or_404(Cve, cve_id=cve_id)
        comment = get_object_or_404(
            CveComment,
            id=comment_id,
            project=self.project,
            cve=cve,
        )

        # Check if the user is the author of the comment
        if comment.author_id != request.user.id:
            return JsonResponse({"success": False, "error": "Forbidden"}, status=403)

        comment.delete()
        return JsonResponse({"success": True, "deleted_id": comment_id})
