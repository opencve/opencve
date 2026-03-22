import importlib
import json
import os
import secrets
import pyparsing as pp
from datetime import datetime

from django.core.files.storage import default_storage
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.core.paginator import Paginator
from django.db.models import Count, Exists, OuterRef, Prefetch, Q
from django.http import FileResponse, Http404, JsonResponse
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
from cves.utils import cvss_score_to_severity, get_highest_cvss
from opencve.mixins import RequestViewMixin
from organizations.mixins import (
    OrganizationIsMemberMixin,
    OrganizationIsOwnerMixin,
)
from projects.forms import (
    AutomationForm,
    AutomationOverviewForm,
    FORM_MAPPING,
    ProjectForm,
    CveTrackerFilterForm,
)
from projects.mixins import ProjectObjectMixin, ProjectIsActiveMixin
from projects.models import (
    Automation,
    AutomationExecution,
    AutomationRunResult,
    CveComment,
    CveTracker,
    Notification,
    Project,
)
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
        report = (
            queryset.filter(project=self.project, day=self.kwargs["day"])
            .order_by("-created_at")
            .first()
        )
        if not report:
            raise Http404()

        return self.get_report_statistics(report)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        return context


class ReportByIdView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    model = Report
    template_name = "projects/report.html"

    def get_object(self, queryset=None):
        changes_with_cve_prefetch = Prefetch(
            "changes",
            queryset=Change.objects.select_related("cve"),
        )
        queryset = self.model.objects.prefetch_related(changes_with_cve_prefetch)
        report = get_object_or_404(
            queryset,
            project=self.project,
            id=self.kwargs["report_id"],
        )
        return ReportView.get_report_statistics(report)

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


class AutomationsView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    model = Project
    template_name = "projects/automations/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        queryset = Automation.objects.filter(project=self.project).order_by("name")
        filter_type = self.request.GET.get("type")
        if filter_type == "realtime":
            queryset = queryset.filter(trigger_type=Automation.TRIGGER_REALTIME)
        elif filter_type == "scheduled":
            queryset = queryset.filter(trigger_type=Automation.TRIGGER_SCHEDULED)
        filter_status = self.request.GET.get("status")
        if filter_status == "enabled":
            queryset = queryset.filter(is_enabled=True)
        elif filter_status == "disabled":
            queryset = queryset.filter(is_enabled=False)
        context["automations"] = list(queryset)
        org_name = self.request.current_organization.name
        context["url_add_realtime"] = reverse(
            "create_automation",
            kwargs={
                "org_name": org_name,
                "project_name": self.project.name,
                "trigger_type": "realtime",
            },
        )
        context["url_add_scheduled"] = reverse(
            "create_automation",
            kwargs={
                "org_name": org_name,
                "project_name": self.project.name,
                "trigger_type": "scheduled",
            },
        )
        return context


class AutomationCreateView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    CreateView,
):
    model = Automation
    form_class = AutomationForm
    template_name = "projects/automations/save.html"
    success_message = "The automation has been successfully created."

    def get_initial(self):
        initial = super().get_initial()
        trigger_type = self.kwargs.get("trigger_type", "realtime")
        if trigger_type not in (
            Automation.TRIGGER_REALTIME,
            Automation.TRIGGER_SCHEDULED,
        ):
            trigger_type = Automation.TRIGGER_REALTIME
        initial["trigger_type"] = trigger_type
        if trigger_type == Automation.TRIGGER_SCHEDULED:
            template = self.request.GET.get("template") or ""
            if template in ("weekly_summary", "weekly_kev", "weekly_pdf"):
                initial["frequency"] = Automation.FREQUENCY_WEEKLY
                initial["schedule_weekday"] = Automation.WEEKDAY_MONDAY
            elif template == "daily_ai_summary":
                initial["frequency"] = Automation.FREQUENCY_DAILY
            else:
                initial["frequency"] = Automation.FREQUENCY_DAILY
            initial["schedule_timezone"] = "UTC"
            initial["schedule_time"] = "09:00"
        else:
            initial["frequency"] = None
        return initial

    def form_valid(self, form):
        form.instance.project = self.project
        return super().form_valid(form)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["project"] = self.project
        kwargs["request"] = self.request
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        trigger_type = self.kwargs.get("trigger_type", "realtime")
        if trigger_type not in (
            Automation.TRIGGER_REALTIME,
            Automation.TRIGGER_SCHEDULED,
        ):
            trigger_type = Automation.TRIGGER_REALTIME
        context["trigger_type"] = trigger_type

        # Add context for form: notifications, users, status choices
        context["notifications"] = (
            Notification.objects.filter(project=self.project).order_by("name").all()
        )
        context["organization_members"] = (
            User.objects.filter(
                membership__organization=self.request.current_organization,
                membership__date_joined__isnull=False,
            )
            .distinct()
            .order_by("username")
        )
        context["status_choices"] = CveTracker.STATUS_CHOICES

        # Add views for view_match condition
        views = SavedView.objects.filter(
            Q(privacy="public", organization=self.request.current_organization)
            | Q(
                privacy="private",
                user=self.request.user,
                organization=self.request.current_organization,
            )
        ).order_by("name")
        context["views"] = views

        # Serialize automation data for JavaScript (preserve submitted config on validation error)
        default_config = {
            "conditions": {"operator": "OR", "children": []},
            "actions": [],
        }
        if self.request.method == "POST":
            raw = self.request.POST.get("configuration_json")
            if raw:
                try:
                    data = json.loads(raw)
                    if (
                        isinstance(data, dict)
                        and "conditions" in data
                        and "actions" in data
                    ):
                        context["automation_data_json"] = json.dumps(data)
                        return context
                except (json.JSONDecodeError, TypeError):
                    pass
        # Pre-fill from template (GET ?template=...)
        if self.request.method == "GET":
            template_config = self._get_template_config()
            context["automation_data_json"] = (
                json.dumps(template_config)
                if template_config
                else json.dumps(default_config)
            )
        return context

    def _get_template_config(self):
        """Build configuration JSON for automation templates."""
        template = self.request.GET.get("template") or ""

        notifications = list(
            Notification.objects.filter(project=self.project).order_by("name")[:1]
        )
        members = list(
            User.objects.filter(
                membership__organization=self.request.current_organization,
                membership__date_joined__isnull=False,
            )
            .distinct()
            .order_by("username")[:1]
        )
        first_notification_id = str(notifications[0].id) if notifications else ""
        first_user_id = str(members[0].id) if members else ""

        # One AND group with no conditions
        empty_and_group = {"operator": "AND", "children": []}

        if template == "recently_published":
            return {
                "triggers": ["cve_enters_project"],
                "conditions": {"operator": "OR", "children": [empty_and_group]},
                "actions": [
                    {"type": "send_notification", "value": first_notification_id}
                ],
            }
        if template == "kev_alert":
            return {
                "triggers": ["cve_enters_project", "kev_added"],
                "conditions": {
                    "operator": "OR",
                    "children": [
                        {
                            "operator": "AND",
                            "children": [
                                {"type": "kev_present", "value": True},
                            ],
                        }
                    ],
                },
                "actions": [
                    {"type": "send_notification", "value": first_notification_id}
                ],
            }
        if template == "critical_cve":
            return {
                "triggers": ["cve_enters_project"],
                "conditions": {
                    "operator": "OR",
                    "children": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "type": "cvss_gte",
                                    "value": {"version": "v3.1", "value": 7},
                                },
                            ],
                        },
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "type": "cvss_gte",
                                    "value": {"version": "v4.0", "value": 7},
                                },
                            ],
                        },
                    ],
                },
                "actions": [
                    {"type": "send_notification", "value": first_notification_id}
                ],
            }
        if template == "auto_triage":
            actions = []
            if first_user_id:
                actions.append({"type": "assign_user", "value": first_user_id})
            actions.append({"type": "change_status", "value": "to_evaluate"})
            return {
                "triggers": ["cve_enters_project"],
                "conditions": {"operator": "OR", "children": [empty_and_group]},
                "actions": actions,
            }

        if template == "weekly_summary":
            return {
                "conditions": {"operator": "OR", "children": [empty_and_group]},
                "actions": [{"type": "generate_report", "value": True}],
            }
        if template == "weekly_kev":
            return {
                "conditions": {
                    "operator": "OR",
                    "children": [
                        {
                            "operator": "AND",
                            "children": [
                                {"type": "kev_present", "value": True},
                            ],
                        }
                    ],
                },
                "actions": [
                    {"type": "send_notification", "value": first_notification_id}
                ],
            }
        if template == "daily_ai_summary":
            return {
                "conditions": {"operator": "OR", "children": [empty_and_group]},
                "actions": [{"type": "include_ai_summary", "value": True}],
            }
        if template == "weekly_pdf":
            return {
                "conditions": {"operator": "OR", "children": [empty_and_group]},
                "actions": [{"type": "generate_pdf", "value": True}],
            }
        return None

    def get_success_url(self):
        return reverse(
            "automations",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
            },
        )


# Map automation result output_type to Font Awesome icon class (for Overview "Recent Executions" and Results page)
RESULT_TYPE_ICONS = {
    "notification_sent": "fa-envelope",
    "report": "fa-file-text-o",
    "assignment": "fa-users",
    "status_change": "fa-check-circle",
    "pdf": "fa-file-pdf-o",
    "ai_summary": "fa-lightbulb-o",
}

# Result type filter choices for the Results page (output_type, label)
RESULT_TYPE_FILTER_CHOICES = [
    ("notification_sent", "Notification"),
    ("pdf", "PDF"),
    ("report", "Report"),
    ("ai_summary", "AI Summary"),
    ("assignment", "Assignment"),
    ("status_change", "Status"),
]


def _build_activity_events(automation, limit=10):
    """Build activity_events list for an automation (for Overview or context)."""
    activity_executions = (
        AutomationExecution.objects.filter(automation=automation)
        .prefetch_related("results")
        .order_by("-executed_at")[:limit]
    )
    return [
        {
            "execution_id": execution.id,
            "execution_slug": execution.slug,
            "executed_at": execution.executed_at,
            "window_start": execution.window_start,
            "window_end": execution.window_end,
            "matched_cves_count": execution.matched_cves_count,
            "result_entries": [
                {
                    "label": r.label,
                    "icon": RESULT_TYPE_ICONS.get(r.output_type, "fa-file-o"),
                    "status": r.status,
                    "status_display": r.get_status_display(),
                }
                for r in execution.results.all()
            ],
        }
        for execution in activity_executions
    ]


class AutomationOverviewView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    UpdateView,
):
    """Overview page for an automation: header, summary, recent executions (drawer on click)."""

    model = Automation
    form_class = AutomationOverviewForm
    template_name = "projects/automations/overview.html"
    success_message = "The automation has been successfully updated."

    def get_object(self, queryset=None):
        return get_object_or_404(
            Automation,
            project=self.project,
            name=self.kwargs["automation"],
        )

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["project"] = self.project
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["automation"] = self.object
        context["activity_events"] = _build_activity_events(self.object, limit=10)
        context["url_back"] = reverse(
            "automations",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
            },
        )
        return context

    def get_success_url(self):
        return reverse(
            "automation_overview",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
                "automation": self.object.name,
            },
        )


class AutomationConfigurationView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    UpdateView,
):
    model = Automation
    form_class = AutomationForm
    template_name = "projects/automations/configuration.html"
    success_message = "The automation has been successfully updated."

    def get_object(self, queryset=None):
        return get_object_or_404(
            Automation,
            project=self.project,
            name=self.kwargs["automation"],
        )

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["project"] = self.project
        kwargs["request"] = self.request
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["automation"] = self.object
        context["is_scheduled_automation"] = (
            self.object.trigger_type == Automation.TRIGGER_SCHEDULED
        )
        context["is_realtime_automation"] = (
            self.object.trigger_type == Automation.TRIGGER_REALTIME
        )
        context["url_back"] = reverse(
            "automations",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
            },
        )
        # Activity (for possible reuse in template): limit 10 for consistency
        context["activity_events"] = _build_activity_events(self.object, limit=10)

        # Add context for form: notifications, users, status choices
        context["notifications"] = (
            Notification.objects.filter(project=self.project).order_by("name").all()
        )
        context["organization_members"] = (
            User.objects.filter(
                membership__organization=self.request.current_organization,
                membership__date_joined__isnull=False,
            )
            .distinct()
            .order_by("username")
        )
        context["status_choices"] = CveTracker.STATUS_CHOICES

        views = SavedView.objects.filter(
            Q(privacy="public", organization=self.request.current_organization)
            | Q(
                privacy="private",
                user=self.request.user,
                organization=self.request.current_organization,
            )
        ).order_by("name")
        context["views"] = views

        # Use submitted configuration when form is re-displayed after validation error
        default_config = (
            self.object.configuration
            if self.object and self.object.pk
            else {"conditions": {"operator": "OR", "children": []}, "actions": []}
        )
        if self.request.method == "POST":
            raw = self.request.POST.get("configuration_json")
            if raw:
                try:
                    data = json.loads(raw)
                    if (
                        isinstance(data, dict)
                        and "conditions" in data
                        and "actions" in data
                    ):
                        context["automation_data_json"] = json.dumps(data)
                        return context
                except (json.JSONDecodeError, TypeError):
                    pass
        context["automation_data_json"] = json.dumps(default_config)
        return context

    def get_success_url(self):
        return reverse(
            "automation_configuration",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
                "automation": self.object.name,
            },
        )


class AutomationResultsView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    DetailView,
):
    """Results page for the current automation: filter by result type and status, table of results."""

    model = Automation
    template_name = "projects/automations/results.html"
    context_object_name = "automation"

    def get_object(self, queryset=None):
        return get_object_or_404(
            Automation,
            project=self.project,
            name=self.kwargs["automation"],
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["automation"] = self.object
        filter_type = self.request.GET.get("type", "").strip()
        filter_status = self.request.GET.get("status", "").strip()
        context["filter_type"] = filter_type
        context["filter_status"] = filter_status

        queryset = (
            AutomationRunResult.objects.filter(
                automation_execution__automation=self.object
            )
            .select_related(
                "automation_execution",
                "automation_execution__automation",
            )
            .order_by("-automation_execution__executed_at", "created_at")
        )
        if filter_type:
            queryset = queryset.filter(output_type=filter_type)
        if filter_status:
            queryset = queryset.filter(status=filter_status)

        paginator = Paginator(queryset, 20)
        page_number = self.request.GET.get("page", 1)
        page = paginator.get_page(page_number)
        context["page_obj"] = page
        context["results"] = [
            {
                "result": r,
                "icon_class": RESULT_TYPE_ICONS.get(r.output_type, "fa-file-o"),
            }
            for r in page.object_list
        ]

        context["result_type_choices"] = RESULT_TYPE_FILTER_CHOICES
        context["result_type_icons"] = RESULT_TYPE_ICONS
        context["result_status_choices"] = AutomationRunResult.STATUS_CHOICES
        context["url_back"] = reverse(
            "automations",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
            },
        )
        return context


def _get_automation_for_results(project, automation_name):
    """Return Automation for the given project and name, or None."""
    return get_object_or_404(
        Automation,
        project=project,
        name=automation_name,
    )


class AutomationResultDetailView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    TemplateView,
):
    """Detail page for a single automation result; template depends on result output_type."""

    def get(self, request, *args, **kwargs):
        self.automation = _get_automation_for_results(
            self.project,
            kwargs["automation"],
        )
        self.result = get_object_or_404(
            AutomationRunResult.objects.select_related(
                "automation_execution",
                "automation_execution__automation",
            ),
            id=kwargs["result_id"],
            automation_execution__automation=self.automation,
        )
        return super().get(request, *args, **kwargs)

    def get_template_names(self):
        return [
            f"projects/automations/result_detail/{self.result.output_type}.html",
            "projects/automations/result_detail/default.html",
        ]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        context["automation"] = self.automation
        context["result"] = self.result
        context["url_results"] = reverse(
            "automation_results",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
                "automation": self.automation.name,
            },
        )
        return context


def build_impact_chart_data_from_cves_table(cves_table_data):
    """
    Build the impact summary dict from cves_table_data for the drawer (and for
    pre-computation in the scheduler / fake data). Returns a dict to store in
    execution.impact_summary, or None if no data. Used by the web view only for
    reading execution.impact_summary; this function is called by the fake data
    command and later by the scheduler.
    """
    if not cves_table_data:
        return None
    cvss_version_keys = ("cvss_40", "cvss_31", "cvss_30", "cvss_20")
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    highest_cvss = None
    highest_cvss_version = None
    cvss_scores = []
    epss_values = []
    epss_distribution = {"high": 0, "medium": 0, "low": 0}  # >0.9, 0.7-0.9, <0.7
    kev_count = 0
    vendor_counts = {}

    for row in cves_table_data:
        scores_dict = {
            k: row.get(k) for k in cvss_version_keys if row.get(k) is not None
        }
        if not scores_dict and row.get("cvss_31") is not None:
            scores_dict = {"cvss_31": row["cvss_31"]}
        score, version = get_highest_cvss(scores_dict) if scores_dict else (None, None)
        if score is not None:
            severity = cvss_score_to_severity(score)
            if severity and severity in distribution:
                distribution[severity] += 1
            cvss_scores.append(score)
            if highest_cvss is None or score > highest_cvss:
                highest_cvss = score
                highest_cvss_version = version
        if row.get("epss") is not None:
            try:
                v = float(row["epss"])
                epss_values.append(v)
                if v > 0.9:
                    epss_distribution["high"] += 1
                elif v >= 0.7:
                    epss_distribution["medium"] += 1
                else:
                    epss_distribution["low"] += 1
            except (TypeError, ValueError):
                pass
        if row.get("kev"):
            kev_count += 1
        vp = row.get("matched_vendor_or_product")
        if vp and str(vp).strip():
            vendor_counts[vp] = vendor_counts.get(vp, 0) + 1

    epss_avg = round(sum(epss_values) / len(epss_values), 2) if epss_values else None
    epss_max = round(max(epss_values), 2) if epss_values else None
    if highest_cvss is not None:
        highest_cvss = round(highest_cvss, 1)
    average_cvss = (
        round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else None
    )
    cves_count = len(cves_table_data)
    kev_percent = int(round(100 * kev_count / cves_count)) if cves_count else 0
    top_vendors_products = [
        {"name": name, "count": count}
        for name, count in sorted(vendor_counts.items(), key=lambda x: -x[1])[:5]
    ]

    return {
        "cvss_distribution": distribution,
        "highest_cvss": highest_cvss,
        "highest_cvss_version": highest_cvss_version,
        "average_cvss": average_cvss,
        "epss_distribution": epss_distribution,
        "epss_avg": epss_avg,
        "epss_max": epss_max,
        "kev_count": kev_count,
        "cves_count": cves_count,
        "kev_percent": kev_percent,
        "top_vendors_products": top_vendors_products,
    }


class AutomationExecutionDrawerView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    View,
):
    """Returns HTML fragment for the execution detail drawer (execution info, CVEs, results in cards)."""

    def get(self, request, *args, **kwargs):
        execution = _get_automation_execution_by_id(
            self.project,
            kwargs["automation"],
            kwargs["execution_id"],
        )
        if execution is None:
            raise Http404("No execution found.")
        results = list(
            AutomationRunResult.objects.filter(automation_execution=execution)
        )
        for res in results:
            if res.details is None:
                res.details = {}
        cves_table_data = (
            execution.cves_table_data if execution.cves_table_data is not None else []
        )
        impact_chart_data = execution.impact_summary
        return render(
            request,
            "projects/automations/execution_drawer.html",
            {
                "project": self.project,
                "automation": execution.automation,
                "execution": execution,
                "results": results,
                "cves_table_data": cves_table_data,
                "impact_chart_data": impact_chart_data,
                "impact_chart_data_json": (
                    json.dumps(impact_chart_data) if impact_chart_data else "null"
                ),
            },
        )


def _get_automation_execution_by_id(project, automation_name, execution_id):
    """Resolve an AutomationExecution by primary key (unique per execution)."""
    return (
        AutomationExecution.objects.filter(
            pk=execution_id,
            automation__project=project,
            automation__name=automation_name,
        )
        .prefetch_related("results")
        .select_related("automation", "automation__project")
        .first()
    )


class AutomationRunResultDownloadView(
    LoginRequiredMixin,
    OrganizationIsMemberMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    View,
):
    """Securely serve an automation execution result file (e.g. PDF)."""

    def get(self, request, *args, **kwargs):
        execution = _get_automation_execution_by_id(
            self.project,
            kwargs["automation"],
            kwargs["execution_id"],
        )
        if execution is None:
            raise Http404("No execution found.")
        result = get_object_or_404(
            AutomationRunResult.objects.select_related(
                "automation_execution",
                "automation_execution__automation",
                "automation_execution__automation__project",
            ),
            id=kwargs["result_id"],
            automation_execution=execution,
        )
        file_path = result.details.get("file_path") if result.details else None
        if not file_path:
            raise Http404("No file attached to this result.")
        if not default_storage.exists(file_path):
            raise Http404("File not found.")
        filename = (
            result.details.get("filename") or os.path.basename(file_path) or "download"
        )
        return FileResponse(
            default_storage.open(file_path, "rb"),
            as_attachment=True,
            filename=filename,
        )


class AutomationDeleteView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectObjectMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    DeleteView,
):
    model = Automation
    template_name = "projects/automations/delete.html"
    success_message = "The automation has been successfully removed."

    def get_object(self, queryset=None):
        return get_object_or_404(
            Automation,
            project=self.project,
            name=self.kwargs["automation"],
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project
        return context

    def get_success_url(self):
        return reverse(
            "automations",
            kwargs={
                "org_name": self.request.current_organization.name,
                "project_name": self.project.name,
            },
        )
