import importlib
import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db.models import Count, Prefetch
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.views.generic import (
    CreateView,
    DeleteView,
    DetailView,
    ListView,
    UpdateView,
    View,
)

from changes.models import Change, Report
from cves.models import Cve
from opencve.mixins import RequestViewMixin
from organizations.mixins import (
    OrganizationIsMemberMixin,
    OrganizationIsOwnerMixin,
)
from projects.forms import FORM_MAPPING, ProjectForm, CveTrackerFilterForm
from projects.mixins import ProjectObjectMixin, ProjectIsActiveMixin
from projects.models import Notification, Project, CveTracker
from users.models import User

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

    def get_queryset(self):
        vendors = (
            self.project.subscriptions["vendors"]
            + self.project.subscriptions["products"]
        )
        if not vendors:
            return self.model.objects.none()

        queryset = (
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
            .order_by("-updated_at")
        )

        # Apply filters
        assignee_username = self.request.GET.get("assignee")
        status = self.request.GET.get("status")

        if assignee_username:
            queryset = queryset.filter(
                trackers__project=self.project,
                trackers__assignee__username=assignee_username,
            )

        if status:
            queryset = queryset.filter(
                trackers__project=self.project, trackers__status=status
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.project

        # Add filter form
        filter_form = CveTrackerFilterForm(
            data=self.request.GET or None,
            organization=self.request.current_organization,
        )
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

        return context


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

        # Create the notification
        form.instance.project = self.project
        form.instance.type = self.request.GET["type"]
        form.instance.configuration = {
            "types": types,
            "metrics": {"cvss31": form.cleaned_data["cvss31_score"]},
            "extras": extras,
        }

        return super().form_valid(form)

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
        return context


class NotificationUpdateView(
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

        # Create the notification
        form.instance.project = self.project
        form.instance.configuration = {
            "types": types,
            "metrics": {"cvss31": form.cleaned_data["cvss31_score"]},
            "extras": extras,
        }

        return super().form_valid(form)

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

        # Transform JSON field into dedicated fields
        context["form"].initial["cvss31_score"] = self.object.configuration["metrics"][
            "cvss31"
        ]
        for _type in self.object.configuration["types"]:
            context["form"].initial[_type] = True

        custom_fields = FORM_MAPPING.get(self.object.type, [])
        for field in custom_fields:
            context["form"].initial[field] = self.object.configuration["extras"][field]

        return {**context, **{"type": self.object.type}}


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
