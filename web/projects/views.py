import importlib

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db.models import Prefetch, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import (
    CreateView,
    DeleteView,
    DetailView,
    ListView,
    UpdateView,
)

from changes.models import Change, Report
from cves.models import Cve
from opencve.mixins import RequestViewMixin
from organizations.mixins import (
    OrganizationIsMemberMixin,
    OrganizationIsOwnerMixin,
)
from projects.forms import FORM_MAPPING, ProjectForm
from projects.mixins import ProjectObjectMixin, ProjectIsActiveMixin
from projects.models import Notification, Project

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
            organization=self.request.user_organization
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

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.get_object()

        # Get the list of vendors and products
        vendors = (
            self.object.subscriptions["vendors"] + self.object.subscriptions["products"]
        )

        if vendors:
            query = Change.objects.select_related("cve")
            query = query.filter(cve__vendors__has_any_keys=vendors)
            context["changes"] = query.all().order_by("-created_at")[:10]

        # Last reports
        query = (
            Report.objects.filter(project=self.get_object())
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
        form.instance.organization = self.request.user_organization
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

    def get_form(self, form_class=None):
        form = super(ProjectEditView, self).get_form()
        form.fields["name"].disabled = True
        return form

    def get_success_url(self):
        return reverse_lazy(
            "list_projects", kwargs={"org_name": self.request.user_organization}
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
            "list_projects", kwargs={"org_name": self.request.user_organization}
        )


class ProjectVulnerabilitiesView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectIsActiveMixin, ListView
):
    model = Cve
    context_object_name = "cves"
    template_name = "projects/vulnerabilities.html"
    paginate_by = 20

    def _get_project(self):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )

    def get_queryset(self):
        project = self._get_project()
        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
        if not vendors:
            return self.model.objects.none()

        return Cve.objects.order_by("-updated_at").filter(vendors__has_any_keys=vendors)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self._get_project()
        return context


class ReportsView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectIsActiveMixin, ListView
):
    model = Report
    context_object_name = "reports"
    template_name = "projects/reports.html"
    paginate_by = 20

    def _get_project(self):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )

    def get_queryset(self):
        project = self._get_project()
        changes_with_cve_prefetch = Prefetch(
            "changes",
            queryset=Change.objects.select_related("cve"),
        )
        query = (
            Report.objects.filter(project=project)
            .prefetch_related(changes_with_cve_prefetch)
            .all()
        )
        return query.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self._get_project()
        return context


class ReportView(
    LoginRequiredMixin, OrganizationIsMemberMixin, ProjectIsActiveMixin, DetailView
):
    model = Report
    template_name = "projects/report.html"

    def _get_project(self):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )

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
            project=self._get_project(),
            day=self.kwargs["day"],
        )

        return self.get_report_statistics(report)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self._get_project()
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
        context["project"] = self.get_object()
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
        context["project"] = self.get_object()
        context["notifications"] = (
            Notification.objects.filter(project=self.object).order_by("name").all()
        )
        return context


class NotificationCreateView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    CreateView,
):
    model = Notification
    template_name = "projects/notifications/save.html"
    success_message = "The notification has been successfully created."

    def _get_project(self):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )

    def get(self, request, *args, **kwargs):
        if request.GET.get("type") not in ["email", "webhook"]:
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
        form.instance.project = self._get_project()
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
        kwargs["project"] = self._get_project()
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self._get_project()
        context["type"] = self.request.GET["type"]
        return context


class NotificationUpdateView(
    LoginRequiredMixin,
    OrganizationIsOwnerMixin,
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    RequestViewMixin,
    UpdateView,
):
    model = Notification
    template_name = "projects/notifications/save.html"
    success_message = "The notification has been successfully updated."

    def _get_project(self):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )

    def get_object(self, queryset=None):
        return get_object_or_404(
            Notification,
            project=self._get_project(),
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
        form.instance.project = self._get_project()
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
        kwargs["project"] = self._get_project()
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self._get_project()
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
    ProjectIsActiveMixin,
    SuccessMessageMixin,
    DeleteView,
):
    model = Notification
    template_name = "projects/notifications/delete.html"
    success_message = "The notification has been successfully removed."

    def _get_project(self):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["project_name"],
        )

    def get_object(self, queryset=None):
        return get_object_or_404(
            Notification,
            project=self._get_project(),
            name=self.kwargs["notification"],
        )

    def get_success_url(self):
        return reverse(
            "notifications",
            kwargs={
                "org_name": self.request.user_organization.name,
                "project_name": self._get_project().name,
            },
        )
