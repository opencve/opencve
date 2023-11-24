import importlib

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView, UpdateView, DeleteView

from changes.models import Change, Report
from cves.models import Cve
from projects.forms import FORM_MAPPING, ProjectForm
from projects.models import Notification, Project
# TODO: bouger ça dans un opencve/mixins.py
from users.views import RequestViewMixin
from organizations.mixins import OrganizationRequiredMixin

EVENT_TYPES = [
    "mitre_new", "mitre_summary",
    "nvd_new", "nvd_summary", "nvd_first_time", "nvd_cvss", "nvd_cwes", "nvd_references", "nvd_cpes"
]


class ProjectsListView(LoginRequiredMixin, OrganizationRequiredMixin, ListView):
    context_object_name = "projects"
    template_name = "projects/list_projects.html"

    def get_queryset(self):
        query = Project.objects.filter(organization=self.request.user_organization).all()
        return query.order_by("name")


class ProjectCreateView(
    LoginRequiredMixin, OrganizationRequiredMixin, SuccessMessageMixin, RequestViewMixin, CreateView
):
    model = Project
    form_class = ProjectForm
    template_name = "projects/project_create_update.html"
    success_message = "The project has been successfully created."

    def form_valid(self, form):
        form.instance.organization = self.request.user_organization
        return super().form_valid(form)


class ProjectEditView(
    LoginRequiredMixin, OrganizationRequiredMixin, SuccessMessageMixin, RequestViewMixin, UpdateView
):
    model = Project
    form_class = ProjectForm
    template_name = "projects/project_create_update.html"
    success_message = "The project has been successfully updated."
    slug_field = "name"
    slug_url_kwarg = "name"
    context_object_name = "project"

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project, organization=self.request.user_organization, name=self.kwargs["name"]
        )

    def get_form(self, form_class=None):
        form = super(ProjectEditView, self).get_form()
        form.fields["name"].disabled = True
        return form

    def get_success_url(self):
        return reverse_lazy("list_projects", kwargs={"orgname": self.request.user_organization})


class ProjectDeleteView(LoginRequiredMixin, OrganizationRequiredMixin, SuccessMessageMixin, DeleteView):
    model = Project
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "projects/delete_project.html"
    success_message = "The project has been deleted."

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project, organization=self.request.user_organization, name=self.kwargs["name"]
        )

    def get_success_url(self):
        return reverse_lazy("projects", kwargs={"orgname": self.request.user_organization})


class ProjectVulnerabilitiesView(LoginRequiredMixin, OrganizationRequiredMixin, ListView):
    model = Cve
    context_object_name = "cves"
    template_name = "projects/vulnerabilities.html"
    paginate_by = 20

    def get_queryset(self):
        project = get_object_or_404(
            Project, organization=self.request.user_organization, name=self.kwargs["name"]
        )
        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
        if not vendors:
            return self.model.objects.none()

        return Cve.objects.filter(vendors__has_any_keys=vendors)


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        project = get_object_or_404(
            Project, organization=self.request.user_organization, name=self.kwargs["name"]
        )
        context["project"] = project
        return context


class ProjectDetailView(LoginRequiredMixin, OrganizationRequiredMixin, DetailView):
    model = Project
    template_name = "projects/dashboard.html"

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["name"]
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.get_object()

        # Get the list of vendors and products
        vendors = (
            self.object.subscriptions["vendors"] + self.object.subscriptions["products"]
        )

        if vendors:
            query = Change.objects.select_related("cve").prefetch_related("events")
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


class ReportsView(LoginRequiredMixin, OrganizationRequiredMixin, ListView):
    context_object_name = "reports"
    template_name = "projects/reports.html"
    paginate_by = 20

    def get_queryset(self):
        project = self.get_object()
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

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["name"]
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.get_object()
        return context


class ReportView(LoginRequiredMixin, OrganizationRequiredMixin, DetailView):
    model = Report
    template_name = "projects/report.html"

    def get_report_statistics(self, report):
        changes = {}

        # A CVE can have several changes in 1 day,
        # so we need to group them by date.
        for change in report.changes.all():

            if change.cve not in changes:
                score = change.cve.cvss["v31"] if change.cve.cvss.get("v31") else 0
                changes[change.cve] = {
                    "cve": change.cve,
                    "score": score,
                    "changes": []
                }

            changes[change.cve]["changes"].append([change.created_at, change.events.all()])

        return {"report": report, "changes": changes.values()}

    def get_object(self, queryset=None):
        project = super(ReportView, self).get_object()

        # Optimize the query to return the associated events and CVE
        changes_with_cve_prefetch = Prefetch(
            "changes",
            queryset=Change.objects.select_related("cve").prefetch_related("events"),
        )
        queryset = self.model.objects.prefetch_related(changes_with_cve_prefetch)

        # Return the daily report
        report = get_object_or_404(
            queryset,
            project=project,
            day=self.kwargs["day"],
        )

        return self.get_report_statistics(report)

    def get_context_data(self, **kwargs):
        context = super(ReportView, self).get_context_data(**kwargs)
        return {
            **context,
            **{
                "project": get_object_or_404(
                    Project, user=self.request.user, name=self.kwargs["name"]
                )
            },
        }


class SubscriptionsView(LoginRequiredMixin, OrganizationRequiredMixin, DetailView):
    model = Project
    template_name = "projects/subscriptions.html"

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["name"]
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.get_object()
        return context


class NotificationsView(LoginRequiredMixin, OrganizationRequiredMixin, DetailView):
    model = Project
    template_name = "projects/notifications/list.html"

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["name"]
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.get_object()
        context["notifications"] = (
            Notification.objects.filter(project=self.object).order_by("name").all()
        )
        return context


class NotificationViewMixin(LoginRequiredMixin, OrganizationRequiredMixin):
    model = Project
    template_name = "projects/notifications/save.html"

    def get_type(self):
        raise NotImplementedError()

    def get_object(self, queryset=None):
        return get_object_or_404(
            Project,
            organization=self.request.user_organization,
            name=self.kwargs["name"]
        )

    def get_context_data(self, **kwargs):
        return {
            **super(NotificationViewMixin, self).get_context_data(**kwargs),
            **{
                "type": self.request.GET.get("type"),
                "project": self.get_object()
            },
        }

    def get_form_class(self):
        return getattr(
            importlib.import_module("projects.forms"),
            f"{self.get_type().capitalize()}Form",
        )

    def exists(self, project, name, instance=None):
        # TODO: la notification 'add' doit être reservée (conflit url sinon)
        queryset = Notification.objects.filter(project=project, name=name)
        if instance:
            queryset = queryset.filter(~Q(id=instance.id))

        if queryset.exists():
            messages.error(
                self.request,
                f"The notification {name} already exists.",
            )
            return True
        return False


class NotificationCreateView(NotificationViewMixin, CreateView):
    def get_type(self):
        return self.request.GET.get("type")

    def get(self, request, *args, **kwargs):
        # TODO: don't harcode
        if request.GET.get("type") not in ["email", "webhook"]:
            project = get_object_or_404(
                Project, name=self.kwargs["name"], user=self.request.user
            )
            return redirect("notifications", name=project.name)

        return super(NotificationCreateView, self).get(request)

    def post(self, request, *args, **kwargs):
        form = self.get_form_class()(request.POST)
        project = get_object_or_404(
            Project, name=self.kwargs["name"], organization=self.request.user_organization
        )

        if form.is_valid():
            if self.exists(project, form.cleaned_data["name"]):
                return render(
                    request,
                    self.template_name,
                    {"form": form, "type": self.get_type(), "project": project},
                )

            # List of events
            events = [
                t
                for t, b in form.cleaned_data.items()
                if t in EVENT_TYPES and b
            ]

            # Extra configuration
            extras = {}
            custom_fields = FORM_MAPPING.get(request.GET.get("type"), [])
            for field in custom_fields:
                extras[field] = form.cleaned_data[field]

            # Create the notification
            notification = form.save(commit=False)
            notification.project = project
            notification.type = request.GET.get("type")
            notification.configuration = {
                "events": events,
                "cvss": form.cleaned_data["cvss_score"],
                "extras": extras,
            }
            notification.save()

            messages.success(
                request, f"Notification {notification.name} successfully created"
            )
            return redirect("notifications", orgname=request.user_organization, name=project.name)

        return render(
            request,
            self.template_name,
            {"form": form, "type": request.GET.get("type"), "project": project},
        )


class NotificationUpdateView(NotificationViewMixin, UpdateView):
    def get_type(self):
        return self.object.type

    def get_object(self, queryset=None):
        return get_object_or_404(
            Notification,
            name=self.kwargs["notification"],
            project__name=self.kwargs["name"],
            project__organization=self.request.user_organization,
        )

    def get_context_data(self, **kwargs):
        context = super(NotificationUpdateView, self).get_context_data(**kwargs)

        # Transform JSON field into dedicated fields
        context["form"].initial["cvss_score"] = self.object.configuration["cvss"]
        for event in self.object.configuration["events"]:
            context["form"].initial[event] = True

        custom_fields = FORM_MAPPING.get(self.object.type, [])
        for field in custom_fields:
            context["form"].initial[field] = self.object.configuration["extras"][field]

        return {**context, **{"type": self.object.type}}

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()

        form = self.get_form_class()(request.POST, instance=self.object)
        project = get_object_or_404(
            Project, name=self.kwargs["name"], organization=self.request.user_organization
        )

        if form.is_valid():
            if self.exists(project, form.cleaned_data["name"], self.object):
                return render(
                    request,
                    self.template_name,
                    {"form": form, "type": self.get_type(), "project": project},
                )

            # List of events
            events = [
                t
                for t, b in form.cleaned_data.items()
                if t in EVENT_TYPES and b
            ]

            # Extra configuration
            extras = {}
            custom_fields = FORM_MAPPING.get(self.object.type, [])
            for field in custom_fields:
                extras[field] = form.cleaned_data[field]

            # Create the  notification
            notification = form.save(commit=False)
            notification.configuration = {
                "events": events,
                "cvss": form.cleaned_data["cvss_score"],
                "extras": extras,
            }
            notification.save()

            messages.success(
                request, f"Notification {notification.name} successfully updated"
            )
            return redirect("notifications", orgname=request.user_organization, name=project.name)

        return render(
            request,
            self.template_name,
            {"form": form, "type": self.get_type(), "project": project},
        )
