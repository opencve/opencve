import importlib
import itertools
import operator

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from changes.models import Change, Report
from projects.forms import FORM_MAPPING
from projects.models import Notification, Project


def get_default_configuration():
    return {
        "cvss": 0,
        "events": [
            "new_cve",
            "first_time",
            "references",
            "cvss",
            "cpes",
            "summary",
            "cwes",
        ],
    }


class ProjectMixin(LoginRequiredMixin):
    def get_object(self, queryset=None):
        return get_object_or_404(
            Project, user=self.request.user, name=self.kwargs["name"]
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["project"] = self.get_object()
        return context


class ProjectDetailView(ProjectMixin, DetailView):
    model = Project
    template_name = "projects/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Filter on project subscriptions
        vendors = (
            self.object.subscriptions["vendors"] + self.object.subscriptions["products"]
        )

        if vendors:
            query = Change.objects.select_related("cve").prefetch_related("events")
            query = query.filter(cve__vendors__has_any_keys=vendors)
            context["changes"] = query.all().order_by("-created_at")[:10]

        return context


class ReportsView(ProjectMixin, ListView):
    context_object_name = "reports"
    template_name = "projects/reports.html"
    paginate_by = 20

    def get_queryset(self):
        project = self.get_object()
        query = Report.objects.filter(project=project).all()
        return query.order_by("-updated_at")


class ReportView(ProjectMixin, DetailView):
    model = Report
    template_name = "projects/report.html"

    def get_report_statistics(self, report):
        changes = {}

        # A CVE can have several changes in 1 day,
        # so we need to group them by date.
        for change in report.changes.all():
            if change.cve not in changes:
                changes[change.cve] = []

            changes[change.cve].append([change.created_at, change.events.all()])

        # Sort the changes by CVSS score
        ordered_changes = {k: v for k, v in sorted(changes.items(), key=lambda t: getattr(t[0], "cvss3") if getattr(t[0], "cvss3") else 0, reverse=True)}

        return {"report": report, "changes": ordered_changes}

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
            created_at__day=self.kwargs["day"].day,
            created_at__month=self.kwargs["day"].month,
            created_at__year=self.kwargs["day"].year,
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


class SubscriptionsView(ProjectMixin, DetailView):
    model = Project
    template_name = "projects/subscriptions.html"


class NotificationsView(ProjectMixin, DetailView):
    model = Project
    template_name = "projects/notifications/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["notifications"] = (
            Notification.objects.filter(project=self.object).order_by("name").all()
        )
        return context


class NotificationViewMixin(ProjectMixin):
    model = Project
    template_name = "projects/notifications/save.html"

    def get_type(self):
        raise NotImplementedError()

    def get_context_data(self, **kwargs):
        return {
            **super(NotificationViewMixin, self).get_context_data(**kwargs),
            **{"type": self.request.GET.get("type")},
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
        if request.GET.get("type") not in ["email", "webhook", "slack"]:
            project = get_object_or_404(
                Project, name=self.kwargs["name"], user=self.request.user
            )
            return redirect("notifications", name=project.name)

        return super(NotificationCreateView, self).get(request)

    def post(self, request, *args, **kwargs):
        form = self.get_form_class()(request.POST)
        project = get_object_or_404(
            Project, name=self.kwargs["name"], user=self.request.user
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
                if t in get_default_configuration().get("events") and b
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
            return redirect("notifications", name=project.name)

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
            project__user=self.request.user,
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
            Project, name=self.kwargs["name"], user=self.request.user
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
                if t in get_default_configuration().get("events") and b
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
            return redirect("notifications", name=project.name)

        return render(
            request,
            self.template_name,
            {"form": form, "type": self.get_type(), "project": project},
        )
