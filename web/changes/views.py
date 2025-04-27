import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import redirect
from django.utils.functional import cached_property
from django.views.generic import DetailView, ListView

from changes.forms import ActivitiesViewForm
from changes.models import Change
from changes.utils import CustomHtmlHTML
from organizations.mixins import OrganizationIsMemberMixin


class ActivityPaginator(Paginator):
    """
    A custom paginator used to improve the performance of the changes
    list. The count number is much larger than expected, so Django doesn't
    have to compute it.
    See: https://pganalyze.com/blog/pagination-django-postgres#pagination-in-django-option-1--removing-the-count-query
    """

    @cached_property
    def count(self):
        return 9999999999


class ChangeListView(LoginRequiredMixin, OrganizationIsMemberMixin, ListView):
    model = Change
    context_object_name = "changes"
    template_name = "changes/change_list.html"
    paginate_by = 10
    paginator_class = ActivityPaginator
    form_class = ActivitiesViewForm

    def get_queryset(self):
        query = Change.objects
        query = query.select_related("cve")

        # Filter on user subscriptions
        if self.request.user.settings["activities_view"] == "subscriptions":

            vendors = self.request.current_organization.get_projects_vendors()
            if vendors:
                query = query.filter(cve__vendors__has_any_keys=vendors)

        return query.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Add the view form
        view = self.request.user.settings["activities_view"]
        context["form"] = ActivitiesViewForm(initial={"view": view})

        return context

    def post(self, request, *args, **kwargs):
        form = ActivitiesViewForm(request.POST)
        if form.is_valid():
            self.request.user.settings = {
                **self.request.user.settings,
                "activities_view": form.cleaned_data["view"],
            }

            messages.success(self.request, "Your activity settings have been updated.")
            self.request.user.save()

        return redirect("activity")


class ChangeDetailView(DetailView):
    model = Change
    template_name = "changes/change_detail.html"

    def get_object(self):
        change_id = self.kwargs["id"]
        cve_id = self.kwargs["cve_id"]

        change = Change.objects.filter(cve__cve_id=cve_id).filter(id=change_id).first()
        if not change:
            raise Http404(f"Change {change_id} not found for {cve_id}")
        return change

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        change = context["change"]

        previous_change = change.get_previous_change()
        previous_data = previous_change.kb_data if previous_change else {}

        differ = CustomHtmlHTML()
        context["diff"] = differ.make_table(
            fromlines=json.dumps(previous_data, sort_keys=True, indent=4).split("\n"),
            tolines=json.dumps(change.kb_data, sort_keys=True, indent=4).split("\n"),
            context=True,
        )
        return context
