from django.contrib import admin
from django.contrib.admin.views.main import ChangeList
from django.db.models import Count
from django.urls import reverse

from changes.models import Change
from cves.admin import BaseReadOnlyAdminMixin


class TaskChangeList(ChangeList):
    def url_for_result(self, result):
        pk = getattr(result, self.pk_attname)
        return f"{reverse('admin:changes_change_changelist')}?task={pk}"


class ChangeChangeList(ChangeList):
    def url_for_result(self, result):
        return f"{reverse('change', kwargs={'cve_id': result.cve.cve_id, 'id': result.id})}"


@admin.register(Change)
class ChangeAdmin(BaseReadOnlyAdminMixin, admin.ModelAdmin):
    ordering = ("-created_at",)
    preserve_filters = False
    list_display = (
        "created_at",
        "cve",
        "events_type",
        "events_count",
    )

    def events_count(self, obj):
        return obj.events_count

    def events_type(self, obj):
        events = obj.events.all()
        return [e for e in events]

    def get_queryset(self, request):
        queryset = super(ChangeAdmin, self).get_queryset(request)
        if request.GET.get("task"):
            queryset = queryset.filter(task_id=request.GET.get("task"))
        return queryset.prefetch_related("events").annotate(
            events_count=Count("events")
        )

    def get_changelist(self, request, **kwargs):
        return ChangeChangeList
