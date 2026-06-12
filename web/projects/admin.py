from django.contrib import admin

from projects.forms import AutomationAdminForm
from projects.models import Automation


@admin.register(Automation)
class AutomationAdmin(admin.ModelAdmin):
    form = AutomationAdminForm
    view_on_site = False
    ordering = ("-created_at",)
    list_display = (
        "name",
        "project",
        "organization",
        "trigger_type",
        "is_enabled",
        "frequency",
        "last_execution_at",
        "created_at",
    )
    list_filter = ("trigger_type", "is_enabled", "frequency")
    search_fields = (
        "name",
        "project__name",
        "project__organization__name",
    )
    raw_id_fields = ("project",)
    readonly_fields = ("conditions_count_display",)
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "name",
                    "project",
                    "is_enabled",
                    "trigger_type",
                )
            },
        ),
        (
            "Schedule",
            {
                "fields": (
                    "frequency",
                    "schedule_timezone",
                    "schedule_time",
                    "schedule_weekday",
                ),
            },
        ),
        (
            "Configuration",
            {
                "fields": (
                    "configuration",
                    "conditions_count_display",
                ),
            },
        ),
        (
            "Metadata",
            {
                "fields": (
                    "last_execution_at",
                    "created_at",
                    "updated_at",
                ),
            },
        ),
    )

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("project", "project__organization")
        )

    @admin.display(description="Organization")
    def organization(self, obj):
        return obj.project.organization.name

    @admin.display(description="Conditions")
    def conditions_count_display(self, obj):
        return obj.conditions_count
