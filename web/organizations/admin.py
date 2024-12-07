from django.contrib import admin
from auditlog.admin import LogEntryAdmin
from auditlog.models import LogEntry

from organizations.models import Membership, Organization


class MembershipInline(admin.TabularInline):
    model = Membership
    fields = ["user", "role"]
    readonly_fields = ["user"]
    raw_id_fields = ["user"]
    max_num = 0
    extra = 0


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    ordering = ("name",)
    search_fields = ["name"]
    list_display = (
        "name",
        "created_at",
    )
    fields = (
        "name",
        "created_at",
        "updated_at",
    )
    inlines = [MembershipInline]


# The following code can be placed in any loaded `admin.py` file.
# I chose this one arbitrarily, as audit logs were originally
# configured here to track organization states.
class CustomLogEntryAdmin(LogEntryAdmin):
    """
    Custom admin used to display the models name in audit logs.
    """

    @admin.display()
    def model_name(self, obj):
        return obj.content_type.model

    list_display = [
        "created",
        "model_name",
        "resource_url",
        "action",
        "msg_short",
        "user_url",
    ]


admin.site.unregister(LogEntry)
admin.site.register(LogEntry, CustomLogEntryAdmin)
