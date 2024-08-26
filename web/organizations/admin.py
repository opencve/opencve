from django.contrib import admin

from organizations.models import Membership, Organization


class MembershipInline(admin.TabularInline):
    model = Membership
    fields = ["user", "role"]
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
