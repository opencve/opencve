from django.contrib import admin

from .models import Dashboard


@admin.register(Dashboard)
class DashboardAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "organization", "is_default")
    list_filter = ("is_default",)
    search_fields = ("name", "user__username", "organization__name")
    readonly_fields = ("config", "user", "organization")
