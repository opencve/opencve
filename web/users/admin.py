from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import path, reverse
from django.utils.html import format_html
from django.views.decorators.http import require_http_methods

from allauth.mfa.models import Authenticator
from allauth.mfa.utils import is_mfa_enabled

from users.mfa import reset_user_mfa
from users.models import User


admin.site.unregister(Group)


@admin.register(User)
class UserAdmin(UserAdmin):
    change_form_template = "users/admin/change_form.html"

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = super().get_readonly_fields(request, obj)
        if obj:
            return (*readonly_fields, "mfa_status")
        return readonly_fields

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        if obj:
            fieldsets = (
                *fieldsets,
                ("Two-factor authentication", {"fields": ("mfa_status",)}),
            )
        return fieldsets

    @admin.display(description="MFA status")
    def mfa_status(self, obj):
        if not is_mfa_enabled(obj):
            return "Disabled"
        types = Authenticator.objects.filter(user=obj).values_list("type", flat=True)
        return f"Enabled ({', '.join(sorted(types))})"

    def get_urls(self):
        urls = super().get_urls()
        disable_mfa_view = require_http_methods(["GET", "POST"])(self.disable_mfa_view)
        custom_urls = [
            path(
                "<uuid:object_id>/disable-mfa/",
                self.admin_site.admin_view(disable_mfa_view),
                name="users_user_disable_mfa",
            ),
        ]
        return custom_urls + urls

    def change_view(self, request, object_id, form_url="", extra_context=None):
        extra_context = extra_context or {}
        obj = self.get_object(request, object_id)
        mfa_enabled = bool(obj and is_mfa_enabled(obj))
        extra_context["mfa_enabled"] = mfa_enabled
        can_disable_mfa = (
            request.user.is_superuser
            and obj is not None
            and obj != request.user
            and self.has_change_permission(request, obj)
        )
        extra_context["show_disable_mfa"] = can_disable_mfa and mfa_enabled
        if extra_context["show_disable_mfa"]:
            extra_context["disable_mfa_url"] = reverse(
                "admin:users_user_disable_mfa",
                args=[object_id],
            )
        return super().change_view(request, object_id, form_url, extra_context)

    def disable_mfa_view(self, request, object_id):
        if not request.user.is_superuser:
            raise PermissionDenied

        user = get_object_or_404(User, pk=object_id)

        if not self.has_change_permission(request, user):
            raise PermissionDenied

        if user == request.user:
            raise PermissionDenied

        if request.method == "POST":
            removed = reset_user_mfa(request, user)
            if removed:
                removed_count = int(removed)
                self.log_change(
                    request,
                    user,
                    f"Disabled MFA ({removed_count} authenticator(s) removed).",
                )
                self.message_user(
                    request,
                    format_html(
                        "MFA disabled for <strong>{}</strong> ({} authenticator(s) removed).",
                        user.username,
                        removed_count,
                    ),
                    messages.SUCCESS,
                )
            else:
                self.log_change(
                    request,
                    user,
                    "Attempted to disable MFA but none was configured.",
                )
                self.message_user(
                    request,
                    format_html(
                        "No MFA was configured for <strong>{}</strong>.",
                        user.username,
                    ),
                    messages.WARNING,
                )
            return redirect(reverse("admin:users_user_change", args=[user.pk]))

        context = {
            **self.admin_site.each_context(request),
            "title": "Disable MFA",
            "user_obj": user,
            "opts": self.model._meta,
        }
        return render(request, "users/admin/disable_mfa_confirm.html", context)
