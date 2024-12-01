from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group

from users.models import User


admin.site.unregister(Group)


@admin.register(User)
class UserAdmin(UserAdmin):
    change_form_template = "users/admin/change_form.html"
