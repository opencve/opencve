from django.contrib import admin

from projects.models import Project, ProjectView


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    readonly_fields = ["organization"]


@admin.register(ProjectView)
class ProjectViewAdmin(admin.ModelAdmin):
    readonly_fields = ["project"]
