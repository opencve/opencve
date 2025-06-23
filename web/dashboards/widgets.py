from django.db import models
from django.template.loader import render_to_string

from changes.models import Change, Report
from cves.models import Cve
from cves.search import Search
from views.models import View
from opencve.utils import is_valid_uuid
from projects.models import Project


def list_widgets():
    return {
        w.id: {
            "type": w.id,
            "name": w.name,
            "description": w.description,
            "class": w,
        }
        for w in Widget.__subclasses__()
    }


class Widget:
    allowed_config_keys = []
    default_config_values = {}

    def __init__(self, request, data, validate_config=True):
        self.request = request
        self.id = self.validate_id(data["id"])
        self.type = self.validate_type(data["type"])
        self.title = data["title"]
        self.raw_config = data.get("config", {})

        self.configuration = (
            self.validate_config(self.raw_config)
            if validate_config
            else self.raw_config
        )

    @staticmethod
    def validate_id(id):
        if id and not is_valid_uuid(id):
            raise ValueError(f"Invalid widget ID ({id})")
        return id

    @staticmethod
    def validate_type(type):
        allowed_types = [t["type"] for t in list_widgets().values()]
        if type not in allowed_types:
            raise ValueError(f"Invalid widget type ({type})")
        return type

    def validate_config(self, config):
        # Filter config to only include allowed keys
        config = {k: v for k, v in config.items() if k in self.allowed_config_keys}

        # Inject default values for missing keys
        for key in self.allowed_config_keys:
            if key not in config and key in self.default_config_values:
                config[key] = self.default_config_values[key]

        # Ensure all required keys are present
        required_keys = set(self.allowed_config_keys)
        provided_keys = set(config.keys())

        if not required_keys.issubset(provided_keys):
            missing_keys = required_keys - provided_keys
            raise ValueError(
                f"Missing required configuration keys: {', '.join(sorted(missing_keys))}"
            )

        return config

    def index(self):
        return self.render_index()

    def config(self):
        return self.render_config()

    def render_index(self, **kwargs):
        return render_to_string(
            f"dashboards/widgets/{self.type}/index.html",
            {
                "widget_id": self.id,
                "widget_type": self.type,
                "title": self.title,
                "config": self.configuration,
                "request": self.request,
                **kwargs,
            },
        )

    def render_config(self, **kwargs):
        return render_to_string(
            f"dashboards/widgets/{self.type}/config.html",
            {
                "widget_id": self.id,
                "widget_type": self.type,
                "title": self.title,
                "config": self.configuration,
                "request": self.request,
                **kwargs,
            },
        )


class ActivityWidget(Widget):
    id = "activity"
    name = "CVEs Activity"
    description = "Displays the most recent CVE changes across all projects."
    allowed_config_keys = ["activities_view"]
    default_config_values = {
        "activities_view": "all",
    }

    def validate_config(self, config):
        cleaned = super().validate_config(config)

        # Ensure the activities_view is supported
        if not cleaned.get("activities_view") in ["all", "subscriptions"]:
            raise ValueError(
                f"Invalid activities view ({cleaned.get('activities_view')})"
            )

        return cleaned

    def index(self):
        query = Change.objects.select_related("cve")

        # Filter on user subscriptions if needed
        activities_view = self.configuration.get("activities_view", "all")
        if activities_view == "subscriptions":
            vendors = self.request.current_organization.get_projects_vendors()
            if vendors:
                query = query.filter(cve__vendors__has_any_keys=vendors)

        # Get the last 20 changes
        changes = query.order_by("-created_at")[:20]

        return self.render_index(changes=changes)


class ViewsWidget(Widget):
    id = "views"
    name = "Views"
    description = (
        "Shows the list of your private views and your organization’s public views."
    )

    def index(self):
        views = View.objects.filter(
            models.Q(privacy="public", organization=self.request.current_organization)
            | models.Q(
                privacy="private",
                user=self.request.user,
                organization=self.request.current_organization,
            )
        ).order_by("privacy")
        return self.render_index(views=views)


class ViewCvesWidget(Widget):
    id = "view_cves"
    name = "CVEs by View"
    description = "Displays CVEs associated with a selected saved view."
    allowed_config_keys = ["view_id", "show_view_info"]
    default_config_values = {
        "show_view_info": 0,
    }

    def validate_config(self, config):
        cleaned = super().validate_config(config)

        # Ensures the view is correctly formatted
        view_id = cleaned.get("view_id", "")
        if not is_valid_uuid(view_id):
            raise ValueError(f"Invalid view ID ({view_id})")

        # Ensure the view exists
        view = View.objects.filter(
            id=view_id, organization=self.request.current_organization
        ).first()
        if not view:
            raise ValueError(f"View not found ({view_id})")

        # If the view is private, it must be owned by the user
        if view.privacy == "private" and view.user != self.request.user:
            raise ValueError(f"View not found ({view_id})")

        # By default, show_view_info is True
        cleaned["show_view_info"] = 1 if cleaned.get("show_view_info") else 0

        return cleaned

    def config(self):
        views = View.objects.filter(
            models.Q(privacy="public", organization=self.request.current_organization)
            | models.Q(
                privacy="private",
                user=self.request.user,
                organization=self.request.current_organization,
            )
        )
        return self.render_config(views=views)

    def index(self):
        view = View.objects.filter(
            id=self.configuration["view_id"],
            organization=self.request.current_organization,
        ).first()
        cves = Search(view.query, self.request.user).query.all()[:20]
        return self.render_index(view=view, cves=cves)


class ProjectCvesWidget(Widget):
    id = "project_cves"
    name = "CVEs by Project"
    description = "Displays CVEs associated with a selected project."
    allowed_config_keys = ["project_id", "show_project_info"]
    default_config_values = {
        "show_project_info": 0,
    }

    def validate_config(self, config):
        cleaned = super().validate_config(config)

        # Ensures the project is correctly formatted
        project_id = cleaned.get("project_id", "")
        if not is_valid_uuid(project_id):
            raise ValueError(f"Invalid project ID ({project_id})")

        # Ensure the project is owned by the current organization
        project = (
            Project.objects.filter(
                id=project_id, organization=self.request.current_organization
            )
            .only("active")
            .first()
        )
        if not project:
            raise ValueError(f"Project not found ({project_id})")

        # Ensure the project is active
        if not project.active:
            raise ValueError(f"Inactive project ({project_id})")

        # By default, show_project_info is True
        cleaned["show_project_info"] = 1 if cleaned.get("show_project_info") else 0

        return cleaned

    def config(self):
        projects = Project.objects.filter(
            organization=self.request.current_organization,
            active=True,
        ).all()
        return self.render_config(projects=projects)

    def index(self):
        project = Project.objects.filter(
            organization=self.request.current_organization,
            id=self.configuration["project_id"],
        ).first()

        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
        if not vendors:
            return self.render_index(project=project, cves=[])

        cves = (
            Cve.objects.order_by("-updated_at")
            .filter(vendors__has_any_keys=vendors)
            .all()[:20]
        )

        return self.render_index(project=project, cves=cves)


class TagsWidget(Widget):
    id = "tags"
    name = "Tags"
    description = "Shows the list of tags you created to categorize CVEs."

    def index(self):
        tags = self.request.user.tags.all()
        return self.render_index(tags=tags)


class ProjectsWidget(Widget):
    id = "projects"
    name = "Projects"
    description = "Displays the list of projects within your organization."

    def index(self):
        organization = self.request.current_organization
        projects = organization.projects.all()
        return self.render_index(
            organization=organization, projects=projects.order_by("name")
        )


class LastReportsWidget(Widget):
    id = "last_reports"
    name = "Last Reports"
    description = (
        "Displays the latest CVE reports generated for your organization’s projects."
    )

    def index(self):
        organization = self.request.current_organization
        projects = organization.projects.all()

        reports = (
            Report.objects.filter(project__in=projects)
            .prefetch_related("changes")
            .select_related("project")
            .order_by("-day")[:10]
        )
        return self.render_index(organization=organization, reports=reports)
