import json
import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views import View
from django.views.generic import TemplateView


from dashboards.models import Dashboard
from dashboards.widgets import list_widgets

logger = logging.getLogger(__name__)


class DashboardView(TemplateView):
    template_name = "dashboards/index.html"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("cves")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["widgets"] = sorted(list_widgets().values(), key=lambda x: x["name"])

        # Retrieve the list of dashboards
        dashboards_qs = Dashboard.objects.filter(
            organization=self.request.current_organization,
            user=self.request.user,
        ).order_by("-is_default", "created_at")

        # If no default dashboard, create one
        default = dashboards_qs.filter(is_default=True).first()
        if not default and dashboards_qs.exists():
            default = dashboards_qs.first()
            default.is_default = True
            default.save()

        # Create a default dashboard
        elif not default:
            default = Dashboard.objects.create(
                organization=self.request.current_organization,
                user=self.request.user,
                name="Default",
                is_default=True,
                config=Dashboard.get_default_config(self.request),
            )
            dashboards_qs = Dashboard.objects.filter(
                organization=self.request.current_organization,
                user=self.request.user,
            ).order_by("-is_default", "created_at")

        context["dashboards"] = [
            {"id": str(d.id), "name": d.name, "is_default": d.is_default}
            for d in dashboards_qs
        ]
        context["default_dashboard_id"] = str(default.id)

        context["dashboards_data"] = {
            "dashboards": context["dashboards"],
            "default_dashboard_id": context["default_dashboard_id"],
        }
        return context


class LoadDashboardView(LoginRequiredMixin, View):
    def get(self, request):
        if not request.current_organization:
            return JsonResponse({"error": "No organization selected"}, status=400)

        dashboard_id = request.GET.get("dashboard_id")

        # Get the dashboard config
        if dashboard_id:
            dashboard = Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
                id=dashboard_id,
            ).first()
            if not dashboard:
                return JsonResponse({"error": "Dashboard not found"}, status=404)
        else:
            dashboard = Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
                is_default=True,
            ).first()
            if not dashboard:
                dashboard = Dashboard.objects.create(
                    organization=request.current_organization,
                    user=request.user,
                    name="Default",
                    is_default=True,
                    config=Dashboard.get_default_config(request),
                )

        return JsonResponse(dashboard.config)


class SaveDashboardView(LoginRequiredMixin, View):
    @staticmethod
    def validate_widgets_config(request, widgets):
        """
        Loop on every widget to validate its config.
        """
        cleaned_config = []

        for widget in widgets:
            cleaned_widget = dict(widget)

            if widget["type"] not in list_widgets():
                return False, "Invalid widget type"
            widget_class = list_widgets().get(widget["type"])["class"]

            try:
                widget_instance = widget_class(request, widget)
            except ValueError as e:
                message = "Error creating widget instance"
                logger.error(f"{message}: {e}")
                return False, message

            # Save the cleaned configuration
            cleaned_widget["config"] = widget_instance.configuration
            cleaned_config.append(cleaned_widget)

        return True, cleaned_config

    def post(self, request):
        body = json.loads(request.body)
        widgets = body.get("widgets", [])
        dashboard_id = body.get("dashboard_id")

        is_clean, result = self.validate_widgets_config(request, widgets)
        if not is_clean:
            return JsonResponse({"error": result}, status=400)

        # Get or create dashboard
        if dashboard_id:
            dashboard_config = Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
                id=dashboard_id,
            ).first()
            if not dashboard_config:
                return JsonResponse({"error": "Dashboard not found"}, status=404)
        else:
            dashboard_config = Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
                is_default=True,
            ).first()
            if not dashboard_config:
                dashboard_config = Dashboard.objects.create(
                    organization=request.current_organization,
                    user=request.user,
                    name="Default",
                    is_default=True,
                    config={"widgets": []},
                )

        dashboard_config.config = {"widgets": result}
        dashboard_config.save()

        return JsonResponse({"message": "dashboard saved"}, status=200)


class CreateDashboardView(LoginRequiredMixin, View):
    def _get_name(self, request):
        base_name = "New Dashboard"
        existing_names = set(
            Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
            ).values_list("name", flat=True)
        )
        name = base_name
        counter = 0
        while name in existing_names:
            counter += 1
            name = f"{base_name} ({counter})"

        return name

    def post(self, request):
        if not request.current_organization:
            return JsonResponse({"error": "No organization selected"}, status=400)

        name = self._get_name(request)
        dashboard = Dashboard.objects.create(
            organization=request.current_organization,
            user=request.user,
            name=name,
            is_default=False,
            config={"widgets": []},
        )
        return JsonResponse(
            {"id": str(dashboard.id), "name": dashboard.name}, status=201
        )


class UpdateDashboardView(LoginRequiredMixin, View):
    def post(self, request):
        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        dashboard_id = body.get("dashboard_id")
        if not dashboard_id:
            return JsonResponse({"error": "dashboard_id required"}, status=400)

        dashboard = Dashboard.objects.filter(
            organization=request.current_organization,
            user=request.user,
            id=dashboard_id,
        ).first()
        if not dashboard:
            return JsonResponse({"error": "Dashboard not found"}, status=404)

        # Set dashboard as default
        if body.get("set_default") is True:
            Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
            ).update(is_default=False)
            dashboard.is_default = True
            dashboard.save()
            return JsonResponse({"message": "Dashboard set as default"})

        # Update dashboard name
        new_name = body.get("name")
        if new_name is not None:
            new_name = new_name.strip()
            if not new_name:
                return JsonResponse({"error": "Name cannot be empty"}, status=400)
            exists = (
                Dashboard.objects.filter(
                    organization=request.current_organization,
                    user=request.user,
                    name=new_name,
                )
                .exclude(id=dashboard.id)
                .exists()
            )
            if exists:
                return JsonResponse(
                    {"error": "A dashboard with this name already exists"},
                    status=400,
                )
            dashboard.name = new_name
            dashboard.save()
            return JsonResponse({"message": "Dashboard updated", "name": new_name})

        return JsonResponse({"error": "Nothing to update"}, status=400)


class DeleteDashboardView(LoginRequiredMixin, View):
    def post(self, request):
        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        dashboard_id = body.get("dashboard_id")
        if not dashboard_id:
            return JsonResponse({"error": "dashboard_id required"}, status=400)

        dashboard = Dashboard.objects.filter(
            organization=request.current_organization,
            user=request.user,
            id=dashboard_id,
        ).first()
        if not dashboard:
            return JsonResponse({"error": "Dashboard not found"}, status=404)

        # Check if there is only one dashboard
        dashboards_count = Dashboard.objects.filter(
            organization=request.current_organization,
            user=request.user,
        ).count()
        if dashboards_count <= 1:
            return JsonResponse(
                {"error": "Cannot delete the last dashboard"},
                status=400,
            )

        was_default = dashboard.is_default
        dashboard.delete()
        response_data = {"message": "Dashboard deleted"}

        # Set a new default dashboard
        if was_default:
            new_default = (
                Dashboard.objects.filter(
                    organization=request.current_organization,
                    user=request.user,
                )
                .order_by("created_at")
                .first()
            )
            if new_default:
                new_default.is_default = True
                new_default.save()
                response_data["new_default_id"] = str(new_default.id)

        return JsonResponse(response_data, status=200)


class BaseWidgetDataView(LoginRequiredMixin, View):
    def _render_widget(self, request, widget_config, include_config=False):
        widget_class_entry = list_widgets().get(widget_config["type"])
        if not widget_class_entry:
            return JsonResponse({"error": "Invalid widget type"}, status=400)

        widget_class = widget_class_entry["class"]

        try:
            widget = widget_class(request, widget_config)
            html = widget.index()
        except ValueError as e:
            message = "Error rendering widget"
            logger.warning(f"{message}: {e}")
            return JsonResponse({"error": message}, status=400)

        data = {"html": html}
        if include_config:
            data["config"] = widget.configuration

        return JsonResponse(data)


class LoadWidgetDataView(BaseWidgetDataView):
    def get(self, request, widget_id):
        dashboard_id = request.GET.get("dashboard_id")

        # Get the dashboard config
        if dashboard_id:
            dashboard = Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
                id=dashboard_id,
            ).first()
        else:
            dashboard = Dashboard.objects.filter(
                organization=request.current_organization,
                user=request.user,
                is_default=True,
            ).first()

        if not dashboard:
            return JsonResponse({"error": "Dashboard not found"}, status=404)

        widget_config = next(
            (w for w in dashboard.config.get("widgets", []) if w["id"] == widget_id),
            None,
        )
        if not widget_config:
            return JsonResponse({"error": "Widget not found"}, status=404)

        return self._render_widget(request, widget_config)


class RenderWidgetDataView(BaseWidgetDataView):
    def post(self, request, widget_type):
        widget_class_entry = list_widgets().get(widget_type)
        if not widget_class_entry:
            return JsonResponse({"error": "Invalid widget type"}, status=400)

        widget_config = {
            "id": request.POST.get("id"),
            "type": widget_type,
            "title": None,
            "config": json.loads(request.POST.get("config", "{}")),
        }

        return self._render_widget(request, widget_config, include_config=True)


class LoadWidgetConfigView(LoginRequiredMixin, View):
    def post(self, request, widget_type):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        widget_class_entry = list_widgets().get(widget_type)
        if not widget_class_entry:
            return JsonResponse({"error": "Invalid widget type"}, status=400)

        widget_class = widget_class_entry["class"]

        widget_config = {
            "id": None,
            "type": widget_type,
            "title": data.get("title", {}),
            "config": data.get("config", {}),
        }

        try:
            widget_intance = widget_class(request, widget_config, validate_config=False)
            html = widget_intance.config()
        except ValueError as e:
            message = "Error rendering widget config"
            logger.error(f"{message}: {e}")
            return JsonResponse({"error": message}, status=400)

        return JsonResponse({"html": html})
