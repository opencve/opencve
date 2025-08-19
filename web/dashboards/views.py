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
        return context


class LoadDashboardView(LoginRequiredMixin, View):
    def get(self, request):
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
        widgets = json.loads(request.body)
        is_clean, result = self.validate_widgets_config(request, widgets)

        if not is_clean:
            return JsonResponse({"error": result}, status=400)

        dashboard_config, _ = Dashboard.objects.get_or_create(
            organization=request.current_organization,
            user=request.user,
            is_default=True,
        )
        dashboard_config.config = {"widgets": result}
        dashboard_config.save()

        return JsonResponse({"message": "dashboard saved"}, status=200)


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
        dashboard = Dashboard.objects.filter(
            organization=request.current_organization,
            user=request.user,
            is_default=True,
        ).first()
        if not dashboard:
            return JsonResponse({"error": "Dashboard not found"}, status=404)

        widget_config = next(
            (w for w in dashboard.config["widgets"] if w["id"] == widget_id), None
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
