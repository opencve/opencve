import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.generic import TemplateView

from dashboards.models import DashboardConfig


class DashboardView(TemplateView):
    template_name = "dashboards/index.html"


@login_required
def save_dashboard(request):
    if request.method == "POST":
        data = json.loads(request.body)
        user = request.user

        dashboard_config, _ = DashboardConfig.objects.get_or_create(user=user)
        dashboard_config.config = data.get("dashboard", [])
        dashboard_config.save()

        return JsonResponse({"message": "dashboard saved"}, status=200)

    return JsonResponse({"error": "method not allowed"}, status=405)


@login_required
def load_dashboard(request):
    dashboard_config, _ = DashboardConfig.objects.get_or_create(user=request.user)
    return JsonResponse({"dashboard": dashboard_config.config})
