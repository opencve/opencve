from projects.models import Project


def current_user_projects(request):
    projects = []
    if request.user.is_authenticated:
        projects = Project.objects.filter(user=request.user).order_by("name").all()
    return {'user_projects': projects}
