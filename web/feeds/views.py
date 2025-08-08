from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.syndication.views import Feed
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.template import loader
from django.urls import reverse
from django.utils import timezone
from django.views.generic import ListView, CreateView, DeleteView

from changes.models import Change
from feeds.forms import FeedTokenForm
from feeds.models import FeedToken
from organizations.mixins import OrganizationIsMemberMixin
from projects.models import Project


class FeedTokenListView(LoginRequiredMixin, ListView):
    """View to list and manage feed tokens."""
    model = FeedToken
    template_name = "feeds/token_management.html"
    context_object_name = "tokens"
    
    def get_queryset(self):
        return FeedToken.objects.filter(user=self.request.user).order_by("name")
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = FeedTokenForm(user=self.request.user)
        return context


class FeedTokenCreateView(LoginRequiredMixin, CreateView):
    """View to create a new feed token."""
    model = FeedToken
    form_class = FeedTokenForm
    template_name = "feeds/create_token.html"
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs
    
    def get_success_url(self):
        return reverse('feeds:feed_tokens')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['tokens'] = FeedToken.objects.filter(user=self.request.user).order_by("name")
        return context


class FeedTokenDeleteView(LoginRequiredMixin, DeleteView):
    """View to delete a feed token."""
    model = FeedToken
    
    def get_queryset(self):
        return FeedToken.objects.filter(user=self.request.user)
    
    def get_object(self):
        return get_object_or_404(self.get_queryset(), id=self.kwargs['token_id'])
    
    def get_success_url(self):
        return reverse('feeds:feed_tokens')


class BaseFeed(Feed):
    """Base feed class with common functionality."""
    
    def get_object(self, request, token):
        """
        Get the user from the token and validate access.
        
        This method:
        1. Retrieves the token from the database
        2. Updates the last_used timestamp
        3. Returns the associated user
        
        If the token is invalid, it raises a 404 error.
        """
        try:
            feed_token = FeedToken.objects.get(token=token)
            
            # Update last used timestamp
            feed_token.last_used = timezone.now()
            feed_token.save()
            
            return feed_token.user
        except FeedToken.DoesNotExist:
            raise Http404("Invalid feed token")
    
    def item_title(self, item):
        return f"{item.cve.cve_id} - {item.created_at.strftime('%Y-%m-%d')}"
    
    def item_description(self, item):
        # Get the change data
        change_data = item.change_data
        
        # Create a context for the template
        context = {
            'obj': item,
            'link': self.item_link(item),
            'change_data': change_data
        }
        
        # Render the template
        template = loader.get_template('feeds/feed_description.html')
        return template.render(context)
    
    def item_link(self, item):
        return reverse('change', kwargs={'cve_id': item.cve.cve_id, 'id': item.id})
    
    def item_pubdate(self, item):
        return item.created_at


class UserFeed(BaseFeed):
    """Feed for all CVEs related to all projects the user has access to."""
    
    def title(self, user):
        return f"OpenCVE - {user.username}'s CVE Feed"
        
    def link(self, user):
        return reverse('activity')
        
    def description(self, user):
        return f"Recent CVE changes for {user.username}'s subscriptions"
        
    def items(self, user):
        # Get all organizations the user is a member of
        organizations = user.list_organizations()
        
        # Get all vendors from all projects in these organizations
        vendors = []
        for org in organizations:
            vendors.extend(org.get_projects_vendors())
            
        # Get changes for these vendors
        if vendors:
            return Change.objects.filter(
                cve__vendors__has_any_keys=vendors
            ).select_related("cve").order_by("-created_at")[:30]
        return []


class ProjectFeed(BaseFeed):
    """Feed for CVEs related to a specific project."""
    
    def get_object(self, request, token, org_name, project_name):
        """Get the user and project."""
        user = super().get_object(request, token)
        
        # Check if the user has access to the organization
        organizations = user.list_organizations()
        organization = next((org for org in organizations if org.name == org_name), None)
        
        if not organization:
            raise Http404("Organization not found")
            
        # Get the project
        project = get_object_or_404(Project, organization=organization, name=project_name)
        
        return {
            'user': user,
            'project': project
        }
        
    def title(self, obj):
        return f"OpenCVE - {obj['project'].name} CVE Feed"
        
    def link(self, obj):
        return reverse('project', kwargs={
            'org_name': obj['project'].organization.name,
            'project_name': obj['project'].name
        })
        
    def description(self, obj):
        return f"Recent CVE changes for {obj['project'].name} project"
        
    def items(self, obj):
        project = obj['project']
        
        # Get all vendors from the project
        vendors = project.subscriptions["vendors"] + project.subscriptions["products"]
            
        # Get changes for these vendors
        if vendors:
            return Change.objects.filter(
                cve__vendors__has_any_keys=vendors
            ).select_related("cve").order_by("-created_at")[:30]
        return []