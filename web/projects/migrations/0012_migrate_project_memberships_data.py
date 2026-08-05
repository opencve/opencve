from django.db import migrations


def create_project_memberships_for_members(apps, schema_editor):
    Membership = apps.get_model("organizations", "Membership")
    Project = apps.get_model("projects", "Project")
    ProjectMembership = apps.get_model("projects", "ProjectMembership")

    contributor_role = "contributor"
    member_role = "member"

    for membership in Membership.objects.filter(
        role=member_role, date_joined__isnull=False
    ).iterator():
        projects = Project.objects.filter(organization_id=membership.organization_id)
        to_create = []
        for project in projects.iterator():
            if project.organization_id != membership.organization_id:
                continue
            to_create.append(
                ProjectMembership(
                    project_id=project.id,
                    membership_id=membership.id,
                    role=contributor_role,
                )
            )
        if to_create:
            ProjectMembership.objects.bulk_create(
                to_create, ignore_conflicts=True, batch_size=500
            )


def reverse_project_memberships(apps, schema_editor):
    ProjectMembership = apps.get_model("projects", "ProjectMembership")
    ProjectMembership.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0011_projectmembership"),
    ]

    operations = [
        migrations.RunPython(
            create_project_memberships_for_members,
            reverse_project_memberships,
        ),
    ]
