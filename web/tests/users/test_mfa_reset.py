import pytest
from django.contrib.admin.models import LogEntry
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory
from django.urls import reverse

from allauth.mfa.models import Authenticator
from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
from allauth.mfa.totp.internal.auth import TOTP, generate_totp_secret
from allauth.mfa.utils import is_mfa_enabled

from users.admin import UserAdmin
from users.mfa import reset_user_mfa
from users.models import User


@pytest.fixture
def superuser(create_user, create_organization):
    user = create_user(username="admin", is_superuser=True, is_staff=True)
    create_organization("admin-org", user=user)
    return user


@pytest.fixture
def staff_user(create_user, create_organization):
    user = create_user(username="staff", is_superuser=False, is_staff=True)
    create_organization("staff-org", user=user)
    content_type = ContentType.objects.get_for_model(User)
    permission = Permission.objects.get(
        content_type=content_type,
        codename="change_user",
    )
    user.user_permissions.add(permission)
    return user


@pytest.fixture
def user_with_mfa(create_user):
    user = create_user(username="mfa_user")
    TOTP.activate(user, generate_totp_secret())
    RecoveryCodes.activate(user)
    return user


@pytest.mark.django_db
def test_reset_user_mfa_removes_all_authenticators(superuser, user_with_mfa):
    """Remove all allauth authenticators for the target user via reset_user_mfa."""
    request = RequestFactory().post("/")
    request.user = superuser

    assert is_mfa_enabled(user_with_mfa)
    assert Authenticator.objects.filter(user=user_with_mfa).count() == 2

    removed = reset_user_mfa(request, user_with_mfa)

    # TOTP removal also clears recovery codes via delete_dangling_recovery_codes.
    assert removed >= 1
    assert not is_mfa_enabled(user_with_mfa)
    assert Authenticator.objects.filter(user=user_with_mfa).count() == 0


@pytest.mark.django_db
def test_reset_user_mfa_noop_when_disabled(superuser, create_user):
    """Return 0 from reset_user_mfa when the user has no MFA configured."""
    user = create_user(username="no_mfa")
    request = RequestFactory().post("/")
    request.user = superuser

    assert reset_user_mfa(request, user) == 0


@pytest.mark.django_db
def test_admin_change_shows_disable_mfa_button(client, superuser, user_with_mfa):
    """Show the Disable MFA link on the admin user change page for a superuser."""
    client.force_login(superuser)
    url = reverse("admin:users_user_change", args=[user_with_mfa.pk])

    response = client.get(url)

    assert response.status_code == 200
    content = response.content.decode()
    assert "Disable MFA" in content
    assert reverse("admin:users_user_disable_mfa", args=[user_with_mfa.pk]) in content


@pytest.mark.django_db
def test_admin_change_hides_disable_mfa_for_non_superuser(
    client, staff_user, user_with_mfa
):
    """Hide the Disable MFA link on the admin user change page for non-superuser staff."""
    client.force_login(staff_user)
    url = reverse("admin:users_user_change", args=[user_with_mfa.pk])

    response = client.get(url)

    assert response.status_code == 200
    assert "Disable MFA" not in response.content.decode()


@pytest.mark.django_db
def test_admin_change_hides_disable_mfa_for_self(client, superuser):
    """Hide the Disable MFA link when a superuser views their own account."""
    TOTP.activate(superuser, generate_totp_secret())
    client.force_login(superuser)
    url = reverse("admin:users_user_change", args=[superuser.pk])

    response = client.get(url)

    assert response.status_code == 200
    assert "Disable MFA" not in response.content.decode()


@pytest.mark.django_db
def test_admin_disable_mfa_rejects_unsupported_methods(
    client, superuser, user_with_mfa
):
    """Return 405 for HTTP methods other than GET and POST."""
    client.force_login(superuser)
    url = reverse("admin:users_user_disable_mfa", args=[user_with_mfa.pk])

    response = client.put(url)

    assert response.status_code == 405
    assert is_mfa_enabled(user_with_mfa)


@pytest.mark.django_db
def test_admin_disable_mfa_post(client, superuser, user_with_mfa):
    """Disable MFA via admin confirmation POST and redirect to the user change page."""
    client.force_login(superuser)
    url = reverse("admin:users_user_disable_mfa", args=[user_with_mfa.pk])

    response = client.post(url)

    assert response.status_code == 302
    assert response.url == reverse("admin:users_user_change", args=[user_with_mfa.pk])
    assert not is_mfa_enabled(user_with_mfa)
    content_type = ContentType.objects.get_for_model(User)
    assert LogEntry.objects.filter(
        user_id=superuser.pk,
        content_type=content_type,
        object_id=str(user_with_mfa.pk),
        change_message__contains="Disabled MFA",
    ).exists()


@pytest.mark.django_db
def test_admin_disable_mfa_forbidden_for_non_superuser(
    client, staff_user, user_with_mfa
):
    """Return 403 when non-superuser staff POSTs to the admin disable MFA URL."""
    client.force_login(staff_user)
    url = reverse("admin:users_user_disable_mfa", args=[user_with_mfa.pk])

    response = client.post(url)

    assert response.status_code == 403
    assert is_mfa_enabled(user_with_mfa)


@pytest.mark.django_db
def test_admin_disable_mfa_forbidden_for_self(client, superuser):
    """Return 403 when a superuser POSTs to disable MFA on their own account."""
    TOTP.activate(superuser, generate_totp_secret())
    client.force_login(superuser)
    url = reverse("admin:users_user_disable_mfa", args=[superuser.pk])

    response = client.post(url)

    assert response.status_code == 403
    assert is_mfa_enabled(superuser)


@pytest.mark.django_db
def test_admin_disable_mfa_respects_change_permission(
    client, superuser, user_with_mfa, monkeypatch
):
    """Return 403 when has_change_permission denies access to the target user."""
    client.force_login(superuser)
    url = reverse("admin:users_user_disable_mfa", args=[user_with_mfa.pk])

    monkeypatch.setattr(
        UserAdmin,
        "has_change_permission",
        lambda self, request, obj=None: False,
    )

    response = client.post(url)

    assert response.status_code == 403
    assert is_mfa_enabled(user_with_mfa)
