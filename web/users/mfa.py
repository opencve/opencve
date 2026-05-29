from allauth.mfa import signals
from allauth.mfa.base.internal.flows import delete_dangling_recovery_codes
from allauth.mfa.models import Authenticator
from allauth.mfa.utils import is_mfa_enabled


def _delete_authenticator(request, target_user, authenticator) -> None:
    authenticator.delete()
    rc_auth = delete_dangling_recovery_codes(target_user)
    for auth in [authenticator, rc_auth]:
        if auth:
            signals.authenticator_removed.send(
                sender=Authenticator,
                request=request,
                user=target_user,
                authenticator=auth,
            )


def reset_user_mfa(request, target_user) -> int:
    """
    Remove all MFA authenticators for target_user (admin recovery flow).

    Returns the number of authenticator records removed.
    """
    if not is_mfa_enabled(target_user):
        return 0

    removed = 0
    while True:
        authenticator = (
            Authenticator.objects.filter(user=target_user)
            .exclude(type=Authenticator.Type.RECOVERY_CODES)
            .first()
        )
        if not authenticator:
            break
        _delete_authenticator(request, target_user, authenticator)
        removed += 1

    rc_auth = delete_dangling_recovery_codes(target_user)
    if rc_auth:
        signals.authenticator_removed.send(
            sender=Authenticator,
            request=request,
            user=target_user,
            authenticator=rc_auth,
        )
        removed += 1

    return removed
