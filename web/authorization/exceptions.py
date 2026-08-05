class RoleAlreadyRegisteredError(Exception):
    pass


class UnknownBaseRoleError(Exception):
    pass


class CircularRoleDependencyError(Exception):
    pass
