from .permissions import Permissions, Action, InvalidPermissionAction
from ..models import Role
from enum import Enum


class RBAC(Permissions):
    def __init__(self):
        super().__init__()

    def parse(self, permissions) -> list[str]:
        if not isinstance(permissions, list):
            raise InvalidPermissionAction("Permissions must be a list.")

        parsed = []
        for perm in permissions:
            if not isinstance(perm, str):
                raise InvalidPermissionAction(
                    f"RBAC permissions must be strings, got: {perm}"
                )
            if perm not in Action.__members__.values():
                raise InvalidPermissionAction(f"Invalid RBAC action: {perm}")
            parsed.append(perm)

        return parsed
