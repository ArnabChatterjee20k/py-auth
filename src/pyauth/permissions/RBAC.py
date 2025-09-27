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

    async def init_schema(self):
        session = self.get_storage_session()
        await session.init_schema(Role)

    async def create(self, role: Role) -> Role:
        role.permissions = self.parse(role.permissions)
        session = self.get_storage_session()
        await session.create(role)

    async def get(self, role: Role):
        session = self.get_storage_session()
        filters = role.to_dict(exclude=["permissions"])
        contains = {"permissions": role.permissions} if role.permissions else None
        return await session.get(Role, filters=filters, contains=contains)

    async def update(self, role: Role) -> Role:
        session = self.get_storage_session()
        filters = role.to_dict(exclude=["permissions"])
        # sqlite doesn't implement row level locking
        account_role = await session.get(model=Role, for_update=True, filters=filters)
        account_role.permissions = role.permissions
        updated_accont_role = await session.update(
            Role,
            filters={"id": account_role.id, **role.to_dict(["permissions"])},
            updates={"permissions": role.permissions},
        )
        return updated_accont_role
