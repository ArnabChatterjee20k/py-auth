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
        return await session.create(role)

    async def get(self, role: Role):
        if role.permissions:
            role.permissions = self.parse(role.permissions)
        session = self.get_storage_session()
        # exclude account id or session id if they are none
        filters = role.to_dict(exclude=["permissions"], include_none=False)
        contains = {"permissions": role.permissions} if role.permissions else None
        return await session.get(Role, filters=filters, contains=contains)

    async def update(self, role: Role) -> Role:
        role.permissions = self.parse(role.permissions)
        session = self.get_storage_session()
        # exclude account id or session id if they are none
        filters = role.to_dict(exclude=["permissions"], include_none=False)
        # sqlite doesn't implement row level locking
        account_role = await session.get(model=Role, for_update=True, filters=filters)
        role_filters_exclude = ["permissions"]
        if not role.session_uid:
            role_filters_exclude.append("session_uid")
        updated_accont_role = await session.update(
            Role,
            filters={"id": account_role.id, **role.to_dict(role_filters_exclude)},
            updates={"permissions": role.permissions},
        )
        return updated_accont_role

    async def check(self, role: Role):
        permission = await self.get(role)
        if permission:
            return True
        return False

    async def remove(self, role: Role, permissions_to_remove: list[str]) -> Role:
        account_role = await self.get(role)
        if not account_role:
            raise InvalidPermissionAction("Account not found.")

        new_permissions = [
            p for p in account_role.permissions if p not in permissions_to_remove
        ]

        account_role.permissions = new_permissions
        return await self.update(account_role)

    async def delete(self, account_id: str, session_id: str | None = None):
        session = self.get_storage_session()
        filters = {"account_uid": account_id}
        if session_id:
            filters["session_id"] = session_id
        await session.delete(Role, filters=filters)
