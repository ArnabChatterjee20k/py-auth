import pytest
from src.pyauth.permissions.RBAC import RBAC, InvalidPermissionAction
from src.pyauth.models import Role


@pytest.mark.asyncio
async def test_rbac_create_get_update_delete(initialized_storage):
    rbac = RBAC()
    async with initialized_storage.session() as storage:
        async with rbac.set_storage_session(storage) as perms:
            await perms.init_schema()

            role = Role(account_uid="u1", permissions=["create", "read"])
            created = await perms.create(role)
            assert created.account_uid == "u1"

            fetched = await perms.get(Role(account_uid="u1"))
            assert fetched and set(fetched.permissions) == {"create", "read"}

            updated = await perms.update(Role(account_uid="u1", permissions=["read"]))
            assert updated.permissions == ["read"]

            after_remove = await perms.remove(Role(account_uid="u1"), ["read"])
            assert after_remove.permissions == []

            await perms.delete(account_id="u1")
            assert await perms.get(Role(account_uid="u1")) is None


def test_rbac_invalid_permissions():
    rbac = RBAC()
    with pytest.raises(InvalidPermissionAction):
        rbac.parse(["invalid_action"])


@pytest.mark.asyncio
async def test_rbac_check_true_false(initialized_storage):
    rbac = RBAC()
    async with initialized_storage.session() as storage:
        async with rbac.set_storage_session(storage) as perms:
            await perms.init_schema()
            await perms.create(Role(account_uid="chk", permissions=["read"]))
            assert (
                await perms.check(Role(account_uid="chk", permissions=["read"])) is True
            )
            await perms.delete(account_id="chk")
            assert (
                await perms.check(Role(account_uid="chk", permissions=["read"]))
                is False
            )


@pytest.mark.asyncio
async def test_rbac_get_with_session_scope(initialized_storage):
    rbac = RBAC()
    async with initialized_storage.session() as storage:
        async with rbac.set_storage_session(storage) as perms:
            await perms.init_schema()
            # same account, different sessions
            await perms.create(
                Role(account_uid="acc1", session_uid="s1", permissions=["create"])
            )
            await perms.create(
                Role(account_uid="acc1", session_uid="s2", permissions=["read"])
            )

            # fetch only s2
            r = await perms.get(Role(account_uid="acc1", session_uid="s2"))
            assert r is not None and r.session_uid == "s2" and r.permissions == ["read"]


@pytest.mark.asyncio
async def test_rbac_update_invalid_action_raises(initialized_storage):
    rbac = RBAC()
    async with initialized_storage.session() as storage:
        async with rbac.set_storage_session(storage) as perms:
            await perms.init_schema()
            await perms.create(Role(account_uid="inv", permissions=["read"]))
            with pytest.raises(InvalidPermissionAction):
                await perms.update(
                    Role(account_uid="inv", permissions=["not_an_action"])
                )


@pytest.mark.asyncio
async def test_rbac_remove_nonexistent_role_raises(initialized_storage):
    rbac = RBAC()
    async with initialized_storage.session() as storage:
        async with rbac.set_storage_session(storage) as perms:
            await perms.init_schema()
            with pytest.raises(InvalidPermissionAction):
                await perms.remove(Role(account_uid="missing"), ["read"])


@pytest.mark.asyncio
async def test_rbac_get_by_contains_permission(initialized_storage):
    rbac = RBAC()
    async with initialized_storage.session() as storage:
        async with rbac.set_storage_session(storage) as perms:
            await perms.init_schema()
            await perms.create(
                Role(account_uid="contain", permissions=["create", "read"])
            )
            # request any role for account that contains 'read'
            result = await perms.get(Role(account_uid="contain", permissions=["read"]))
            assert result is not None and "read" in result.permissions
