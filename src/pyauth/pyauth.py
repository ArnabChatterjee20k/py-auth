from .providers import Provider, Payload, InvalidAccount
import asyncio
from .token import Token
from .storage import Storage
from .permissions import Permissions
from .models import Account, Session, Role


class Pyauth:
    def __init__(self, provider: Provider, storage: Storage, permissions: Permissions):
        self._provider = provider
        self._storage = storage
        self._permissions = permissions

    async def init_schema(self):
        models = [Account, Session]
        # HACK: scoping task group inside session and permission context so that connection doesn't get closed
        async with self._storage.session() as session:
            async with self._permissions.set_storage_session(session) as permission:
                async with asyncio.TaskGroup() as group:
                    for model in models:
                        group.create_task(session.init_schema(model))
                    group.create_task(permission.init_schema())

    # account
    # in every function the payload should match the stored account
    # example -> if password adapter then the password of the payload should be same as the present account
    async def create_account(self, payload: Payload) -> Account:
        async with self._storage.begin() as storage:
            async with self._provider.set_storage_session(storage) as provider:
                account = await provider.create(payload)
            async with self._permissions.set_storage_session(storage) as permission:
                await permission.create(
                    Role(account_uid=account.uid, permissions=payload.permissions)
                )
        return account

    async def get_account(self, payload: Payload) -> Account:
        async with self._storage.session() as storage:
            async with self._provider.set_storage_session(storage) as provider:
                account = await provider.get(payload)
        return account

    async def delete_account(self, payload: Payload):
        async with self._storage.session() as storage:
            async with self._provider.set_storage_session(storage) as provider:
                account = await provider.get(payload)
                if not account:
                    return InvalidAccount("Account not found")
                async with self._permissions.set_storage_session(
                    storage
                ) as permissions:
                    async with asyncio.TaskGroup() as group:
                        # TODO: delete sessions as well -> might be using some queuing mechanism(or might be let user do this)
                        group.create_task(provider.delete(payload))
                        group.create_task(permissions.delete(account.uid))

    async def update_account(self, payload: Payload, updated_account: Account):
        async with self._storage.session() as storage:
            async with self._provider.set_storage_session(storage) as provider:
                account = await provider.get(payload)
                if not account:
                    return InvalidAccount("Account not found")
                account = await provider.update(payload, updated_account)
        return account

    async def block_account(self):
        pass

    async def verify_account(self):
        pass

    async def get_sessions(self):
        pass

    # session
    async def start_session(self):
        pass

    async def end_session(self):
        pass

    async def get_current_account(self):
        pass

    # roles
    def grant(self):
        pass

    def revoke(self):
        pass

    def check(self):
        pass

    def list(self):
        pass

    # rate-limit/throttling/control
    def set_attempts(self):
        pass

    # helpers/decorators
    def require_auth(self):
        pass

    def require_role(self):
        pass
