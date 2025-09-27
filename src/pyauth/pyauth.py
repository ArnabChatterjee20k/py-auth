from .providers import Provider, Payload
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
    async def create_account(self, payload: Payload) -> Account:
        self._provider.validate_paylod(payload)
        async with self._storage.begin() as storage:
            account = self._provider.create_account(payload)
            account = await storage.create(account)
            async with self._permissions.set_storage_session(storage) as permission:
                await permission.assign(
                    Role(account_uid=account.uid, permissions=payload.permissions)
                )
        return account

    async def logout_account(self):
        pass

    async def get_account(self):
        pass

    async def delete_account(self):
        pass

    async def update_account(self):
        pass

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
