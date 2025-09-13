from providers import Provider, Payload
from .storage import Storage
from .permissions import Permissions
from .models import Account


class Pyauth:
    async def __init__(
        self, provider: Provider, storage: Storage, permissions: Permissions
    ):
        self._provider = provider
        self._storage = storage
        self._permissions = permissions.get_adapter().init_storage(storage)

    # account
    async def create_account(self, payload: Payload) -> Account:
        self._provider.validate_paylod(payload)
        async with self._storage as storage:
            account = self._provider.create_account(payload)
            self._storage.create(account)
            self._storage.create(account.permissions)

        return self._provider.create_account(payload)

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
    def assign_role(self):
        pass

    def update_role(self):
        pass

    def verify_role(self):
        pass

    def get_roles(self):
        pass

    # rate-limit/throttling/control
    def set_attempts(self):
        pass

    # helpers/decorators
    def require_auth(self):
        pass

    def require_role(self):
        pass
