from .providers import Provider, Payload, InvalidAccount
import asyncio
from .token import Token
from .storage import Storage
from .permissions import Permissions, RBAC
from .models import Account, Session, Role
from .session import SessionAdapter
from typing import Optional, List
from contextlib import asynccontextmanager


class Pyauth:
    def __init__(
        self,
        provider: Provider,
        storage: Storage,
        permissions: Permissions = RBAC(),
        token_secret: str | None = None,
    ):
        self._provider = provider
        self._storage = storage
        self._permissions = permissions
        if not token_secret:
            import secrets

            token_secret = secrets.token_urlsafe(16)
        self._session_adapter = SessionAdapter(token_secret)

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
                    async with self._session_adapter.set_storage_session(
                        storage
                    ) as session_adapter:
                        async with asyncio.TaskGroup() as group:
                            # Delete account, permissions, and all sessions
                            group.create_task(provider.delete(payload))
                            group.create_task(permissions.delete(account.uid))
                            group.create_task(
                                self._delete_all_sessions_for_account(
                                    session_adapter, account.uid
                                )
                            )

    async def update_account(self, payload: Payload, updated_account: Account):
        async with self._storage.session() as storage:
            async with self._provider.set_storage_session(storage) as provider:
                account = await provider.update(payload, updated_account)
        return account

    async def block_account(self):
        pass

    async def verify_account(self):
        pass

    # session
    async def get_sessions(
        self, account_uid: str, limit: int = 25, after_id: Optional[int] = None
    ) -> List[Session]:
        """Get all sessions for a specific account"""
        async with self._storage.session() as storage:
            async with self._session_adapter.set_storage_session(
                storage
            ) as session_adapter:
                return await session_adapter.list(account_uid, limit, after_id)

    async def start_session(
        self, payload: Payload, metadata: Optional[dict] = None
    ) -> Session:
        """Start a new session for an account after authentication"""
        async with self._storage.session() as storage:
            # First verify the account exists and credentials are valid
            async with self._provider.set_storage_session(storage) as provider:
                account = await provider.get(payload)
                if not account:
                    raise InvalidAccount("Account not found")

            # Create session for the verified account
            async with self._session_adapter.set_storage_session(
                storage
            ) as session_adapter:
                session = await session_adapter.create(account.uid, metadata)

                # Update last_active_at for the account
                async with self._provider.set_storage_session(storage) as provider:
                    from datetime import datetime

                    updated_account = Account(
                        uid=account.uid,
                        password=account.password,
                        permissions=account.permissions,
                        is_active=account.is_active,
                        is_blocked=account.is_blocked,
                        created_at=account.created_at,
                        updated_at=account.updated_at,
                        last_active_at=datetime.now(),
                        metadata=account.metadata,
                    )
                    await provider.update(payload, updated_account)

                return session

    async def end_session(self, sid: str) -> bool:
        """End a specific session by session ID"""
        async with self._storage.session() as storage:
            async with self._session_adapter.set_storage_session(
                storage
            ) as session_adapter:
                return await session_adapter.set_session_active(sid, False)

    async def get_current_account_from_session(self, access_token: str) -> Account:
        """Get the current account from a valid access token"""
        async with self._storage.session() as storage:
            async with self._session_adapter.set_storage_session(
                storage
            ) as session_adapter:
                # Verify the session and get account_uid
                session = await session_adapter.verify(access_token)

                # Get the account directly from storage using account_uid
                # This avoids needing to create a specific payload type
                account = await storage.get(
                    Account, filters={"uid": session.account_uid}
                )
                if not account:
                    raise InvalidAccount("Account not found")

                if not account.is_active or account.is_blocked:
                    raise InvalidAccount("Account is blocked or inactive")

                permission = await storage.get(
                    Role, filters={"account_uid": session.account_uid}
                )
                account.permissions = permission.permissions
                return account

    async def get_current_session(self, access_token: str) -> Session:
        """Get the current account from a valid access token"""
        async with self._storage.session() as storage:
            async with self._session_adapter.set_storage_session(
                storage
            ) as session_adapter:
                # Verify the session and get account_uid
                session = await session_adapter.verify(access_token)

                permission = await storage.get(
                    Role,
                    filters={
                        "account_uid": session.account_uid,
                        "session_uid": session.sid,
                    },
                )
                if permission:
                    session.permissions = permission.permissions
                return session

    async def refresh_session(self, refresh_token: str) -> Session:
        async with self._storage.session() as storage:
            async with self._session_adapter.set_storage_session(
                storage
            ) as session_adapter:
                return session_adapter.refresh_access_token(refresh_token)

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

    async def _delete_all_sessions_for_account(self, session_adapter, account_uid: str):
        """Helper method to delete all sessions for a specific account using bulk delete"""
        return await session_adapter.bulk_delete_by_account(account_uid)

    @asynccontextmanager
    async def as_admin(self):
        """Context manager for admin operations that bypass payload verification"""
        try:
            self._provider.set_admin(True)
            yield self
        finally:
            self._provider.set_admin(False)
