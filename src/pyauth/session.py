from typing import TypeVar, Type, AsyncGenerator, Any, Optional, List
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from uuid import uuid4

from .models import Model, Session as SessionModel
from .storage import StorageSession
from .token import Token

T = TypeVar("T", bound=Model)


class InvalidSession(Exception):
    def __init__(self, msg: str = None, *args):
        message = f"Invalid session: {msg}" if msg else "Invalid session"
        super().__init__(message, *args)


class BlockedSession(InvalidSession):
    def __init__(self):
        super().__init__("Session is blocked")


class ExpiredSession(InvalidSession):
    def __init__(self):
        super().__init__("Session is expired")


class SessionAdapter:
    _storage_session: StorageSession = None

    def __init__(
        self,
        token_secret: str,
        access_token_expiry: int = 900,
        refresh_token_expiry: int = 604800,
    ):
        self._token = Token(token_secret)
        self._access_token_expiry = access_token_expiry
        self._refresh_token_expiry = refresh_token_expiry

    @asynccontextmanager
    async def set_storage_session(
        self, storage: StorageSession
    ) -> AsyncGenerator["SessionAdapter", Any]:
        try:
            self._storage_session = storage
            yield self
        finally:
            self._storage_session = None

    def get_storage_session(self) -> StorageSession:
        if self._storage_session is None:
            raise ValueError("Storage session is not set")
        return self._storage_session

    async def create(
        self, account_uid: str, metadata: Optional[dict] = None
    ) -> SessionModel:
        sid = str(uuid4())

        access_token_exp = datetime.now() + timedelta(seconds=self._access_token_expiry)
        refresh_token_exp = datetime.now() + timedelta(
            seconds=self._refresh_token_expiry
        )

        access_token = self._token.create(
            {"sid": sid, "account_uid": account_uid}, expires_at=access_token_exp
        )
        refresh_token = self._token.create(
            {"sid": sid, "account_uid": account_uid}, expires_at=refresh_token_exp
        )

        session = SessionModel(
            sid=sid,
            account_uid=account_uid,
            access_token=access_token,
            refresh_token=refresh_token,
            is_active=True,
            is_blocked=False,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            expires_at=refresh_token_exp,
            metadata=metadata or {},
        )

        return await self.get_storage_session().create(session)

    async def get(self, sid: str) -> Optional[SessionModel]:
        session = await self.get_storage_session().get(
            SessionModel, filters={"sid": sid}
        )
        if not session:
            raise InvalidSession("Session not found")
        return session

    async def update(self, session: SessionModel) -> SessionModel:
        storage = self.get_storage_session()
        exclude = ["sid", "account_uid", "created_at"]
        updates = session.to_dict(exclude=exclude)
        updates["updated_at"] = datetime.utcnow()
        return await storage.update(SessionModel, {"sid": session.sid}, updates)

    async def delete(self, sid: str) -> bool:
        return await self.get_storage_session().delete(
            SessionModel, filters={"sid": sid}
        )

    async def list(
        self, account_uid: str, limit: int = 25, after_id: Optional[int] = None
    ) -> List[SessionModel]:
        return await self.get_storage_session().list(
            SessionModel,
            filters={"account_uid": account_uid},
            limit=limit,
            after_id=after_id,
        )

    async def verify(
        self, access_token: str, check_expired: bool = True
    ) -> SessionModel:
        try:
            claims = self._token.extract(access_token)
        except Exception:
            raise InvalidSession("Invalid access token")

        sid = claims.get("sid")
        if not sid:
            raise InvalidSession("Invalid access token claims")

        session = await self.get(sid)

        if not session.is_active or session.is_blocked:
            raise InvalidSession("Session is blocked or inactive")

        if check_expired and session.is_expired():
            raise ExpiredSession()

        return session

    async def refresh_access_token(
        self, refresh_token: str, data: Optional[dict] = None
    ) -> SessionModel:
        try:
            claims = self._token.extract(refresh_token)
        except Exception:
            raise InvalidSession("Invalid refresh token")

        sid = claims.get("sid")
        account_uid = claims.get("account_uid")
        if not sid or not account_uid:
            raise InvalidSession("Invalid refresh token claims")

        session = await self.get(sid)

        if not session or not session.is_active or session.is_blocked:
            raise InvalidSession("Session invalid or blocked")

        if session.refresh_token != refresh_token:
            raise InvalidSession("Refresh token mismatch")

        access_token_exp = datetime.now() + timedelta(seconds=self._access_token_expiry)
        refresh_token_exp = datetime.now() + timedelta(
            seconds=self._refresh_token_expiry
        )

        base_claims = {
            "sid": sid,
            "account_uid": account_uid,
        }

        if data:
            base_claims.update(data)

        new_access_token = self._token.create(base_claims, expires_at=access_token_exp)
        new_refresh_token = self._token.create(
            {"sid": sid, "account_uid": account_uid}, expires_at=refresh_token_exp
        )

        return await self.update(
            SessionModel(
                sid=session.sid,
                account_uid=session.account_uid,
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                expires_at=refresh_token_exp,
                is_active=True,
                is_blocked=False,
                metadata=session.metadata,
            )
        )

    async def block(self, sid: str) -> SessionModel:
        return await self.update(sid, {"is_blocked": True, "is_active": False})

    async def unblock(self, sid: str) -> SessionModel:
        return await self.update(sid, {"is_blocked": False, "is_active": True})

    async def extend(self, sid: str, seconds: int) -> SessionModel:
        session = await self.get(sid)
        if session.expires_at:
            session.expires_at += timedelta(seconds=seconds)
        return await self.update(sid, {"expires_at": session.expires_at})
