from abc import ABC, abstractmethod
from typing import TypeVar, Type, AsyncGenerator, Any
from contextlib import asynccontextmanager
from ..models import Model, Account
from ..storage import StorageSession
from .payload import Payload

T = TypeVar("T", bound=Model)


class InvalidAccount(Exception):
    def __init__(self, msg: str = None, *args):
        message = f"Invalid account: {msg}" if msg else "Invalid account"
        super().__init__(message, *args)


class Provider(ABC):
    _storage_session: StorageSession = None
    _admin_operation: bool = False

    @asynccontextmanager
    async def set_storage_session(
        self, storage: StorageSession
    ) -> AsyncGenerator["Provider", Any]:
        try:
            self._storage_session = storage
            yield self
        finally:
            self._storage_session = None

    def get_storage_session(self) -> StorageSession:
        if self._storage_session is None:
            raise ValueError("Storage is not set")
        return self._storage_session

    def set_admin(self, admin_operation: bool = False) -> None:
        """Set admin mode for the provider"""
        self._admin_operation = admin_operation

    @abstractmethod
    async def create(self, payload: Payload) -> Account:
        pass

    @abstractmethod
    async def get(self, paylod: Payload) -> Account:
        pass

    @abstractmethod
    async def delete(self, paylod: Payload) -> bool:
        pass

    @abstractmethod
    async def update(self, payload: Payload, account: Account) -> Account:
        pass

    @staticmethod
    @abstractmethod
    def validate_payload(paylod: Payload) -> bool:
        pass

    @staticmethod
    def get_model_from_dict(model: Type[T], data: dict[str]) -> T:
        model_keys = model.get_fields()
        filtered = {k: v for k, v in data.items() if k in model_keys}
        return model(**filtered)
