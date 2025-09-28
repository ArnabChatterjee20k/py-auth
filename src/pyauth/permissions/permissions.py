from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Any
from ..models import Role
from ..storage import StorageSession
from enum import Enum


class Action(str, Enum):
    """
    Every permissions boil down to either any of this, now adapters can use them in any way they want.
    Example ->
        1. RBAC can directly have them
        2. ReBAC store the relation configs in a separate table -> {relation:{friendsOnly:[read, write]}}
    """

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"


class InvalidPermissionAction(Exception):
    def __init__(self, msg: str = None, *args):
        message = (
            f"Invalid permission action: {msg}" if msg else "Invalid permission action"
        )
        super().__init__(message, *args)


class Permissions(ABC):
    _storage_session: StorageSession = None

    @asynccontextmanager
    async def set_storage_session(
        self, storage: StorageSession
    ) -> AsyncGenerator["Permissions", Any]:
        try:
            self._storage_session = storage
            yield self
        finally:
            self._storage_session = None

    def get_storage_session(self) -> StorageSession:
        if self._storage_session is None:
            raise ValueError("Storage is not set for this Permissions adapter.")
        return self._storage_session

    @abstractmethod
    async def create(self, role: Role) -> Role:
        pass

    @abstractmethod
    async def get(self):
        pass

    @abstractmethod
    async def remove(self, role: Role, permissions: list[str]) -> Role:
        pass

    @abstractmethod
    async def check(self, role: Role) -> bool:
        pass

    @abstractmethod
    async def update(self, role: Role) -> Role:
        pass

    @abstractmethod
    async def init_schema(self):
        pass

    @abstractmethod
    def parse(self, permissions: list[str]) -> list[str]:
        pass

    async def delete(self) -> Role:
        pass
