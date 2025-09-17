from abc import ABC, abstractmethod
from typing import TypeVar, Type, Coroutine, Any
from ..models import Model

T = TypeVar("T", bound=Model)


class Storage(ABC):
    def __init__(self):
        super().__init__()

    # here we dont have mutable sharable resource so using the Storage only as the Session only instead of a separate Session
    # for starting a transactions
    async def __aenter__(self) -> "Storage":
        await self.begin()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type:
            await self.rollback()
        else:
            await self.commit()
        await self.close()

    @abstractmethod
    async def create(self, model: T) -> T:
        pass

    @abstractmethod
    async def update(self):
        pass

    @abstractmethod
    async def delete(self):
        pass

    @abstractmethod
    async def get(self):
        pass

    @abstractmethod
    async def begin(self):
        pass

    @abstractmethod
    async def commit(self):
        pass

    @abstractmethod
    async def rollback(self):
        pass

    @abstractmethod
    async def close(self):
        pass

    @abstractmethod
    async def init_schema(self, schema: Model):
        pass
