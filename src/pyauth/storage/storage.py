from abc import ABC, abstractmethod
from typing import TypeVar
from contextlib import asynccontextmanager, AbstractAsyncContextManager
from typing import AsyncGenerator, Any, Union, Type, Optional
from ..models import Model

T = TypeVar("T", bound=Model)


class StorageSession(ABC):
    def __init__(self, conn):
        self._conn = conn

    @abstractmethod
    async def create(self, model: T) -> T: ...
    @abstractmethod
    async def update(
        self, model: Union[T, Type[T]], filters: dict, updates: dict
    ) -> T: ...
    @abstractmethod
    async def delete(self): ...
    @abstractmethod
    async def get(
        self,
        model: Union[T, Type[T]],
        for_update: bool = False,
        filters: Optional[dict] = None,
        contains: Optional[dict] = None,
    ) -> T: ...

    @abstractmethod
    async def begin(self): ...
    @abstractmethod
    async def commit(self): ...
    @abstractmethod
    async def rollback(self): ...
    @abstractmethod
    async def connect(self) -> "StorageSession": ...
    @abstractmethod
    async def close(self): ...
    @abstractmethod
    async def init_schema(self, schema: Model): ...
    @abstractmethod
    async def init_index(self, table: str, indexes: list[str]): ...


# to create independent sessions and connection objects and since its returning StorageSession which implements aenter and aexit , we can use `async with storage.session()`
class Storage(ABC):
    def __init__(self, conn_uri: str, debug=False):
        self.conn_uri = conn_uri
        self._debug = debug

    # not using here asyncontextmanager and async to type hint properly
    # AbstractAsyncContextManager -> async and asynccontextmanager
    @abstractmethod
    def session(self) -> AbstractAsyncContextManager[StorageSession]:
        pass

    @asynccontextmanager
    async def begin(self) -> AsyncGenerator[StorageSession, Any]:
        # session = await self.session()
        # session is async context manager
        async with self.session() as session:
            try:
                await session.begin()
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                raise e
            finally:
                await session.close()

    def get_model_class(model: object) -> Type[Model]:
        # Model instance (Model()) is provided
        if isinstance(model, Model):
            return model.__class__
        # Model class is given
        elif isinstance(model, type) and issubclass(model, Model):
            return model

        raise TypeError("Invalid model type")
