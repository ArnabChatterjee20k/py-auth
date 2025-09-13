from abc import ABC, abstractmethod
from ..storage import Storage


class PermissionSession(ABC):
    def __init__(self):
        self._storage = None

    """Actuall permession session which requires the storage adapter as well to work with"""

    def init_storage(self, storage: Storage) -> "PermissionSession":
        self._storage = storage
        return self


class Permissions(ABC):
    @abstractmethod
    def get_adapter(self) -> PermissionSession:
        pass
