from abc import ABC, abstractmethod
from ..storage import Storage


class Permissions(ABC):
    def __init__(self):
        self._storage = None

    def init_storage(self, storage: Storage):
        self._storage = storage
