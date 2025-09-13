from abc import ABC, abstractmethod
from dataclasses import is_dataclass, fields
from typing import TypeVar, Type
from ..models import Model, Account, Role
from ..storage import Storage
from .payload import Payload

T = TypeVar("T", bound=Model)


class Provider(ABC):
    @abstractmethod
    def create_account(self, payload: Payload) -> Account:
        pass

    @staticmethod
    @abstractmethod
    def validate_paylod(paylod: Payload) -> bool:
        pass

    @staticmethod
    def get_model_from_dict(model: Type[T], data: dict[str]) -> T:
        model_keys = model.get_fields()
        filtered = {k: v for k, v in data.items() if k in model_keys}
        return model(**filtered)
