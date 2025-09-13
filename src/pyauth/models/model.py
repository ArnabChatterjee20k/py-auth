from abc import ABC
from dataclasses import dataclass, asdict, fields
from typing import ClassVar


@dataclass
class Model(ABC):
    exclude: ClassVar[list[str]] = []

    def to_dict(self) -> dict:
        data = asdict(self)
        return {k: v for k, v in data.items() if k not in self.exclude}

    def get_fields(self):
        return {f.name for f in fields(self)}
