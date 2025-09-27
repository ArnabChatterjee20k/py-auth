from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class Payload(ABC):
    permissions: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @abstractmethod
    def validate(self) -> "Payload":
        """Implement provider-specific validation of the payload."""
        pass

    def to_dict(self, exclude: Optional[list[str]] = None) -> dict:
        exclude = exclude or []
        return {k: v for k, v in asdict(self).items() if k not in exclude}
