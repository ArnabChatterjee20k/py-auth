from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field


@dataclass
class Payload(ABC):
    permissions: list = field(default_factory=list)

    @abstractmethod
    def validate(self) -> "Payload":
        """Implement provider-specific validation of the payload."""
        pass

    def to_dict(self) -> dict:
        return asdict(self)
