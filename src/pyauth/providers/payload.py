from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field


@dataclass
class Payload(ABC):
    permissions: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @abstractmethod
    def validate(self) -> "Payload":
        """Implement provider-specific validation of the payload."""
        pass

    def to_dict(self) -> dict:
        return asdict(self)
