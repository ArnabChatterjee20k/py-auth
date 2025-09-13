from ..payload import Payload
from dataclasses import dataclass, field


@dataclass
class PasswordPayload(Payload):
    identifier: str | None = None
    password: str | None = None
    metadata: dict = field(default_factory=dict)

    def validate(self) -> "PasswordPayload":
        if not self.identifier or not self.password:
            raise ValueError("Password and identifier required")
