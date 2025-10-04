from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, ClassVar
from . import Model


@dataclass
class Session(Model):
    """Represents an authenticated session for an account (user/api key)."""

    schema_exclude: ClassVar[list[str]] = ["permissions"]

    sid: str = field(metadata={"index": True, "unique": True})
    account_uid: str = field(metadata={"index": True})
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None

    is_active: bool = False
    is_blocked: bool = False

    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None

    metadata: Dict = field(default_factory=dict)

    permissions: list = field(default=None, init=False)

    def is_expired(self) -> bool:
        if self.expires_at and datetime.now() > self.expires_at:
            return True
        return False

    def extend(self, seconds: int):
        if self.expires_at:
            self.expires_at += timedelta(seconds=seconds)
