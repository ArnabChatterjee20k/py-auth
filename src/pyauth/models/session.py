from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict


@dataclass
class Session:
    """Represents an authenticated session for an account (user/api key)."""

    sid: str
    account_uid: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None

    is_active: bool = False
    is_blocked: bool = False

    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    metadata: Dict = field(default_factory=dict)

    def is_expired(self) -> bool:
        if self.expires_at and datetime.now() > self.expires_at:
            return True
        return False

    def extend(self, seconds: int):
        if self.expires_at:
            self.expires_at += timedelta(seconds=seconds)
