from dataclasses import dataclass, field
from . import Model
from datetime import datetime
from typing import Dict


@dataclass
class Account(Model):
    """Representing authenticable entities. eg., user, apikeys, oauth,etc"""

    uid: str = field(metadata={"index": True, "unique": True})
    permissions: list[str] = field(default_factory=list)

    is_active: bool = True
    is_blocked: bool = False

    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_active_at: datetime | None = None

    metadata: Dict = field(default_factory=dict)
