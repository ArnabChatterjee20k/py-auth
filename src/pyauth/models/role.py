from dataclasses import dataclass, field
from . import Model
from typing import Optional, List


@dataclass
class Role(Model):
    account_uid: str
    session_uid: Optional[str] = None
    # TODO: can be different for different permission adapters
    # but we can use a single unified layer
    # HACK:
    # a separate Role adapter to represent roles which will produce roles in string(like in utopia-php/database)
    # dont associate permission directly -> rather have a single Role class and that defines the stringified version and Permission Adapter just parses it
    # these ways we can separate the storage layer from the representation in the application layer
    # permissions: A list of permissions, which can be either:
    # 1. Flat strings representing RBAC permissions (e.g., "read", "write").
    # 2. JSON-encoded strings for more complex permission payloads (e.g., ABAC conditions or ReBAC relationships).

    permissions: List[str] = field(default_factory=list)
