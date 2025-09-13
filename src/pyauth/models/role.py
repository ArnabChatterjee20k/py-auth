from dataclasses import dataclass
from . import Model


@dataclass
class Role(Model):
    uid: str
    account_uid: str
    session_uid: str | None = None
    # TODO: can be different for different permission adapters
    # but we can use a single unified layer
    # HACK:
    # a separate Role adapter to represent roles which will produce roles in string(like in utopia-php/database)
    # dont associate permission directly -> rather have a single Role class and that defines the stringified version and Permission Adapter just parses it
    # these ways we can separate the storage layer from the representation in the application layer
    roles: list[str] | None = None

    # TODO: parsers to get the eligilibility
