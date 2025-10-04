import asyncio
import os
import pytest
import pytest_asyncio
from datetime import datetime

from src.pyauth.storage.sqlite import SQLite
from src.pyauth.providers.password.password import Password
from src.pyauth.providers.password.payload import PasswordPayload
from src.pyauth.permissions.RBAC import RBAC
from src.pyauth.pyauth import Pyauth
from src.pyauth.models import Account, Session, Role


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture()
def sqlite_db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture()
def sqlite_storage(sqlite_db_path):
    return SQLite(sqlite_db_path)


@pytest_asyncio.fixture()
async def initialized_storage(sqlite_storage):
    # Initialize schema for core models used by most tests
    async with sqlite_storage.session() as session:
        await session.init_schema(Account)
        await session.init_schema(Session)
        await session.init_schema(Role)
    return sqlite_storage


@pytest.fixture()
def password_provider():
    return Password()


@pytest.fixture()
def rbac_permissions():
    return RBAC()


@pytest.fixture()
def token_secret():
    return "test-secret-key"


@pytest.fixture()
def pyauth(initialized_storage, password_provider, rbac_permissions, token_secret):
    return Pyauth(
        provider=password_provider,
        storage=initialized_storage,
        permissions=rbac_permissions,
        token_secret=token_secret,
    )


@pytest.fixture()
def password_payload():
    return PasswordPayload(identifier="user_1", password="strong_password")
