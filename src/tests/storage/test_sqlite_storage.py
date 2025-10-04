import pytest
from src.pyauth.storage.sqlite import SQLite
from src.pyauth.models import Account
from .test_storage_base import BaseStorageTest


class TestSQLiteStorage(BaseStorageTest):
    """SQLite storage implementation tests"""

    async def get_storage(self):
        """Get SQLite storage instance for testing"""
        import tempfile
        import os

        # Create a temporary database file
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test.db")
        return SQLite(db_path)

    async def cleanup_storage(self, storage):
        """Clean up SQLite storage after tests"""
        # SQLite cleanup is handled by tempfile cleanup
        pass

    @pytest.fixture
    def tmp_path(self):
        """Provide tmp_path for backward compatibility with existing tests"""
        import tempfile

        return tempfile.mkdtemp()


# Legacy function-based tests for backward compatibility
# These tests are kept for backward compatibility but new tests should use TestSQLiteStorage class
@pytest.mark.asyncio
async def test_sqlite_crud(tmp_path):
    """Legacy test - use TestSQLiteStorage class instead"""
    db_path = str(tmp_path / "t.db")
    storage = SQLite(db_path)

    async with storage.session() as session:
        await session.init_schema(Account)

        # create
        created = await session.create(Account(uid="x", permissions=["read"]))
        assert created.uid == "x"

        # get
        got = await session.get(Account, filters={"uid": "x"})
        assert got and got.uid == "x"

        # list
        lst = await session.list(Account, limit=10)
        assert len(lst) >= 1

        # update
        updated = await session.update(
            Account, {"uid": "x"}, {"permissions": ["read", "update"]}
        )
        assert "update" in updated.permissions

        # delete
        ok = await session.delete(Account, {"uid": "x"})
        assert ok is True
        assert await session.get(Account, filters={"uid": "x"}) is None


@pytest.mark.asyncio
async def test_list_with_filters_and_contains(tmp_path):
    """Legacy test - use TestSQLiteStorage class instead"""
    db_path = str(tmp_path / "filters.db")
    storage = SQLite(db_path)

    async with storage.session() as session:
        await session.init_schema(Account)

        await session.create(Account(uid="u1", permissions=["read"]))
        await session.create(Account(uid="u2", permissions=["read", "write"]))
        await session.create(Account(uid="u3", permissions=["delete"]))

        # filter by uid
        res = await session.list(Account, filters={"uid": "u2"})
        assert len(res) == 1 and res[0].uid == "u2"

        # contains on list field
        res = await session.list(Account, contains={"permissions": "write"})
        assert any(a.uid == "u2" for a in res)


@pytest.mark.asyncio
async def test_pagination_after_id(tmp_path):
    """Legacy test - use TestSQLiteStorage class instead"""
    db_path = str(tmp_path / "pagination.db")
    storage = SQLite(db_path)

    async with storage.session() as session:
        await session.init_schema(Account)

        created = []
        for i in range(5):
            created.append(await session.create(Account(uid=f"p{i}", permissions=[])))

        # first page
        page1 = await session.list(Account, limit=2)
        assert len(page1) == 2
        # second page using after_id
        last_id = page1[-1].id
        page2 = await session.list(Account, limit=2, after_id=last_id)
        assert len(page2) == 2
        # third page
        last_id2 = page2[-1].id
        page3 = await session.list(Account, limit=2, after_id=last_id2)
        assert len(page3) >= 1


@pytest.mark.asyncio
async def test_init_index_and_noop(tmp_path):
    """Legacy test - use TestSQLiteStorage class instead"""
    db_path = str(tmp_path / "index.db")
    storage = SQLite(db_path)

    async with storage.session() as session:
        await session.init_schema(Account)
        # create index, then create again to ensure it is a noop on existing
        await session.init_index("account", ["uid"])  # should not raise
        await session.init_index("account", ["uid"])  # idempotent


@pytest.mark.asyncio
async def test_update_with_no_valid_fields_returns_none(tmp_path):
    """Legacy test - use TestSQLiteStorage class instead"""
    db_path = str(tmp_path / "update_none.db")
    storage = SQLite(db_path)

    async with storage.session() as session:
        await session.init_schema(Account)
        await session.create(Account(uid="z", permissions=["read"]))

        result = await session.update(Account, {"uid": "z"}, {"not_a_field": True})
        assert result is None


@pytest.mark.asyncio
async def test_get_without_filters_raises(tmp_path):
    """Legacy test - use TestSQLiteStorage class instead"""
    db_path = str(tmp_path / "get_err.db")
    storage = SQLite(db_path)

    async with storage.session() as session:
        await session.init_schema(Account)
        with pytest.raises(ValueError):
            await session.get(Account)
