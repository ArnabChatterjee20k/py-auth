from .sql import SQLSession, StorageSession
from contextlib import asynccontextmanager
from .storage import Storage
from ..models import Model
import aiosqlite


class SQLiteSession(SQLSession):
    def __init__(self, conn_uri: str):
        self.conn_uri = conn_uri
        self.connection: aiosqlite.Connection = None

    def python_to_sqltype(self, py_type):
        # If union, pick the first non-NoneType
        if isinstance(py_type, list):
            main_type = next((t for t in py_type if t != "NoneType"), "TEXT")
            return self.python_to_sqltype(main_type)

        mapping = {
            "str": "TEXT",
            "bool": "INTEGER",
            "int": "INTEGER",
            "float": "REAL",
            "datetime": "TEXT",  # store as ISO string
            "json": "TEXT",
            "NoneType": "TEXT",
            "auto_increment": "AUTOINCREMENT",
        }
        return mapping.get(py_type, "TEXT")

    async def execute(self, *args):
        async with self.connection.execute(*args) as cursor:
            await self.connection.commit()
            return cursor.lastrowid

    async def init_index(self, table: str, indexes: list[str]):
        if not indexes:
            return

        for col in indexes:
            index_name = f"{table}_{col}_idx"

            # check if index exists
            stmt = """
            SELECT name 
            FROM sqlite_master 
            WHERE type='index' AND name=?;
            """
            cursor = await self.connection.execute(stmt, (index_name,))
            existing_index = await cursor.fetchone()
            await cursor.close()

            if existing_index:
                continue  # skip, already exists

            # create the index
            create_stmt = f"CREATE INDEX {index_name} ON {table}({col});"
            await self.connection.execute(create_stmt)

        await self.connection.commit()

    async def get(self, model: Model, **selections):
        # Model instance (Model()) is provided
        if isinstance(model, Model):
            table = model.__class__
        # Model class is given
        elif isinstance(model, type) and issubclass(model, Model):
            table: Model = model

        table_name = table.__name__.lower()
        where = " AND ".join([f"{attribute}=?" for attribute in selections])
        values = [value for value in selections.values()]
        select = f"SELECT * FROM {table_name} where {where} LIMIT 1"
        async with self.connection.execute(select, values) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None

        # using iteration and keys() to have a row order properly
        schema = [attribute for attribute in model.get_schema()]
        # removing id from the from the schema and the row as we can't init id
        result = zip(schema[1:], row[1:])
        result = table(**dict(result))
        result.id = row[0]
        return result

    async def update(self, model: Model):
        """Update a row based on model.id using get_schema() order"""
        if not isinstance(model, Model):
            raise ValueError("update expects a Model instance")
        if model.id is None:
            raise ValueError("Cannot update model without id")

        table_name = model.__class__.__name__.lower()
        schema = list(model.get_schema().keys())[1:]  # skip 'id'
        values = [getattr(model, attr) for attr in schema]

        set_clause = ", ".join([f"{attr}=?" for attr in schema])
        sql = f"UPDATE {table_name} SET {set_clause} WHERE id=?"

        async with self.connection.execute(sql, (*values, model.id)):
            await self.connection.commit()

        return model

    async def delete(self, model: Model):
        """Delete a row based on model.id"""
        if not isinstance(model, Model):
            raise ValueError("delete expects a Model instance")
        if model.id is None:
            raise ValueError("Cannot delete model without id")

        table_name = model.__class__.__name__.lower()
        sql = f"DELETE FROM {table_name} WHERE id=?"

        async with self.connection.execute(sql, (model.id,)):
            await self.connection.commit()

        return True

    async def rollback(self):
        return await self.connection.rollback()

    async def begin(self):
        await self.connection.execute("BEGIN")

    async def commit(self):
        await self.connection.commit()

    async def connect(self):
        self.connection = await aiosqlite.connect(self.conn_uri)
        return self

    async def close(self):
        await self.connection.close()

    def get_placeholder(self, count: int):
        return ",".join("?" for _ in range(count))


class SQLite(Storage):
    def __init__(self, connection_uri: str):
        self.conn_uri = connection_uri

    @asynccontextmanager
    async def session(self):
        session = SQLiteSession(self.conn_uri)
        try:
            await session.connect()
            yield session
        except Exception as e:
            raise e
        finally:
            await session.close()
