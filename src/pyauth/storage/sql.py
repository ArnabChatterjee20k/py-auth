from abc import abstractmethod
import json
from . import StorageSession
from ..models import Model, MissingDefault, CurrentTimeStamp


class SQLSession(StorageSession):
    async def init_schema(self, model: Model) -> str:
        table_name = model.__name__.lower()
        schema = model.get_schema()
        columns_sql = []
        indexes = []

        for column, info in schema.items():
            col_type = info["type"]
            default = info["default"]
            primary = info["primary_key"]
            index = info["index"]
            auto_increment = info["auto_increment"]
            unique = info["unique"]

            if index:
                indexes.append(index)

            constraints = ""
            if primary:
                constraints += "PRIMARY KEY"

            if auto_increment:
                constraints += " " + self.python_to_sqltype("auto_increment")

            if unique:
                constraints += " " + "UNIQUE"

            # SQL type
            sql_type = self.python_to_sqltype(col_type)

            # NOT NULL
            not_null = ""
            if isinstance(col_type, list) and "NoneType" not in col_type:
                not_null = "NOT NULL"
            elif isinstance(col_type, str) and col_type != "json":
                not_null = "NOT NULL"

            # DEFAULT
            default_sql = ""
            if isinstance(default, CurrentTimeStamp):
                default_sql = f"DEFAULT {self.get_default_datetime_sql()}"

            elif not isinstance(default, MissingDefault):
                if col_type == "json":
                    default_sql = f"DEFAULT {self.get_default_json_sql()}"

                elif isinstance(default, str):
                    default_sql = f"DEFAULT '{default}'"
                elif default is None:
                    default_sql = "DEFAULT NULL"
                else:
                    default_sql = f"DEFAULT {default}"

            col_def = " ".join(
                part
                for part in [column, sql_type, constraints, not_null, default_sql]
                if part
            )
            columns_sql.append(col_def)

        create_table_sql = (
            f"CREATE TABLE IF NOT EXISTS {table_name} (\n  "
            + ",\n  ".join(columns_sql)
            + "\n);"
        )
        await self.execute(create_table_sql)
        await self.init_index(table_name, indexes)
        return create_table_sql

    async def create(self, model: Model) -> Model:
        table_name = type(model).__name__.lower()
        schema = model.get_schema()
        columns = []
        values = []
        for key, value in model.get_values().items():
            columns.append(key)
            if "json" in schema.get(key).get("type") and value is not None:
                value = json.dumps(value)
            values.append(value)
            pass
        placeholders = self.get_placeholder(len(values))
        column_names = ",".join(columns)
        sql = f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders})"
        row_id = await self.execute(sql, values)
        model.id = row_id
        return model

    @abstractmethod
    def python_to_sqltype(self, py_type: str) -> str:
        pass

    @abstractmethod
    async def execute(self, query):
        pass

    @abstractmethod
    async def get_placeholder(self, count: int):
        pass

    def get_default_datetime_sql(self):
        return "CURRENT_TIMESTAMP"

    def get_default_json_sql(self):
        return "NULL"
