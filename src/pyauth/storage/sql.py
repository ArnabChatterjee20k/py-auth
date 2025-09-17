from abc import ABC, abstractmethod
from . import Storage
from ..models import Model, MissingDefault

class SQL(ABC,Storage):
    def __init__(self):
        super().__init__()

    def init_schema(self, model: Model) -> str:
        table_name = model.__name__.lower()
        schema = model.get_schema()
        columns_sql = []

        for column, info in schema.items():
            col_type = info['type']
            default = info['default']

            # SQL type
            sql_type = self.python_to_sqltype(col_type)

            # NOT NULL
            not_null = ''
            if isinstance(col_type, list) and 'NoneType' not in col_type:
                not_null = 'NOT NULL'
            elif isinstance(col_type, str) and col_type != 'json':
                not_null = 'NOT NULL'

            # DEFAULT
            default_sql = ''
            if not isinstance(default, MissingDefault):
                if isinstance(default, str):
                    default_sql = f"DEFAULT '{default}'"
                elif default is None:
                    default_sql = "DEFAULT NULL"
                else:
                    default_sql = f"DEFAULT {default}"

            col_def = ' '.join(part for part in [column, sql_type, not_null, default_sql] if part)
            columns_sql.append(col_def)

        create_table_sql = f"CREATE TABLE {table_name} (\n  " + ",\n  ".join(columns_sql) + "\n);"
        return create_table_sql

    @abstractmethod
    def python_to_sqltype(self, py_type: str) -> str:
        pass

    @abstractmethod
    def execute(self, query):
        pass
