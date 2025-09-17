from .sql import SQL
class SQLite(SQL):
    def __init__(self):
        super().__init__()
    
    def python_to_sqltype(self, py_type):
        # If union, pick the first non-NoneType
        if isinstance(py_type, list):
            main_type = next((t for t in py_type if t != 'NoneType'), 'TEXT')
            return self.python_to_sqltype(main_type)

        mapping = {
            'str': 'TEXT',
            'bool': 'INTEGER',
            'int': 'INTEGER',
            'float': 'REAL',
            'datetime': 'TEXT', # store as ISO string
            'json': 'TEXT',
            'NoneType': 'TEXT',
        }
        return mapping.get(py_type, 'TEXT')
