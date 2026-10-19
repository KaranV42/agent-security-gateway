import sqlite3


class ExecutorInputError(ValueError):
    pass


class ControlledToolExecutor:
    _TABLES = {
        "public_data": "public_data",
        "restricted_data": "restricted_data",
    }

    def __init__(self, connection: sqlite3.Connection):
        self.__connection = connection

    def execute_tool(
        self,
        tool_name: str,
        args: dict,
    ) -> list[dict]:
        if tool_name != "read_database":
            raise ExecutorInputError("Unsupported tool")

        if not isinstance(args, dict):
            raise ExecutorInputError("Arguments must be an object")

        if set(args) != {"table_name"}:
            raise ExecutorInputError("Invalid arguments")

        table_name = args["table_name"]

        if not isinstance(table_name, str):
            raise ExecutorInputError("Invalid table name")

        table = self._TABLES.get(table_name)

        if table is None:
            raise ExecutorInputError("Unsupported table")

        # The SQL identifier comes exclusively from the fixed allowlist.
        rows = self.__connection.execute(
            f'SELECT key, value FROM "{table}" ORDER BY key'
        ).fetchall()

        return [dict(row) for row in rows]