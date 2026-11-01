import sqlite3
from asg.broker import CredentialBroker

class ExecutorInputError(ValueError):
    pass

class ControlledToolExecutor:
    _TABLES = {
        "read_market_data": "market_data",
        "read_client_pii": "client_pii",
    }

    def __init__(self, connection: sqlite3.Connection, broker: CredentialBroker):
        self.__connection = connection
        self.__broker = broker

    def execute_tool(self, tool_name: str, args: dict, session_token: str) -> list[dict]:
        if tool_name not in self._TABLES:
            raise ExecutorInputError("Unsupported tool")
        
        # 1. Validate Service-to-Service Session
        table_name = args.get("table_name") # <-- Fixed typo here
        if not self.__broker.validate_session(session_token, table_name):
            raise ExecutorInputError("Invalid or expired session token")

        if not isinstance(args, dict) or set(args) != {"table_name"}:
            raise ExecutorInputError("Invalid arguments")

        table = self._TABLES.get(tool_name)
        if table is None:
            raise ExecutorInputError("Unsupported table")

        # 2. Execute safely
        rows = self.__connection.execute(
            f'SELECT * FROM "{table}" ORDER BY 1'
        ).fetchall()
        return [dict(row) for row in rows]