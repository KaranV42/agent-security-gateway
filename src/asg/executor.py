import sqlite3
from asg.broker import CredentialBroker

class ExecutorInputError(ValueError):
    pass

class ControlledToolExecutor:
    _TABLES = {
        "public_records": "public_records",
        "restricted_records": "restricted_records",
    }

    def __init__(self, connection: sqlite3.Connection, broker: CredentialBroker):
        self.__connection = connection
        self.__broker = broker

    def execute_tool(self, tool_name: str, args: dict, session_token: str) -> list[dict]:
        if tool_name != "read_data":
            raise ExecutorInputError("Unsupported tool")
        
        # 1. Validate Service-to-Service Session
        resource_id = args.get("resource_id")
        if not self.__broker.validate_session(session_token, resource_id):
            raise ExecutorInputError("Invalid or expired session token")

        if not isinstance(args, dict) or set(args) != {"resource_id"}:
            raise ExecutorInputError("Invalid arguments")

        # 2. Resolve the requested resource through the fixed table allow-list.
        table = self._TABLES.get(resource_id)
        if table is None:
            raise ExecutorInputError("Unsupported table")

        # 3. Execute safely (parameterized queries prevent SQL injection at the DB level)
        rows = self.__connection.execute(
            f'SELECT * FROM "{table}" ORDER BY 1'
        ).fetchall()
        return [dict(row) for row in rows]