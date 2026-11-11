import sqlite3
from collections.abc import Mapping

from asg.broker import CredentialBroker
from asg.execution import (
    ExecutorInputError,
    ToolExecutionRequest,
    ToolExecutionResult,
)


class ControlledToolExecutor:
    _OPERATIONS = {
        ("read_data", "public_records"): ("public_records", "public_records"),
        ("read_data", "restricted_records"): ("restricted_records", "restricted_records"),
    }

    def __init__(self, connection: sqlite3.Connection, broker: CredentialBroker):
        self.__connection = connection
        self.__broker = broker

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        if (
            not isinstance(request.tool_name, str)
            or not isinstance(request.resource_id, str)
            or not isinstance(request.session_token, str)
            or not isinstance(request.arguments, Mapping)
        ):
            raise ExecutorInputError("Invalid arguments")

        if request.tool_name != "read_data":
            raise ExecutorInputError("Unsupported tool")
        binding = self._OPERATIONS.get((request.tool_name, request.resource_id))
        if binding is None:
            raise ExecutorInputError("Unsupported resource")
        table, operation_resource = binding

        if (
            set(request.arguments) != {"resource_id"}
            or request.arguments.get("resource_id") != operation_resource
        ):
            raise ExecutorInputError("Invalid arguments")

        if not self.__broker.validate_session(
            request.session_token, operation_resource
        ):
            raise ExecutorInputError("Invalid or expired session token")

        rows = self.__connection.execute(
            f'SELECT * FROM "{table}" ORDER BY 1'
        ).fetchall()
        return ToolExecutionResult(records=tuple(dict(row) for row in rows))

    def execute_tool(
        self, tool_name: str, args: dict, session_token: str
    ) -> list[dict]:
        if not isinstance(args, dict):
            raise ExecutorInputError("Invalid arguments")
        resource_id = args.get("resource_id")
        if not isinstance(resource_id, str):
            raise ExecutorInputError("Invalid arguments")

        result = self.execute(
            ToolExecutionRequest(
                tool_name=tool_name,
                resource_id=resource_id,
                arguments=args,
                session_token=session_token,
                principal_id="",
            )
        )
        return [dict(record) for record in result.records]