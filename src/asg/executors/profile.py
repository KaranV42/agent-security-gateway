from asg.execution import (
    ExecutorInputError,
    ToolExecutionRequest,
    ToolExecutionResult,
)


class ProfileToolExecutor:
    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        if (
            request.tool_name != "get_my_profile"
            or request.resource_id != "get_my_profile"
            or request.arguments
            or not request.principal_id
        ):
            raise ExecutorInputError("Invalid get_my_profile execution request")

        return ToolExecutionResult(
            records=(
                {
                    "display_name": "Test User",
                    "email": "test@example.com",
                    "uid": request.principal_id,
                },
            )
        )
