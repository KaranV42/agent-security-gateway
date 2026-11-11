from dataclasses import dataclass
from typing import Mapping, Protocol


class ToolExecutionError(Exception):
    """Base error for failures at the tool execution boundary."""


class ExecutorInputError(ToolExecutionError, ValueError):
    """Raised when an execution request is invalid or outside configured scope."""


@dataclass(frozen=True)
class ToolExecutionRequest:
    tool_name: str
    resource_id: str
    arguments: Mapping[str, object]
    session_token: str
    principal_id: str


@dataclass(frozen=True)
class ToolExecutionResult:
    records: tuple[Mapping[str, object], ...]


class ToolExecutor(Protocol):
    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        """Execute one server-configured tool operation."""


class ToolExecutorRouter:
    def __init__(self, executors: Mapping[str, ToolExecutor]) -> None:
        self._executors = dict(executors)

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        executor = self._executors.get(request.tool_name)
        if executor is None:
            raise ExecutorInputError(
                f"No executor configured for tool '{request.tool_name}'"
            )
        return executor.execute(request)
