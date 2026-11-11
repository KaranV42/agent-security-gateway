from dataclasses import dataclass
from typing import Mapping, Protocol


class ToolExecutionError(Exception):
    """Base error for failures at the tool execution boundary."""


class ExecutorError(ToolExecutionError):
    """Raised when an executor fails during execution."""


class ExecutorInputError(ToolExecutionError, ValueError):
    """Raised when an execution request is invalid or outside configured scope."""


@dataclass(frozen=True)
class ToolExecutionRequest:
    tool_name: str
    resource_id: str
    arguments: Mapping[str, object]
    session_token: str
    principal_id: str
    user_token: str = ""

    def __init__(
        self,
        tool_name: str,
        resource_id: str,
        arguments: Mapping[str, object],
        session_token: str,
        principal_id: str,
        user_token: str = "",
        token: str | None = None,
    ) -> None:
        object.__setattr__(self, "tool_name", tool_name)
        object.__setattr__(self, "resource_id", resource_id)
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(self, "session_token", session_token)
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(
            self, "user_token", token if token is not None else user_token
        )

    @property
    def token(self) -> str:
        return self.user_token


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
