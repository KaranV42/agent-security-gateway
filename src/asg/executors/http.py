import os
import json
from typing import Mapping
from urllib.parse import quote

import httpx

from asg.execution import (
    ExecutorError,
    ExecutorInputError,
    ToolExecutionRequest,
    ToolExecutionResult,
)

DEFAULT_BACKEND_URL = "https://api.internal.example.com/v1/users/me"
DEFAULT_TIMEOUT_SECONDS = 5.0
PROFILE_ENDPOINT = "/v1/users/me"
CONVERSATION_ENDPOINT = "/v1/conversations/{conversation_id}"
ENDPOINTS = {
    "get_my_profile": PROFILE_ENDPOINT,
    "get_conversation": CONVERSATION_ENDPOINT,
}


class HttpExecutor:
    """Constrained HTTP adapter for internal backend services."""

    def __init__(
        self,
        backend_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        raw_url = backend_url or os.environ.get("BACKEND_URL") or DEFAULT_BACKEND_URL
        self._backend_base_url = self._resolve_base_url(raw_url)
        self._timeout = timeout
        self._client = client

    @staticmethod
    def _resolve_base_url(raw_url: str) -> str:
        url = raw_url.strip()
        if not url:
            raise ValueError("BACKEND_URL must not be empty")
        if not (url.startswith("https://") or url.startswith("http://")):
            raise ValueError(f"BACKEND_URL has an invalid scheme: {url}")
        if url.endswith(PROFILE_ENDPOINT):
            return url[: -len(PROFILE_ENDPOINT)].rstrip("/")
        return url.rstrip("/")

    @property
    def backend_url(self) -> str:
        return f"{self._backend_base_url}{PROFILE_ENDPOINT}"

    def _endpoint_url(self, tool_name: str, arguments: Mapping[str, object]) -> str:
        endpoint = ENDPOINTS.get(tool_name)
        if endpoint is None:
            raise ExecutorInputError(f"Unsupported HTTP tool '{tool_name}'")
        if tool_name == "get_conversation":
            conversation_id = arguments.get("conversation_id")
            if (
                not isinstance(conversation_id, str)
                or not conversation_id
                or conversation_id in {".", ".."}
            ):
                raise ExecutorInputError(
                    "get_conversation requires a non-empty conversation_id"
                )
            endpoint = endpoint.format(
                conversation_id=quote(conversation_id, safe="")
            )
        return f"{self._backend_base_url}{endpoint}"

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        if request.tool_name == "get_my_profile":
            if (
                request.resource_id != "get_my_profile"
                or request.arguments
                or not request.principal_id
            ):
                raise ExecutorInputError(
                    "Invalid get_my_profile execution request"
                )
        elif request.tool_name == "get_conversation":
            if (
                request.resource_id != "conversation"
                or not request.principal_id
                or set(request.arguments) != {"conversation_id"}
                or not isinstance(request.arguments.get("conversation_id"), str)
                or not request.arguments["conversation_id"]
                or request.arguments["conversation_id"] in {".", ".."}
            ):
                raise ExecutorInputError(
                    "Invalid get_conversation execution request"
                )
        else:
            raise ExecutorInputError("Invalid get_my_profile execution request")

        endpoint_url = self._endpoint_url(request.tool_name, request.arguments)

        token = request.user_token or getattr(request, "token", "")
        if not token:
            raise ExecutorError("Missing Firebase ID token for backend request")

        token = token.removeprefix("Bearer ").strip()

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        try:
            if self._client is not None:
                response = self._client.get(
                    endpoint_url,
                    headers=headers,
                    timeout=self._timeout,
                )
            else:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.get(
                        endpoint_url,
                        headers=headers,
                    )
        except httpx.TimeoutException as exc:
            raise ExecutorError(
                f"Backend request timed out after {self._timeout}s: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise ExecutorError(f"Backend request failed: {exc}") from exc

        if response.status_code != 200:
            raise ExecutorError(
                f"Backend returned HTTP {response.status_code}: {response.text}"
            )

        try:
            data = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ExecutorError(
                f"Backend returned invalid JSON: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ExecutorError(
                f"Backend response must be a JSON object, got {type(data).__name__}"
            )

        return ToolExecutionResult(records=(dict(data),))
