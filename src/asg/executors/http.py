import os
from typing import Mapping
import httpx

from asg.execution import (
    ExecutorError,
    ExecutorInputError,
    ToolExecutionRequest,
    ToolExecutionResult,
)

DEFAULT_BACKEND_URL = "https://api.internal.example.com/v1/users/me"
DEFAULT_TIMEOUT_SECONDS = 5.0


class HttpExecutor:
    """Constrained HTTP adapter for internal backend services."""

    def __init__(
        self,
        backend_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        raw_url = backend_url or os.environ.get("BACKEND_URL") or DEFAULT_BACKEND_URL
        self._backend_url = self._resolve_url(raw_url)
        self._timeout = timeout
        self._client = client

    @staticmethod
    def _resolve_url(raw_url: str) -> str:
        url = raw_url.strip()
        if not url:
            raise ValueError("BACKEND_URL must not be empty")
        if not (url.startswith("https://") or url.startswith("http://")):
            raise ValueError(f"BACKEND_URL has an invalid scheme: {url}")
        if url.endswith("/v1/users/me"):
            return url
        return f"{url.rstrip('/')}/v1/users/me"

    @property
    def backend_url(self) -> str:
        return self._backend_url

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        if (
            request.tool_name != "get_my_profile"
            or request.resource_id != "get_my_profile"
            or request.arguments
            or not request.principal_id
        ):
            raise ExecutorInputError("Invalid get_my_profile execution request")

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
                    self._backend_url,
                    headers=headers,
                    timeout=self._timeout,
                )
            else:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.get(
                        self._backend_url,
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
        except Exception as exc:
            raise ExecutorError(
                f"Backend returned invalid JSON: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ExecutorError(
                f"Backend response must be a JSON object, got {type(data).__name__}"
            )

        return ToolExecutionResult(records=(dict(data),))

