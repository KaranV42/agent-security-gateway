import os
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient

from asg.api import create_app
from asg.audit import AuditLogger, AuditRecord
from asg.broker import CredentialBroker
from asg.execution import (
    ExecutorError,
    ExecutorInputError,
    ToolExecutionRequest,
    ToolExecutorRouter,
)
from asg.executors.http import HttpExecutor
from asg.gateway import ASGGateway
from asg.models import Effect
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.registry import ToolRegistry, ToolSchema

TEST_SECRET = "test-service-secret"
BACKEND_URL = "https://api.internal.example.com/v1/users/me"


class _DummyAuditLogger(AuditLogger):
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def log(self, record: AuditRecord) -> None:
        self.records.append(record)


def _make_request(
    *,
    tool_name: str = "get_my_profile",
    resource_id: str = "get_my_profile",
    arguments: dict | None = None,
    session_token: str = "valid-session",
    principal_id: str = "user-123",
    user_token: str = "firebase-jwt-token-abc",
) -> ToolExecutionRequest:
    return ToolExecutionRequest(
        tool_name=tool_name,
        resource_id=resource_id,
        arguments=arguments if arguments is not None else {},
        session_token=session_token,
        principal_id=principal_id,
        user_token=user_token,
    )


def test_http_executor_successful_response():
    recorded_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request)
        return httpx.Response(
            200,
            json={"display_name": "Test User", "email": "test@example.com"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request(user_token="test-jwt-token-xyz")
    result = executor.execute(request)

    assert len(recorded_requests) == 1
    outbound = recorded_requests[0]
    assert outbound.method == "GET"
    assert str(outbound.url) == BACKEND_URL
    assert outbound.headers["authorization"] == "Bearer test-jwt-token-xyz"
    assert outbound.headers["accept"] == "application/json"

    assert len(result.records) == 1
    assert result.records[0] == {
        "display_name": "Test User",
        "email": "test@example.com",
    }


def test_http_executor_timeout_raises_executor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Connection timed out", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request()
    with pytest.raises(ExecutorError, match="timed out"):
        executor.execute(request)


def test_http_executor_401_from_backend_raises_executor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Unauthorized: Token expired or revoked")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request()
    with pytest.raises(ExecutorError, match="Backend returned HTTP 401"):
        executor.execute(request)


def test_http_executor_500_from_backend_raises_executor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request()
    with pytest.raises(ExecutorError, match="Backend returned HTTP 500"):
        executor.execute(request)


def test_http_executor_invalid_json_raises_executor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>502 Bad Gateway</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request()
    with pytest.raises(ExecutorError, match="invalid JSON"):
        executor.execute(request)


def test_http_executor_non_dict_json_raises_executor_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["unexpected", "array"])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request()
    with pytest.raises(ExecutorError, match="must be a JSON object"):
        executor.execute(request)


def test_http_executor_missing_token_raises_executor_error():
    executor = HttpExecutor()
    request = _make_request(user_token="")
    with pytest.raises(ExecutorError, match="Missing Firebase ID token"):
        executor.execute(request)


def test_http_executor_rejects_user_arguments():
    executor = HttpExecutor()
    request = _make_request(arguments={"url": "http://malicious-target.local"})
    with pytest.raises(ExecutorInputError, match="Invalid get_my_profile"):
        executor.execute(request)


def test_http_executor_rejects_wrong_tool_name():
    executor = HttpExecutor()
    request = _make_request(tool_name="unregistered_tool")
    with pytest.raises(ExecutorInputError, match="Invalid get_my_profile"):
        executor.execute(request)


def test_http_executor_rejects_missing_principal():
    executor = HttpExecutor()
    request = _make_request(principal_id="")
    with pytest.raises(ExecutorInputError, match="Invalid get_my_profile"):
        executor.execute(request)


def test_http_executor_loads_backend_url_from_env(monkeypatch):
    custom_url = "https://custom-auth.internal.example.com/v1/users/me"
    monkeypatch.setenv("BACKEND_URL", custom_url)
    executor = HttpExecutor()
    assert executor.backend_url == custom_url


def test_http_executor_appends_path_if_base_url_provided(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "https://api.internal.example.com")
    executor = HttpExecutor()
    assert executor.backend_url == "https://api.internal.example.com/v1/users/me"


def test_http_executor_rejects_empty_or_invalid_backend_url():
    with pytest.raises(ValueError, match="empty"):
        HttpExecutor(backend_url="   ")

    with pytest.raises(ValueError, match="invalid scheme"):
        HttpExecutor(backend_url="ftp://api.internal.example.com")


def test_http_executor_handles_token_with_existing_bearer_prefix():
    recorded_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request)
        return httpx.Response(200, json={"display_name": "Prefixed", "email": "p@e.com"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    request = _make_request(user_token="Bearer already-prefixed-jwt")
    executor.execute(request)

    assert recorded_requests[0].headers["authorization"] == "Bearer already-prefixed-jwt"


def test_http_executor_with_unittest_mock_patch():
    """Verify unittest.mock can intercept outbound requests directly."""
    executor = HttpExecutor()
    mock_response = httpx.Response(
        200,
        json={"display_name": "Mocked User", "email": "mocked@example.com"},
        request=httpx.Request("GET", BACKEND_URL),
    )

    with patch.object(httpx.Client, "get", return_value=mock_response) as mock_get:
        request = _make_request(user_token="my-jwt")
        result = executor.execute(request)

        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        assert args[0] == BACKEND_URL
        assert kwargs["headers"]["Authorization"] == "Bearer my-jwt"
        assert result.records[0] == {
            "display_name": "Mocked User",
            "email": "mocked@example.com",
        }


def test_http_executor_via_gateway():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"display_name": "Gateway User", "email": "gw@example.com"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = HttpExecutor(client=client)

    registry = ToolRegistry()
    registry.register(
        "get_my_profile",
        ToolSchema(
            description="Returns profile",
            required_args=frozenset(),
        ),
    )
    policy = DeclarativePolicyEngine(
        [
            PolicyRule(
                principal_id=None,
                action="read",
                resource_id="get_my_profile",
                effect=Effect.ALLOW,
                reason="Allow profile read",
            )
        ]
    )
    logger = _DummyAuditLogger()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)

    gateway = ASGGateway(
        executor=executor,
        registry=registry,
        principal_id="user-456",
        policy=policy,
        audit_logger=logger,
        broker=broker,
        asg_service_secret=TEST_SECRET,
        user_token="firebase-token-789",
    )

    records = gateway.execute_tool("get_my_profile", {})
    assert records == [{"display_name": "Gateway User", "email": "gw@example.com"}]
    assert any(r.phase.value == "EXECUTION" and r.outcome == "SUCCESS" for r in logger.records)


def test_http_executor_via_api_client(firebase_token):
    recorded_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded_requests.append(request)
        return httpx.Response(
            200,
            json={"display_name": "API User", "email": "api@example.com"},
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = ToolExecutorRouter({
        "get_my_profile": HttpExecutor(client=http_client),
    })

    registry = ToolRegistry()
    registry.register(
        "get_my_profile",
        ToolSchema(
            description="Returns profile",
            required_args=frozenset(),
        ),
    )
    policy = DeclarativePolicyEngine([
        PolicyRule(
            principal_id=None,
            action="read",
            resource_id="get_my_profile",
            effect=Effect.ALLOW,
            reason="Allow profile",
        )
    ])
    logger = _DummyAuditLogger()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)

    app = create_app(executor, registry, policy, logger, broker, TEST_SECRET)
    test_client = TestClient(app)

    token = firebase_token(subject="user-e2e-777")
    response = test_client.post(
        "/api/v1/execute",
        json={"tool_name": "get_my_profile", "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.json()
    assert response.json()["status"] == "SUCCESS"
    assert response.json()["result"] == [{
        "display_name": "API User",
        "email": "api@example.com",
    }]
    assert len(recorded_requests) == 1
    assert recorded_requests[0].headers["authorization"] == f"Bearer {token}"


def test_http_executor_via_api_client_backend_500_maps_to_500(firebase_token):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Backend Error")

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    executor = ToolExecutorRouter({
        "get_my_profile": HttpExecutor(client=http_client),
    })

    registry = ToolRegistry()
    registry.register(
        "get_my_profile",
        ToolSchema(description="Returns profile", required_args=frozenset()),
    )
    policy = DeclarativePolicyEngine([
        PolicyRule(principal_id=None, action="read", resource_id="get_my_profile", effect=Effect.ALLOW, reason="Allow")
    ])
    logger = _DummyAuditLogger()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)

    app = create_app(executor, registry, policy, logger, broker, TEST_SECRET)
    test_client = TestClient(app)

    token = firebase_token(subject="user-e2e-777")
    response = test_client.post(
        "/api/v1/execute",
        json={"tool_name": "get_my_profile", "arguments": {}},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 500
    assert response.json()["detail"]["status"] == "EXECUTION_FAILURE"
    assert "Backend returned HTTP 500" in response.json()["detail"]["error"]

