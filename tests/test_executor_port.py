import pytest

from asg.audit import AuditLogger, AuditRecord
from asg.broker import CredentialBroker
from asg.database import create_mock_database
from asg.execution import (
    ExecutorInputError,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutor,
)
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway
from asg.models import Effect
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.registry import ToolRegistry, ToolSchema

TEST_SECRET = "test-secret"


class _DummyAuditLogger(AuditLogger):
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def log(self, record: AuditRecord) -> None:
        self.records.append(record)


class _InMemoryToolExecutor:
    def __init__(self, broker: CredentialBroker):
        self._broker = broker
        self.requests: list[ToolExecutionRequest] = []
        self._operations = {
            ("read_data", "public_records"): (
                "public_records",
                ({"record_id": "memory-001"},),
            )
        }

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        operation = self._operations.get((request.tool_name, request.resource_id))
        if operation is None:
            raise ExecutorInputError("Unsupported operation")

        configured_resource, records = operation
        if (
            set(request.arguments) != {"resource_id"}
            or request.arguments["resource_id"] != configured_resource
        ):
            raise ExecutorInputError("Invalid arguments")
        if not self._broker.validate_session(
            request.session_token, configured_resource
        ):
            raise ExecutorInputError("Invalid or expired session token")

        self.requests.append(request)
        return ToolExecutionResult(records=records)


def _gateway(executor: ToolExecutor, broker: CredentialBroker) -> ASGGateway:
    registry = ToolRegistry()
    registry.register(
        "read_data",
        ToolSchema(
            required_args=frozenset({"resource_id"}),
            resource_arg="resource_id",
            allowed_resources=frozenset({"public_records"}),
        ),
    )
    policy = DeclarativePolicyEngine(
        [
            PolicyRule(
                principal_id="admin",
                action="read",
                resource_id="public_records",
                effect=Effect.ALLOW,
                reason="Allow",
            )
        ]
    )
    return ASGGateway(
        executor,
        registry,
        "admin",
        policy,
        _DummyAuditLogger(),
        broker,
        TEST_SECRET,
    )


def test_gateway_executes_through_backend_neutral_port():
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)
    executor = _InMemoryToolExecutor(broker)
    gateway = _gateway(executor, broker)

    records = gateway.execute_tool(
        "read_data", {"resource_id": "public_records"}
    )

    assert records == [{"record_id": "memory-001"}]
    assert len(executor.requests) == 1
    assert executor.requests[0].resource_id == "public_records"
    assert executor.requests[0].arguments == {"resource_id": "public_records"}
    assert broker.validate_session(
        executor.requests[0].session_token, "public_records"
    )


def test_sqlite_adapter_binds_broker_scope_to_configured_operation():
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)
    executor = ControlledToolExecutor(connection, broker)
    token = broker.issue_session_token("public_records")
    request = ToolExecutionRequest(
        tool_name="read_data",
        resource_id="restricted_records",
        arguments={"resource_id": "restricted_records"},
        session_token=token,
    )
    try:
        with pytest.raises(
            ExecutorInputError, match="Invalid or expired session token"
        ):
            executor.execute(request)
    finally:
        connection.close()
