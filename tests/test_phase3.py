import pytest
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit import AuditLogger, AuditRecord
from asg.broker import CredentialBroker

TEST_SECRET = "test-secret"

class _DummyAuditLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None: pass

class _FailingExecutor:
    def execute_tool(self, tool_name: str, args: dict, token: str) -> list[dict]:
        raise RuntimeError("Security boundary violated")

@pytest.fixture
def gateway():
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)
    executor = ControlledToolExecutor(connection, broker)
    registry = ToolRegistry()
    registry.register("read_market_data", ToolSchema(
        required_args=frozenset({"table_name"}), resource_arg="table_name",
        allowed_resources=frozenset({"market_data"})
    ))
    policy = DeclarativePolicyEngine()
    policy.add_rule(PolicyRule(principal_id="wealth_advisor", action="read", resource_id="market_data", effect=Effect.ALLOW, reason="Allow"))
    yield ASGGateway(executor, registry, "wealth_advisor", policy, _DummyAuditLogger(), broker, TEST_SECRET)
    connection.close()

def test_gateway_validates_unknown_tool(gateway):
    with pytest.raises(ToolValidationError, match="Unknown tool"):
        gateway.execute_tool("delete_all_data", {})

def test_gateway_validates_missing_argument(gateway):
    with pytest.raises(ToolValidationError, match="Missing required"):
        gateway.execute_tool("read_market_data", {})

def test_gateway_validates_unexpected_argument(gateway):
    with pytest.raises(ToolValidationError, match="Unexpected arguments"):
        gateway.execute_tool("read_market_data", {"table_name": "market_data", "extra": "arg"})

def test_gateway_validates_unauthorized_resource(gateway):
    with pytest.raises(ToolValidationError, match="not permitted"):
        gateway.execute_tool("read_market_data", {"table_name": "client_pii"})

def test_gateway_blocks_execution_on_validation_failure():
    executor = _FailingExecutor()
    registry = ToolRegistry()
    registry.register("read_market_data", ToolSchema(
        required_args=frozenset({"table_name"}), resource_arg="table_name",
        allowed_resources=frozenset({"market_data"})
    ))
    policy = DeclarativePolicyEngine()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)
    gateway = ASGGateway(executor, registry, "wealth_advisor", policy, _DummyAuditLogger(), broker, TEST_SECRET)
    
    with pytest.raises(ToolValidationError):
        gateway.execute_tool("read_market_data", {"table_name": "client_pii"})