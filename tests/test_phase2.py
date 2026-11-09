import ast
import inspect
import pytest
from asg.agent_runtime import run_agent
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

@pytest.fixture
def gateway():
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)
    executor = ControlledToolExecutor(connection, broker)
    
    registry = ToolRegistry()
    registry.register("read_data", ToolSchema(
        required_args=frozenset({"resource_id"}), resource_arg="resource_id",
        allowed_resources=frozenset({"public_records"})
    ))
    
    policy = DeclarativePolicyEngine()
    policy.add_rule(PolicyRule(principal_id="admin", action="read", resource_id="public_records", effect=Effect.ALLOW, reason="Allow"))
    
    yield ASGGateway(executor, registry, "admin", policy, _DummyAuditLogger(), broker, TEST_SECRET)
    connection.close()

def test_agent_reads_public_records_through_gateway(gateway):
    result = run_agent(gateway)
    assert result[0]["record_id"] == "public-001"

def test_gateway_forwards_tool_request(gateway):
    result = gateway.execute_tool("read_data", {"resource_id": "public_records"})
    assert result[0]["record_id"] == "public-001"

def test_agent_runtime_does_not_import_executor():
    import asg.agent_runtime as runtime
    source = inspect.getsource(runtime)
    tree = ast.parse(source)
    imported_modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported_names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names}
    assert "asg.executor" not in imported_modules
    assert "ControlledToolExecutor" not in imported_names

def test_gateway_rejects_unknown_tool(gateway):
    with pytest.raises(ToolValidationError):
        gateway.execute_tool("delete_all_data", {})