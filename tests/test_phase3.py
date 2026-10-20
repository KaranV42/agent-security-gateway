import pytest
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway
from asg.policy import PolicyEvaluator
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.audit import AuditLogger, AuditRecord

class _DummyAuditLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None:
        pass

class _FailingExecutor:
    """A mock executor that raises an exception if invoked."""
    def execute_tool(self, tool_name: str, args: dict) -> list[dict]:
        raise RuntimeError("Security boundary violated: Executor was called despite validation failure.")

@pytest.fixture
def gateway():
    connection = create_mock_database()
    executor = ControlledToolExecutor(connection)
    
    registry = ToolRegistry()
    registry.register(
        "read_database",
        ToolSchema(
            required_args=frozenset({"table_name"}),
            resource_arg="table_name",
            allowed_resources=frozenset({"public_data", "restricted_data"})
        )
    )
    
    # Provide a policy evaluator. 
    # Phase 2/3 tests use "user_1" to ensure authorization passes for routing tests.
    policy = PolicyEvaluator()
    
    yield ASGGateway(
        executor=executor, 
        registry=registry, 
        principal_id="user_1", 
        policy=policy,
        audit_logger=_DummyAuditLogger()
    )
    connection.close()

def test_gateway_validates_unknown_tool(gateway):
    with pytest.raises(ToolValidationError, match="Unknown tool"):
        gateway.execute_tool("delete_all_data", {})

def test_gateway_validates_missing_argument(gateway):
    with pytest.raises(ToolValidationError, match="Missing required"):
        gateway.execute_tool("read_database", {})

def test_gateway_validates_unexpected_argument(gateway):
    with pytest.raises(ToolValidationError, match="Unexpected arguments"):
        gateway.execute_tool("read_database", {"table_name": "public_data", "extra": "arg"})

def test_gateway_validates_unauthorized_resource(gateway):
    with pytest.raises(ToolValidationError, match="not permitted"):
        gateway.execute_tool("read_database", {"table_name": "secret_data"})

def test_gateway_blocks_execution_on_validation_failure():
    """
    Proves that the gateway halts execution before reaching the executor 
    when a validation rule is violated.
    """
    executor = _FailingExecutor()
    registry = ToolRegistry()
    registry.register(
        "read_database",
        ToolSchema(
            required_args=frozenset({"table_name"}),
            resource_arg="table_name",
            allowed_resources=frozenset({"public_data"})
        )
    )
    
    # Phase 4 requires identity and policy context.
    policy = PolicyEvaluator()
    
    # Phase 5 requires an audit logger.
    audit_logger = _DummyAuditLogger()
    
    gateway = ASGGateway(
        executor=executor, 
        registry=registry, 
        principal_id="user_1", 
        policy=policy,
        audit_logger=audit_logger
    )
    
    with pytest.raises(ToolValidationError):
        gateway.execute_tool("read_database", {"table_name": "unauthorized_table"})