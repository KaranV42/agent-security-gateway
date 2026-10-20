import ast
import inspect
import pytest

from asg.agent_runtime import run_agent
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.policy import PolicyEvaluator
from asg.audit import AuditLogger, AuditRecord

class _DummyAuditLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None:
        pass

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

def test_agent_reads_public_data_through_gateway(gateway):
    result = run_agent(gateway)
    assert result == [
        {
            "key": "company_name",
            "value": "Example Company",
        }
    ]

def test_gateway_forwards_tool_request(gateway):
    result = gateway.execute_tool(
        "read_database",
        {"table_name": "public_data"},
    )
    assert result[0]["key"] == "company_name"

def test_agent_runtime_does_not_import_executor():
    """
    Verifies that the agent runtime module does not contain static imports 
    of the executor module or the ControlledToolExecutor class.
    """
    import asg.agent_runtime as runtime
    
    source = inspect.getsource(runtime)
    tree = ast.parse(source)
    
    imported_modules = set()
    imported_names = set()
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.add(node.module)
                for alias in node.names:
                    imported_names.add(alias.name)
                    
    assert "asg.executor" not in imported_modules, \
        "agent_runtime must not import asg.executor"
    assert "ControlledToolExecutor" not in imported_names, \
        "agent_runtime must not import ControlledToolExecutor"

def test_gateway_rejects_unknown_tool(gateway):
    # With Phase 3 validation, an unknown tool raises ToolValidationError
    with pytest.raises(ToolValidationError):
        gateway.execute_tool("delete_all_data", {})