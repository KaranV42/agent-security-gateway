import pytest
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway, AuthorizationError
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.policy import PolicyEvaluator
from asg.audit import AuditLogger, AuditRecord

class _DummyAuditLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None:
        pass

@pytest.fixture
def make_gateway():
    def _factory(principal_id: str):
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
        policy = PolicyEvaluator()
        audit_logger = _DummyAuditLogger()
        return ASGGateway(executor, registry, principal_id, policy, audit_logger = _DummyAuditLogger()), connection
    return _factory

def test_admin_can_read_public_data(make_gateway):
    gateway, conn = make_gateway("user_1")
    try:
        result = gateway.execute_tool("read_database", {"table_name": "public_data"})
        assert result[0]["key"] == "company_name"
    finally:
        conn.close()

def test_admin_can_read_restricted_data(make_gateway):
    gateway, conn = make_gateway("user_1")
    try:
        result = gateway.execute_tool("read_database", {"table_name": "restricted_data"})
        assert result[0]["key"] == "ceo_salary"
    finally:
        conn.close()

def test_viewer_can_read_public_data(make_gateway):
    gateway, conn = make_gateway("user_2")
    try:
        result = gateway.execute_tool("read_database", {"table_name": "public_data"})
        assert result[0]["key"] == "company_name"
    finally:
        conn.close()

def test_viewer_cannot_read_restricted_data(make_gateway):
    gateway, conn = make_gateway("user_2")
    try:
        with pytest.raises(AuthorizationError, match="Viewers cannot access"):
            gateway.execute_tool("read_database", {"table_name": "restricted_data"})
    finally:
        conn.close()

def test_unknown_user_denied_by_default(make_gateway):
    gateway, conn = make_gateway("unknown_user")
    try:
        with pytest.raises(AuthorizationError, match="Access denied by default"):
            gateway.execute_tool("read_database", {"table_name": "public_data"})
    finally:
        conn.close()

def test_agent_cannot_spoof_principal(make_gateway):
    """
    Proves that the agent cannot inject a principal into the tool arguments.
    Phase 3 structural validation rejects unexpected arguments before 
    Phase 4 authorization is even evaluated.
    """
    gateway, conn = make_gateway("user_2")
    try:
        with pytest.raises(ToolValidationError, match="Unexpected arguments"):
            gateway.execute_tool(
                "read_database", 
                {
                    "table_name": "restricted_data",
                    "principal_id": "user_1" # Spoofed payload
                }
            )
    finally:
        conn.close()