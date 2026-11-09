import pytest
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway, AuthorizationError
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit import AuditLogger, AuditRecord
from asg.broker import CredentialBroker

TEST_SECRET = "test-secret"

class _DummyAuditLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None: pass

@pytest.fixture
def make_gateway():
    def _factory(principal_id: str):
        connection = create_mock_database()
        broker = CredentialBroker(asg_service_secret=TEST_SECRET)
        executor = ControlledToolExecutor(connection, broker)
        registry = ToolRegistry()
        registry.register("read_data", ToolSchema(
            required_args=frozenset({"resource_id"}), resource_arg="resource_id",
            allowed_resources=frozenset({"public_records", "restricted_records"})
        ))
        policy = DeclarativePolicyEngine()
        policy.add_rule(PolicyRule(principal_id="admin", action="read", resource_id="public_records", effect=Effect.ALLOW, reason="Allow"))
        policy.add_rule(PolicyRule(principal_id="admin", action="read", resource_id="restricted_records", effect=Effect.ALLOW, reason="Allow"))
        policy.add_rule(PolicyRule(principal_id="analyst", action="read", resource_id="public_records", effect=Effect.ALLOW, reason="Allow"))
        
        return ASGGateway(executor, registry, principal_id, policy, _DummyAuditLogger(), broker, TEST_SECRET), connection
    return _factory

def test_admin_can_read_public_records(make_gateway):
    gateway, conn = make_gateway("admin")
    try:
        result = gateway.execute_tool("read_data", {"resource_id": "public_records"})
        assert result[0]["record_id"] == "public-001"
    finally: conn.close()

def test_admin_can_read_restricted_records(make_gateway):
    gateway, conn = make_gateway("admin")
    try:
        result = gateway.execute_tool("read_data", {"resource_id": "restricted_records"})
        assert result[0]["record_id"] == "restricted-001"
    finally: conn.close()

def test_analyst_can_read_public_records(make_gateway):
    gateway, conn = make_gateway("analyst")
    try:
        result = gateway.execute_tool("read_data", {"resource_id": "public_records"})
        assert result[0]["record_id"] == "public-001"
    finally: conn.close()

def test_analyst_cannot_read_restricted_records(make_gateway):
    gateway, conn = make_gateway("analyst")
    try:
        with pytest.raises(AuthorizationError, match="No matching policy"):
            gateway.execute_tool("read_data", {"resource_id": "restricted_records"})
    finally: conn.close()

def test_unknown_user_denied_by_default(make_gateway):
    gateway, conn = make_gateway("unknown_user")
    try:
        with pytest.raises(AuthorizationError, match="No matching policy"):
            gateway.execute_tool("read_data", {"resource_id": "public_records"})
    finally: conn.close()

def test_agent_cannot_spoof_principal(make_gateway):
    gateway, conn = make_gateway("analyst")
    try:
        with pytest.raises(ToolValidationError, match="Unexpected arguments"):
            gateway.execute_tool("read_data", {"resource_id": "restricted_records", "principal_id": "admin"})
    finally: conn.close()