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
        registry.register("read_market_data", ToolSchema(
            required_args=frozenset({"table_name"}), resource_arg="table_name",
            allowed_resources=frozenset({"market_data", "client_pii"})
        ))
        registry.register("read_client_pii", ToolSchema(
            required_args=frozenset({"table_name"}), resource_arg="table_name",
            allowed_resources=frozenset({"market_data", "client_pii"})
        ))
        policy = DeclarativePolicyEngine()
        policy.add_rule(PolicyRule(principal_id="wealth_advisor", action="read", resource_id="market_data", effect=Effect.ALLOW, reason="Allow"))
        policy.add_rule(PolicyRule(principal_id="wealth_advisor", action="read", resource_id="client_pii", effect=Effect.ALLOW, reason="Allow"))
        policy.add_rule(PolicyRule(principal_id="client_portal", action="read", resource_id="market_data", effect=Effect.ALLOW, reason="Allow"))
        
        return ASGGateway(executor, registry, principal_id, policy, _DummyAuditLogger(), broker, TEST_SECRET), connection
    return _factory

def test_advisor_can_read_market_data(make_gateway):
    gateway, conn = make_gateway("wealth_advisor")
    try:
        result = gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        assert result[0]["symbol"] == "AAPL"
    finally: conn.close()

def test_advisor_can_read_client_pii(make_gateway):
    gateway, conn = make_gateway("wealth_advisor")
    try:
        result = gateway.execute_tool("read_client_pii", {"table_name": "client_pii"})
        assert result[0]["client_id"] == "C-9901"
    finally: conn.close()

def test_portal_can_read_market_data(make_gateway):
    gateway, conn = make_gateway("client_portal")
    try:
        result = gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        assert result[0]["symbol"] == "AAPL"
    finally: conn.close()

def test_portal_cannot_read_client_pii(make_gateway):
    gateway, conn = make_gateway("client_portal")
    try:
        with pytest.raises(AuthorizationError, match="No matching policy"):
            gateway.execute_tool("read_client_pii", {"table_name": "client_pii"})
    finally: conn.close()

def test_unknown_user_denied_by_default(make_gateway):
    gateway, conn = make_gateway("unknown_user")
    try:
        with pytest.raises(AuthorizationError, match="No matching policy"):
            gateway.execute_tool("read_market_data", {"table_name": "market_data"})
    finally: conn.close()

def test_agent_cannot_spoof_principal(make_gateway):
    gateway, conn = make_gateway("client_portal")
    try:
        with pytest.raises(ToolValidationError, match="Unexpected arguments"):
            gateway.execute_tool("read_client_pii", {"table_name": "client_pii", "principal_id": "wealth_advisor"})
    finally: conn.close()