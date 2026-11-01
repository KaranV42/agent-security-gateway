import pytest
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway, AuthorizationError, AuditPersistenceError
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit import AuditLogger, AuditRecord, AuditPhase
from asg.broker import CredentialBroker

TEST_SECRET = "test-secret"

class InMemoryAuditLogger(AuditLogger):
    def __init__(self, fail_on_call=None):
        self.records = []; self.call_count = 0; self.fail_on_call = fail_on_call
    def log(self, record):
        self.call_count += 1
        if self.fail_on_call is not None and self.call_count == self.fail_on_call:
            raise RuntimeError("Simulated audit persistence failure")
        self.records.append(record)

@pytest.fixture
def make_gateway():
    def _factory(principal_id: str, audit_logger: AuditLogger):
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
        
        return ASGGateway(executor, registry, principal_id, policy, audit_logger, broker, TEST_SECRET), connection
    return _factory

def test_successful_execution_logs_auth_and_execution(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("wealth_advisor", logger)
    try:
        gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        assert len(logger.records) == 2
        assert logger.records[0].phase == AuditPhase.AUTHORIZATION and logger.records[0].outcome == "ALLOW"
        assert logger.records[1].phase == AuditPhase.EXECUTION and logger.records[1].outcome == "SUCCESS"
        assert logger.records[0].request_id == logger.records[1].request_id
    finally: conn.close()

def test_denied_request_logs_auth_deny_and_skips_execution(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("client_portal", logger) # client_portal denied client_pii
    try:
        with pytest.raises(AuthorizationError):
            gateway.execute_tool("read_client_pii", {"table_name": "client_pii"})
        assert len(logger.records) == 1 and logger.records[0].outcome == "DENY"
    finally: conn.close()

def test_audit_failure_withholds_result(make_gateway):
    logger = InMemoryAuditLogger(fail_on_call=2)
    gateway, conn = make_gateway("wealth_advisor", logger)
    try:
        with pytest.raises(AuditPersistenceError, match="Audit logging failed"):
            gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        assert len(logger.records) == 1
    finally: conn.close()

def test_validation_failure_logs_auth_deny(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("wealth_advisor", logger)
    try:
        with pytest.raises(ToolValidationError):
            gateway.execute_tool("read_market_data", {"table_name": "invalid_table"})
        assert len(logger.records) == 1 and "Validation failed" in logger.records[0].reason
    finally: conn.close()

def test_request_ids_are_unique(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("wealth_advisor", logger)
    try:
        gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        ids = {record.request_id for record in logger.records}
        assert len(ids) == 2
    finally: conn.close()