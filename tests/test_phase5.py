import pytest
from typing import Optional
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway, AuthorizationError, AuditPersistenceError
from asg.registry import ToolRegistry, ToolSchema, ToolValidationError
from asg.policy import PolicyEvaluator
from asg.audit import AuditLogger, AuditRecord, AuditPhase

class InMemoryAuditLogger(AuditLogger):
    """Mock logger that stores records in memory and can simulate failures."""
    def __init__(self, fail_on_call: Optional[int] = None):
        self.records: list[AuditRecord] = []
        self.call_count = 0
        self.fail_on_call = fail_on_call

    def log(self, record: AuditRecord) -> None:
        self.call_count += 1
        if self.fail_on_call is not None and self.call_count == self.fail_on_call:
            raise RuntimeError("Simulated audit persistence failure")
        self.records.append(record)

@pytest.fixture
def make_gateway():
    def _factory(principal_id: str, audit_logger: AuditLogger):
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
        return ASGGateway(executor, registry, principal_id, policy, audit_logger), connection
    return _factory

def test_successful_execution_logs_auth_and_execution(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("user_1", logger)
    try:
        gateway.execute_tool("read_database", {"table_name": "public_data"})
        
        assert len(logger.records) == 2
        assert logger.records[0].phase == AuditPhase.AUTHORIZATION
        assert logger.records[0].outcome == "ALLOW"
        assert logger.records[1].phase == AuditPhase.EXECUTION
        assert logger.records[1].outcome == "SUCCESS"
        
        # Verify request_id correlation
        assert logger.records[0].request_id == logger.records[1].request_id
    finally:
        conn.close()

def test_denied_request_logs_auth_deny_and_skips_execution(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("user_2", logger)
    try:
        with pytest.raises(AuthorizationError):
            gateway.execute_tool("read_database", {"table_name": "restricted_data"})
            
        assert len(logger.records) == 1
        assert logger.records[0].phase == AuditPhase.AUTHORIZATION
        assert logger.records[0].outcome == "DENY"
    finally:
        conn.close()

def test_audit_failure_withholds_result(make_gateway):
    """
    Proves fail-closed behavior: if the final execution audit fails, 
    the gateway must raise an AuditPersistenceError and not return the result.
    """
    # Fail on the 2nd call (the EXECUTION SUCCESS log)
    logger = InMemoryAuditLogger(fail_on_call=2)
    gateway, conn = make_gateway("user_1", logger)
    try:
        with pytest.raises(AuditPersistenceError, match="Audit logging failed"):
            gateway.execute_tool("read_database", {"table_name": "public_data"})
            
        # The first log (AUTHORIZATION) should have succeeded
        assert len(logger.records) == 1
        assert logger.records[0].phase == AuditPhase.AUTHORIZATION
    finally:
        conn.close()

def test_validation_failure_logs_auth_deny(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("user_1", logger)
    try:
        with pytest.raises(ToolValidationError):
            gateway.execute_tool("read_database", {"table_name": "invalid_table"})
            
        assert len(logger.records) == 1
        assert logger.records[0].phase == AuditPhase.AUTHORIZATION
        assert logger.records[0].outcome == "DENY"
        assert "Validation failed" in logger.records[0].reason
    finally:
        conn.close()

def test_request_ids_are_unique(make_gateway):
    logger = InMemoryAuditLogger()
    gateway, conn = make_gateway("user_1", logger)
    try:
        gateway.execute_tool("read_database", {"table_name": "public_data"})
        gateway.execute_tool("read_database", {"table_name": "public_data"})
        
        ids = {record.request_id for record in logger.records}
        # 4 records total (2 per request), should have 2 unique IDs
        assert len(ids) == 2
    finally:
        conn.close()