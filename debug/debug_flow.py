# debug_flow.py
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit import AuditLogger, AuditRecord
from asg.broker import CredentialBroker
from asg.gateway import ASGGateway

class SilentLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None: pass

def main():
    print("Starting Direct Flow Test...")
    
    # 1. Create SHARED components
    SECRET = "test-secret-123"
    broker = CredentialBroker(asg_service_secret=SECRET)
    db = create_mock_database()
    executor = ControlledToolExecutor(db, broker)
    
    # 2. Setup Registry & Policy
    registry = ToolRegistry()
    registry.register("read_market_data", ToolSchema(
        required_args=frozenset({"table_name"}), resource_arg="table_name",
        allowed_resources=frozenset({"market_data"})
    ))
    
    policy = DeclarativePolicyEngine()
    policy.add_rule(PolicyRule(
        principal_id="wealth_advisor", action="read", resource_id="market_data", 
        effect=Effect.ALLOW, reason="Test Allow"
    ))
    
    # 3. Create Gateway using the EXACT SAME broker and executor
    gateway = ASGGateway(
        executor=executor,
        registry=registry,
        principal_id="wealth_advisor",
        policy=policy,
        audit_logger=SilentLogger(),
        broker=broker,
        asg_service_secret=SECRET
    )
    
    # 4. Execute
    try:
        print("Calling Gateway...")
        result = gateway.execute_tool("read_market_data", {"table_name": "market_data"})
        print(f"SUCCESS: {result}")
    except Exception as e:
        print(f"FAILED: {type(e).__name__} - {e}")

if __name__ == "__main__":
    main()