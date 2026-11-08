# debug_gateway_flow.py
from asg.broker import CredentialBroker
from asg.executor import ControlledToolExecutor
from asg.gateway import ASGGateway
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit import AuditLogger, AuditRecord
from asg.database import create_mock_database

class SilentLogger(AuditLogger):
    def log(self, record: AuditRecord) -> None: pass

SECRET = "test-secret-123"
broker = CredentialBroker(asg_service_secret=SECRET)
db = create_mock_database()
executor = ControlledToolExecutor(db, broker)

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

gateway = ASGGateway(
    executor=executor, registry=registry, principal_id="wealth_advisor",
    policy=policy, audit_logger=SilentLogger(), broker=broker, asg_service_secret=SECRET
)

# --- INTERCEPTOR CODE ---
# This prints exactly what the Gateway sends to the Broker
original_issue = broker.issue_session_token
def debug_issue(resource_id, ttl=60):
    print(f"\n[GATEWAY -> BROKER] Issuing token for resource_id: '{resource_id}' (type: {type(resource_id)})")
    token = original_issue(resource_id, ttl)
    print(f"[GATEWAY -> BROKER] Issued token: {token}\n")
    return token
broker.issue_session_token = debug_issue

# This prints exactly what the Executor sends to the Broker
original_validate = broker.validate_session
def debug_validate(token, resource_id):
    print(f"[EXECUTOR -> BROKER] Validating token for resource_id: '{resource_id}' (type: {type(resource_id)})")
    result = original_validate(token, resource_id)
    print(f"[EXECUTOR -> BROKER] Validation result: {result}\n")
    return result
broker.validate_session = debug_validate
# ------------------------

try:
    print("Calling Gateway...")
    result = gateway.execute_tool("read_market_data", {"table_name": "market_data"})
    print(f"SUCCESS: {result}")
except Exception as e:
    print(f"FAILED: {type(e).__name__} - {e}")