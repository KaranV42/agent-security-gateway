import datetime
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.executors import HttpExecutor
from asg.execution import ToolExecutorRouter
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.audit_store import PersistentAuditLogger
from asg.broker import CredentialBroker
from asg.idp import idp
from asg.models import Effect

# --- 1. Singletons & Configuration ---
ASG_SERVICE_SECRET = "super-secret-machine-identity"

# Create the Broker ONCE to ensure Gateway and Executor share the same state
broker = CredentialBroker(asg_service_secret=ASG_SERVICE_SECRET)

db_connection = create_mock_database()
http_executor = HttpExecutor()
executor = ToolExecutorRouter({
    "read_data": ControlledToolExecutor(db_connection, broker),
    "get_my_profile": http_executor,
    "get_conversation": http_executor,
})

# --- 2. Generic Data Registry ---
registry = ToolRegistry()
registry.register("read_data", ToolSchema(
    description="Reads records from an authorized resource.",
    required_args=frozenset({"resource_id"}),
    resource_arg="resource_id",
    allowed_resources=frozenset({"public_records", "restricted_records"})
))
registry.register("get_my_profile", ToolSchema(
    description="Returns the authenticated user's profile.",
    required_args=frozenset(),
))
registry.register("get_conversation", ToolSchema(
    description="Returns a conversation owned by the authenticated user.",
    required_args=frozenset({"conversation_id"}),
    authorization_resource="conversation",
))

# --- 3. Declarative Policy ---
policy = DeclarativePolicyEngine()
policy.add_rule(PolicyRule(
    principal_id="admin", action="read", resource_id="public_records",
    effect=Effect.ALLOW, reason="Administrators can read public records."
))
policy.add_rule(PolicyRule(
    principal_id="admin", action="read", resource_id="restricted_records",
    effect=Effect.ALLOW, reason="Administrators can read restricted records."
))
policy.add_rule(PolicyRule(
    principal_id="analyst", action="read", resource_id="public_records",
    effect=Effect.ALLOW, reason="Analysts can read public records."
))
policy.add_rule(PolicyRule(
    principal_id=None, action="read", resource_id="get_my_profile",
    effect=Effect.ALLOW, reason="Authenticated users can read their own profile."
))
policy.add_rule(PolicyRule(
    principal_id=None, action="read", resource_id="conversation",
    effect=Effect.ALLOW, reason="Authenticated users can request their conversations."
))
# Note: analyst access to restricted records is intentionally omitted (default-deny).

# --- 4. Audit & App Initialization ---
audit_logger = PersistentAuditLogger(db_path="audit.db")

app: FastAPI = create_app(
    executor=executor,
    registry=registry,
    policy=policy,
    audit_logger=audit_logger,
    broker=broker, 
    asg_service_secret=ASG_SERVICE_SECRET
)

# --- 5. Routes ---
@app.get("/", response_class=HTMLResponse)
async def console_home():
    html_path = Path("templates/index.html")
    if not html_path.exists():
        return HTMLResponse(content="<h1>Error: templates/index.html not found.</h1>", status_code=404)
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.get("/api/v1/auth/.well-known/jwks.json")
async def get_jwks(): 
    return idp.get_jwks()

@app.post("/api/v1/auth/demo-token")
async def get_demo_token(principal_id: str):
    token = idp.generate_token(principal_id)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/v1/audit/verify")
async def verify_audit_chain():
    is_valid = audit_logger.verify_integrity()
    return {"chain_intact": is_valid}