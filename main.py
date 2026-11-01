import datetime
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.audit_store import PersistentAuditLogger
from asg.broker import CredentialBroker
from asg.idp import idp
from asg.models import Effect

# 1. Core Resources
db_connection = create_mock_database()
ASG_SERVICE_SECRET = "super-secret-machine-identity"
broker = CredentialBroker(asg_service_secret=ASG_SERVICE_SECRET)
executor = ControlledToolExecutor(db_connection, broker)

# 2. Registry (Financial Services Wedge)
registry = ToolRegistry()
registry.register("read_market_data", ToolSchema(
    description="Reads public market data.",
    required_args=frozenset({"table_name"}), resource_arg="table_name",
    allowed_resources=frozenset({"market_data"})
))
registry.register("read_client_pii", ToolSchema(
    description="Reads sensitive client PII.",
    required_args=frozenset({"table_name"}), resource_arg="table_name",
    allowed_resources=frozenset({"client_pii"})
))

# 3. Policy (Financial Services Rules)
policy = DeclarativePolicyEngine()
policy.add_rule(PolicyRule(principal_id="wealth_advisor", action="read", resource_id="market_data", effect=Effect.ALLOW, reason="Advisors can view market data."))
policy.add_rule(PolicyRule(principal_id="wealth_advisor", action="read", resource_id="client_pii", effect=Effect.ALLOW, reason="Advisors can view their assigned client PII."))
policy.add_rule(PolicyRule(principal_id="client_portal", action="read", resource_id="market_data", effect=Effect.ALLOW, reason="Clients can view market data."))

# 4. Audit & Broker
audit_logger = PersistentAuditLogger(db_path="audit.db")
ASG_SERVICE_SECRET = "super-secret-machine-identity"
broker = CredentialBroker(asg_service_secret=ASG_SERVICE_SECRET)

# 5. Create App (Pass broker and secret)
app: FastAPI = create_app(
    executor=executor,
    registry=registry,
    policy=policy,
    audit_logger=audit_logger,
    broker=broker,
    asg_service_secret=ASG_SERVICE_SECRET
)


@app.get("/", response_class=HTMLResponse)
async def console_home():
    html_path = Path("templates/index.html")
    if not html_path.exists():
        return HTMLResponse(content="<h1>Error: templates/index.html not found.</h1>", status_code=404)
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.get("/api/v1/auth/.well-known/jwks.json")
async def get_jwks(): return idp.get_jwks()

@app.post("/api/v1/auth/demo-token")
async def get_demo_token(principal_id: str):
    token = idp.generate_token(principal_id)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/v1/audit/verify")
async def verify_audit_chain():
    """Investor Requirement: Prove tamper-evident audit log."""
    is_valid = audit_logger.verify_integrity()
    return {"chain_intact": is_valid}