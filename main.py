import datetime
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import PolicyEvaluator
from asg.audit_store import PersistentAuditLogger
from asg.idp import idp

db_connection = create_mock_database()
executor = ControlledToolExecutor(db_connection)

registry = ToolRegistry()
registry.register(
    "read_database",
    ToolSchema(
        description="Reads data from a specific database table.",
        required_args=frozenset({"table_name"}),
        resource_arg="table_name",
        allowed_resources=frozenset({"public_data", "restricted_data"})
    )
)

policy = PolicyEvaluator()
audit_logger = PersistentAuditLogger(db_path="audit.db")

# Note: jwt_secret_key is no longer needed; auth.py uses the IdP's public key
app: FastAPI = create_app(
    executor=executor,
    registry=registry,
    policy=policy,
    audit_logger=audit_logger
)

@app.get("/", response_class=HTMLResponse)
async def console_home():
    html_path = Path("templates/index.html")
    if not html_path.exists():
        return HTMLResponse(content="<h1>Error: templates/index.html not found.</h1>", status_code=404)
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

# --- Identity Provider Simulation Endpoints ---
@app.get("/api/v1/auth/.well-known/jwks.json")
async def get_jwks():
    """Exposes the IdP's public key for the ASG (or other services) to verify tokens."""
    return idp.get_jwks()

@app.post("/api/v1/auth/demo-token")
async def get_demo_token(principal_id: str):
    """
    Simulates a user logging in. 
    In production, this would be replaced by a real IdP's /oauth/token endpoint.
    """
    token = idp.generate_token(principal_id)
    return {"access_token": token, "token_type": "bearer"}