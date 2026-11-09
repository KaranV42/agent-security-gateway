import pytest
import datetime
import os
import jwt
from pathlib import Path
from fastapi.testclient import TestClient

from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit_store import PersistentAuditLogger
from asg.idp import idp
from asg.broker import CredentialBroker

TEST_DB_PATH = "test_audit.db"
ASG_SERVICE_SECRET = "test-machine-secret"

@pytest.fixture
def client():
    if Path(TEST_DB_PATH).exists():
        os.remove(TEST_DB_PATH)
    
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=ASG_SERVICE_SECRET)
    executor = ControlledToolExecutor(connection, broker)
    
    registry = ToolRegistry()
    registry.register("read_data", ToolSchema(
        description="Reads records from an authorized resource.", required_args=frozenset({"resource_id"}),
        resource_arg="resource_id", allowed_resources=frozenset({"public_records", "restricted_records"})
    ))
    
    policy = DeclarativePolicyEngine()
    policy.add_rule(PolicyRule(principal_id="admin", action="read", resource_id="public_records", effect=Effect.ALLOW, reason="Administrators can read public records."))
    policy.add_rule(PolicyRule(principal_id="admin", action="read", resource_id="restricted_records", effect=Effect.ALLOW, reason="Administrators can read restricted records."))
    policy.add_rule(PolicyRule(principal_id="analyst", action="read", resource_id="public_records", effect=Effect.ALLOW, reason="Analysts can read public records."))
    
    logger = PersistentAuditLogger(db_path=TEST_DB_PATH)
    
    app = create_app(executor, registry, policy, logger, broker, ASG_SERVICE_SECRET)
    yield TestClient(app), logger
    connection.close()
    
    if Path(TEST_DB_PATH).exists():
        os.remove(TEST_DB_PATH)
    for ext in ["-wal", "-shm"]:
        wal_file = Path(TEST_DB_PATH + ext)
        if wal_file.exists():
            os.remove(wal_file)

def test_get_tools_returns_openai_schema(client):
    test_client, _ = client
    response = test_client.get("/api/v1/tools")
    assert response.status_code == 200
    data = response.json()
    tool_names = {t["function"]["name"] for t in data}
    assert tool_names == {"read_data"}

def test_unauthorized_request_returns_401(client):
    test_client, _ = client
    response = test_client.post("/api/v1/execute", json={
        "tool_name": "read_data", "arguments": {"resource_id": "public_records"}
    })
    assert response.status_code == 401

def test_successful_execution_returns_200(client):
    test_client, logger = client
    token = idp.generate_token("admin")
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "public_records"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["result"][0]["record_id"] == "public-001"
    
    records = logger.get_recent_records()
    assert len(records) >= 2

def test_authorization_denial_returns_403(client):
    test_client, logger = client
    token = idp.generate_token("analyst")
    
    # Analysts are not allowed to read restricted records.
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "restricted_records"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    
    records = logger.get_recent_records()
    assert len(records) >= 1
    assert records[0]["outcome"] == "DENY"

def test_invalid_issuer_returns_401(client):
    from cryptography.hazmat.primitives import serialization
    
    test_client, _ = client
    
    private_pem = idp._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    bad_payload = {
        "sub": "admin",
        "iss": "https://malicious-idp.local",
        "aud": "https://api.asg-prototype.local",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }
    bad_token = jwt.encode(bad_payload, private_pem, algorithm="RS256", headers={"kid": idp._kid})
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "public_records"}},
        headers={"Authorization": f"Bearer {bad_token}"}
    )
    assert response.status_code == 401
    assert "Invalid token issuer" in response.json()["detail"]