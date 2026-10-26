import pytest
import datetime
import os
from pathlib import Path
from fastapi.testclient import TestClient

from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import PolicyEvaluator
from asg.audit_store import PersistentAuditLogger
from asg.idp import idp # Import the simulated IdP

TEST_DB_PATH = "test_audit.db"

@pytest.fixture
def client():
    if Path(TEST_DB_PATH).exists():
        os.remove(TEST_DB_PATH)
    
    connection = create_mock_database()
    executor = ControlledToolExecutor(connection)
    registry = ToolRegistry()
    registry.register("read_database", ToolSchema(
        description="Reads data.", required_args=frozenset({"table_name"}),
        resource_arg="table_name", allowed_resources=frozenset({"public_data", "restricted_data"})
    ))
    policy = PolicyEvaluator()
    logger = PersistentAuditLogger(db_path=TEST_DB_PATH)
    
    app = create_app(executor, registry, policy, logger)
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
    assert len(data) == 1
    assert data[0]["function"]["name"] == "read_database"

def test_unauthorized_request_returns_401(client):
    test_client, _ = client
    response = test_client.post("/api/v1/execute", json={
        "tool_name": "read_database", "arguments": {"table_name": "public_data"}
    })
    assert response.status_code == 401

def test_successful_execution_returns_200(client):
    test_client, logger = client
    # Generate token using the IdP
    token = idp.generate_token("user_1")
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_database", "arguments": {"table_name": "public_data"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["result"][0]["key"] == "company_name"
    
    records = logger.get_recent_records()
    assert len(records) >= 2

def test_authorization_denial_returns_403(client):
    test_client, logger = client
    token = idp.generate_token("user_2")
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_database", "arguments": {"table_name": "restricted_data"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    
    records = logger.get_recent_records()
    assert len(records) >= 1
    assert records[0]["outcome"] == "DENY"

def test_invalid_issuer_returns_401(client):
    """Proves that tokens from untrusted IdPs are rejected."""
    import jwt
    from cryptography.hazmat.primitives import serialization
    
    test_client, _ = client
    
    private_pem = idp._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    bad_payload = {
        "sub": "user_1",
        "iss": "https://malicious-idp.local", # Wrong issuer
        "aud": "https://api.asg-prototype.local",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }
    bad_token = jwt.encode(bad_payload, private_pem, algorithm="RS256", headers={"kid": idp._kid})
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_database", "arguments": {"table_name": "public_data"}},
        headers={"Authorization": f"Bearer {bad_token}"}
    )
    assert response.status_code == 401
    assert "Invalid token issuer" in response.json()["detail"]