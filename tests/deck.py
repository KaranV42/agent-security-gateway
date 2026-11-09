import time
import statistics
import pytest
import jwt
import datetime
from fastapi.testclient import TestClient

from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor, ExecutorInputError
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import Effect
from asg.audit_store import PersistentAuditLogger
from asg.idp import idp
from asg.broker import CredentialBroker

TEST_DB_PATH = "test_audit_phase10.db"
ASG_SERVICE_SECRET = "test-machine-secret"

@pytest.fixture
def client():
    import os
    from pathlib import Path
    if Path(TEST_DB_PATH).exists():
        os.remove(TEST_DB_PATH)
    
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=ASG_SERVICE_SECRET)
    executor = ControlledToolExecutor(connection, broker)
    
    registry = ToolRegistry()
    registry.register("read_data", ToolSchema(
        description="Reads records from an authorized resource.", required_args=frozenset({"resource_id"}),
        resource_arg="resource_id", allowed_resources=frozenset({"public_records"})
    ))
    
    policy = DeclarativePolicyEngine()
    policy.add_rule(PolicyRule(principal_id="admin", action="read", resource_id="public_records", effect=Effect.ALLOW, reason="Allow"))
    
    logger = PersistentAuditLogger(db_path=TEST_DB_PATH)
    
    app = create_app(executor, registry, policy, logger, broker, ASG_SERVICE_SECRET)
    yield TestClient(app), logger, broker, executor
    connection.close()
    
    if Path(TEST_DB_PATH).exists():
        os.remove(TEST_DB_PATH)

# --- 1. Performance Metrics (p95 Latency) ---
def test_p95_policy_and_validation_latency(client):
    """Measures the p95 latency of the ASG enforcement boundary."""
    test_client, _, _, _ = client
    token = idp.generate_token("admin")
    
    latencies = []
    iterations = 500
    
    for _ in range(iterations):
        start = time.perf_counter()
        test_client.post("/api/v1/execute", 
            json={"tool_name": "read_data", "arguments": {"resource_id": "public_records"}},
            headers={"Authorization": f"Bearer {token}"}
        )
        end = time.perf_counter()
        latencies.append((end - start) * 1000) # Convert to ms

    latencies.sort()
    p95_index = int(len(latencies) * 0.95)
    p95_latency = latencies[p95_index]
    median_latency = latencies[len(latencies) // 2]
    
    print(f"\n--- PERFORMANCE METRICS ---")
    print(f"Iterations: {iterations}")
    print(f"Median Latency: {median_latency:.2f} ms")
    print(f"p95 Latency: {p95_latency:.2f} ms")
    print(f"---------------------------\n")
    
    # Assert p95 is under 50ms for the local SQLite demonstration.
    assert p95_latency < 50.0 

# --- 2. Bypass Resistance (Investor Demand: Bypass-resistance test results) ---
def test_executor_bypass_resistance(client):
    """Proves the executor cannot be called directly without a valid broker session."""
    _, _, broker, executor = client
    
    # Attempt to call executor with a fake token
    with pytest.raises(ExecutorInputError, match="Invalid or expired session token"):
        executor.execute_tool("read_data", {"resource_id": "public_records"}, "fake-token")
        
    # Attempt to call executor with an expired token
    expired_token = broker.issue_session_token("public_records", ttl_seconds=-1)
    with pytest.raises(ExecutorInputError, match="Invalid or expired session token"):
        executor.execute_tool("read_data", {"resource_id": "public_records"}, expired_token)

# --- 3. Red Team: Schema Abuse & SQL Injection ---
def test_sql_injection_in_resource_id(client):
    """Proves the registry and executor prevent SQL injection via resource names."""
    test_client, _, _, _ = client
    token = idp.generate_token("admin")
    
    # Attempt SQL injection
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "public_records'; DROP TABLE public_records;--"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Should be caught by Registry validation (400) or Executor (500/400), but NEVER succeed
    assert response.status_code in [400, 500]
    
    # Prove the table was NOT dropped by making a legitimate request immediately after
    response2 = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "public_records"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response2.status_code == 200

# --- 4. Red Team: Token Replay & Expiration ---
def test_expired_token_rejection(client):
    """Proves the ASG rejects expired JWTs (Token Replay mitigation)."""
    import jwt
    import datetime
    from cryptography.hazmat.primitives import serialization
    
    test_client, _, _, _ = client

    # Manually craft an expired token
    private_pem = idp._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    expired_payload = {
        "sub": "admin",
        "iss": "https://idp.asg-prototype.local",
        "aud": "https://api.asg-prototype.local",
        "exp": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1) # Expired 1 hour ago
    }
    expired_token = jwt.encode(expired_payload, private_pem, algorithm="RS256", headers={"kid": idp._kid})
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "public_records"}},
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()

# --- 5. Audit Completeness under Failure Injection ---
def test_audit_completeness_fail_closed(client):
    """Proves that if audit logging fails, the protected data is NEVER returned to the agent."""
    _, logger, _, _ = client
    
    # We can't easily inject a failure into PersistentAuditLogger mid-flight without mocking,
    # but we can verify the chain integrity after a normal run.
    import os
    from pathlib import Path
    
    # Corrupt the database file permissions to simulate a disk failure
    os.chmod(TEST_DB_PATH, 0o000) 
    
    test_client, _, _, _ = client
    token = idp.generate_token("admin")
    
    response = test_client.post("/api/v1/execute", 
        json={"tool_name": "read_data", "arguments": {"resource_id": "public_records"}},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Restore permissions for cleanup
    os.chmod(TEST_DB_PATH, 0o644)
    
    # The ASG MUST fail closed (500) and NOT return the data
    assert response.status_code == 500
    assert "AUDIT_FAILURE" in response.json()["detail"]["status"]