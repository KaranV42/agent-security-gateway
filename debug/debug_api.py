# debug_api.py
from fastapi.testclient import TestClient
from asg.api import create_app
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.registry import ToolRegistry, ToolSchema
from asg.policy import PolicyEvaluator
from asg.audit import AuditLogger, AuditRecord

class DebugLogger(AuditLogger):
    def __init__(self):
        self.records = []
    def log(self, record: AuditRecord) -> None:
        self.records.append(record)

# 1. Setup dependencies exactly as the test does
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
logger = DebugLogger()

# 2. Create app and client
app = create_app(executor, registry, policy, logger)
client = TestClient(app)

# 3. Make the request
response = client.post("/api/v1/execute", json={
    "principal_id": "user_1",
    "tool_name": "read_database",
    "args": {"table_name": "public_data"}
})

# 4. Print the exact error detail
print(f"HTTP Status: {response.status_code}")
print(f"Response JSON: {response.json()}")

connection.close()