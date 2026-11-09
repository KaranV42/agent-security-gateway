import json
import itertools
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient

from asg.api import create_app
from asg.audit_store import PersistentAuditLogger
from asg.broker import CredentialBroker
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor
from asg.idp import idp
from asg.models import Effect
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.registry import ToolRegistry, ToolSchema

_uuid_counter = itertools.count(1)


def mock_uuid4() -> uuid.UUID:
    return uuid.UUID(int=next(_uuid_counter))


if __name__ == "__main__":
    service_secret = "golden-e2e-service-secret"
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=service_secret)
    executor = ControlledToolExecutor(connection, broker)

    registry = ToolRegistry()
    registry.register(
        "read_data",
        ToolSchema(
            description="Reads records from an authorized resource.",
            required_args=frozenset({"resource_id"}),
            resource_arg="resource_id",
            allowed_resources=frozenset({"public_records", "restricted_records"}),
        ),
    )

    policy = DeclarativePolicyEngine(
        [
            PolicyRule(
                principal_id="admin",
                action="read",
                resource_id="public_records",
                effect=Effect.ALLOW,
                reason="Golden smoke authorized access",
            )
        ]
    )

    with tempfile.TemporaryDirectory() as temp_dir:
        audit_logger = PersistentAuditLogger(
            db_path=str(Path(temp_dir) / "audit.db")
        )
        app = create_app(
            executor,
            registry,
            policy,
            audit_logger,
            broker,
            service_secret,
        )
        with patch("asg.api.uuid.uuid4", side_effect=mock_uuid4):
            with TestClient(app) as client:
                authorized = client.post(
                    "/api/v1/execute",
                    json={
                        "tool_name": "read_data",
                        "arguments": {"resource_id": "public_records"},
                    },
                    headers={
                        "Authorization": f"Bearer {idp.generate_token('admin')}"
                    },
                )
                unauthorized = client.post(
                    "/api/v1/execute",
                    json={
                        "tool_name": "read_data",
                        "arguments": {"resource_id": "restricted_records"},
                    },
                    headers={
                        "Authorization": f"Bearer {idp.generate_token('analyst')}"
                    },
                )

    connection.close()
    result = {
        "authorized": {
            "status_code": authorized.status_code,
            "json": authorized.json(),
        },
        "unauthorized": {
            "status_code": unauthorized.status_code,
            "json": unauthorized.json(),
        },
    }
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (ROOT / "golden" / "e2e.json").write_text(output, encoding="utf-8")
