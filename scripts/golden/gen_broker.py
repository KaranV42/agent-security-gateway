import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from asg.broker import CredentialBroker


if __name__ == "__main__":
    broker = CredentialBroker(asg_service_secret="golden-service-secret")
    resource_id = "golden-resource"
    token = broker.issue_session_token(resource_id)
    # The issued session dict contains resource_id, expires_at, and hash.
    result = {
        "correct_resource": broker.validate_session(token, resource_id),
        "incorrect_resource": broker.validate_session(token, "other-resource"),
        "nonexistent_token": broker.validate_session(
            "00000000-0000-0000-0000-000000000000", resource_id
        ),
    }
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (ROOT / "golden" / "broker.json").write_text(output, encoding="utf-8")
