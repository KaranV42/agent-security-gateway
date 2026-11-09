import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from asg.audit import AuditPhase, AuditRecord
from asg.audit_store import PersistentAuditLogger


if __name__ == "__main__":
    records = [
        AuditRecord(
            request_id=f"request-{index}",
            principal_id="golden-principal",
            tool_name="read_data",
            resource_id="public_records",
            phase=AuditPhase.AUTHORIZATION,
            outcome="ALLOW",
            reason=f"fixed audit record {index}",
        )
        for index in range(1, 6)
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "audit.db"
        logger = PersistentAuditLogger(db_path=str(db_path))
        hashes = []
        for record in records:
            logger.log(record)
            with sqlite3.connect(db_path) as connection:
                row = connection.execute(
                    "SELECT current_hash FROM audit_events ORDER BY id DESC LIMIT 1"
                ).fetchone()
            hashes.append(row[0])

    result = {"final_hash": hashes[-1], "intermediate_hashes": hashes}
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (ROOT / "golden" / "hashchain.json").write_text(output, encoding="utf-8")
