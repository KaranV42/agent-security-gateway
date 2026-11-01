import sqlite3
import hashlib
import json
from pathlib import Path
from asg.audit import AuditLogger, AuditRecord, AuditPhase

class PersistentAuditLogger(AuditLogger):
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = Path(db_path)
        self._init_database()
    
    def _init_database(self) -> None:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                outcome TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                previous_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _get_last_hash(self) -> str:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        try:
            row = conn.execute("SELECT current_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
            return row[0] if row else "GENESIS"
        finally:
            conn.close()

    def log(self, record: AuditRecord) -> None:
        previous_hash = self._get_last_hash()
        
        # Create payload for hashing
        payload = json.dumps({
            "request_id": record.request_id,
            "principal_id": record.principal_id,
            "tool_name": record.tool_name,
            "resource_id": record.resource_id,
            "phase": record.phase.value,
            "outcome": record.outcome,
            "reason": record.reason,
            "previous_hash": previous_hash
        }, sort_keys=True)
        
        current_hash = hashlib.sha256(payload.encode()).hexdigest()

        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        try:
            conn.execute("""
                INSERT INTO audit_events 
                (request_id, principal_id, tool_name, resource_id, phase, outcome, reason, previous_hash, current_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.request_id, record.principal_id, record.tool_name, record.resource_id,
                record.phase.value, record.outcome, record.reason, previous_hash, current_hash
            ))
            conn.commit()
        except Exception as e:
            from asg.audit import AuditPersistenceError
            raise AuditPersistenceError(f"Failed to persist audit record: {e}") from e
        finally:
            conn.close()

    def verify_integrity(self) -> bool:
        """Verifies the hash chain. Returns True if tamper-evident log is intact."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
            prev_hash = "GENESIS"
            for row in rows:
                payload = json.dumps({
                    "request_id": row["request_id"], "principal_id": row["principal_id"],
                    "tool_name": row["tool_name"], "resource_id": row["resource_id"],
                    "phase": row["phase"], "outcome": row["outcome"], 
                    "reason": row["reason"], "previous_hash": prev_hash
                }, sort_keys=True)
                expected_hash = hashlib.sha256(payload.encode()).hexdigest()
                if row["current_hash"] != expected_hash:
                    return False
                prev_hash = row["current_hash"]
            return True
        finally:
            conn.close()

    def get_recent_records(self, limit: int = 50) -> list[dict]:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("""
                SELECT request_id, principal_id, tool_name, resource_id, 
                       phase, outcome, reason, timestamp
                FROM audit_events ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()