import sqlite3
import json
from pathlib import Path
from typing import Optional
from asg.audit import AuditLogger, AuditRecord, AuditPhase

class PersistentAuditLogger(AuditLogger):
    """
    SQLite-backed audit logger with WAL mode for durability.
    Stores audit records in a separate database from protected data.
    """
    
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = Path(db_path)
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the audit database with WAL mode and schema."""
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
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_request_id ON audit_events(request_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp DESC)
        """)
        conn.commit()
        conn.close()
    
    def log(self, record: AuditRecord) -> None:
        """Persist an audit record to the database."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        try:
            conn.execute("""
                INSERT INTO audit_events 
                (request_id, principal_id, tool_name, resource_id, phase, outcome, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record.request_id,
                record.principal_id,
                record.tool_name,
                record.resource_id,
                record.phase.value,
                record.outcome,
                record.reason
            ))
            conn.commit()
        except Exception as e:
            # Re-raise as AuditPersistenceError so the gateway can handle it
            from asg.audit import AuditPersistenceError
            raise AuditPersistenceError(f"Failed to persist audit record: {e}") from e
        finally:
            conn.close()
    
    def get_recent_records(self, limit: int = 50) -> list[dict]:
        """Retrieve the most recent audit records for the UI."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("""
                SELECT request_id, principal_id, tool_name, resource_id, 
                       phase, outcome, reason, timestamp
                FROM audit_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def clear_all(self) -> None:
        """Clear all audit records. For testing purposes only."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.execute("DELETE FROM audit_events")
        conn.commit()
        conn.close()