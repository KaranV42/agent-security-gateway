from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any

class AuditPhase(str, Enum):
    AUTHORIZATION = "AUTHORIZATION"
    EXECUTION = "EXECUTION"

@dataclass(frozen=True)
class AuditRecord:
    request_id: str
    principal_id: str
    tool_name: str
    resource_id: str
    phase: AuditPhase
    outcome: str
    reason: str

class AuditLogger(ABC):
    @abstractmethod
    def log(self, record: AuditRecord) -> None:
        pass

    def get_recent_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve recent audit records. 
        Base implementation returns an empty list. Subclasses (like PersistentAuditLogger) override this.
        """
        return []

class AuditPersistenceError(RuntimeError):
    """Raised when the audit logger fails to persist a required record."""
    pass