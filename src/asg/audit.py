from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

class AuditPhase(str, Enum):
    """The stage of the request lifecycle being audited."""
    AUTHORIZATION = "AUTHORIZATION"
    EXECUTION = "EXECUTION"

@dataclass(frozen=True)
class AuditRecord:
    """Immutable record of a specific security or execution event."""
    request_id: str
    principal_id: str
    tool_name: str
    resource_id: str
    phase: AuditPhase
    outcome: str  # e.g., "ALLOW", "DENY", "SUCCESS", "FAILURE"
    reason: str

class AuditLogger(ABC):
    """Interface for persisting audit records."""
    
    @abstractmethod
    def log(self, record: AuditRecord) -> None:
        """Persists the audit record. Raises an exception on failure."""
        pass

class AuditPersistenceError(RuntimeError):
    """Raised when the audit logger fails to persist a required record."""
    pass