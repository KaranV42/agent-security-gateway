import uuid
import hashlib
import time
from typing import Optional

class CredentialBroker:
    """
    Simulates a secrets broker (e.g., HashiCorp Vault).
    Issues short-lived, resource-scoped session tokens.
    """
    def __init__(self, asg_service_secret: str):
        self._asg_secret = asg_service_secret
        self._sessions: dict[str, dict] = {}

    def authenticate_asg(self, provided_secret: str) -> bool:
        """Verifies the ASG's machine identity (Simulating mTLS client cert)."""
        return provided_secret == self._asg_secret

    def issue_session_token(self, resource_id: str, ttl_seconds: int = 60) -> Optional[str]:
        """Issues a short-lived token scoped to a specific resource."""
        token = str(uuid.uuid4())
        self._sessions[token] = {
            "resource_id": resource_id,
            "expires_at": time.time() + ttl_seconds,
            "hash": hashlib.sha256(f"{token}{resource_id}".encode()).hexdigest()
        }
        return token

    def validate_session(self, token: str, resource_id: str) -> bool:
        """Validates the token and ensures it is scoped to the correct resource."""
        session = self._sessions.get(token)
        if not session:
            return False
        if time.time() > session["expires_at"]:
            del self._sessions[token] # Cleanup expired
            return False
        return session["resource_id"] == resource_id