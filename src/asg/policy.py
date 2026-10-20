from asg.models import AuthorizationRequest, AuthorizationDecision, Effect

class PolicyEvaluator:
    """Evaluates authorization requests against a defined policy."""
    
    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """
        Evaluates the request against the prototype policy matrix.
        """
        # Admin policy (user_1)
        if request.principal_id == "user_1":
            if request.action == "read" and request.resource_id in ("public_data", "restricted_data"):
                return AuthorizationDecision(Effect.ALLOW, "Admin access granted.")
        
        # Viewer policy (user_2)
        if request.principal_id == "user_2":
            if request.action == "read" and request.resource_id == "public_data":
                return AuthorizationDecision(Effect.ALLOW, "Viewer access granted.")
            if request.action == "read" and request.resource_id == "restricted_data":
                return AuthorizationDecision(Effect.DENY, "Viewers cannot access restricted data.")
                
        # Default deny for unknown or unauthorized principals
        return AuthorizationDecision(Effect.DENY, "Access denied by default policy.")