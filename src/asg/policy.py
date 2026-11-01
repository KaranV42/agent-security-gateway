from dataclasses import dataclass
from typing import List, Optional
from asg.models import AuthorizationRequest, AuthorizationDecision, Effect

@dataclass(frozen=True)
class PolicyRule:
    """
    A single declarative rule. 
    If a field is None, it acts as a wildcard for that attribute.
    """
    principal_id: Optional[str] = None
    action: Optional[str] = None
    resource_id: Optional[str] = None
    effect: Effect = Effect.DENY
    reason: str = "Default deny"

class DeclarativePolicyEngine:
    """
    Evaluates authorization requests against a configurable list of rules.
    Uses a first-match-wins strategy with a strict default-deny fallback.
    """
    
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        # Initialize with a default deny-all rule if no rules are provided
        self._rules: List[PolicyRule] = rules if rules is not None else []

    def add_rule(self, rule: PolicyRule) -> None:
        """Dynamically adds a rule to the engine (simulating a DB update)."""
        self._rules.append(rule)

    def clear_rules(self) -> None:
        """Removes all rules, reverting to strict default-deny."""
        self._rules.clear()

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """
        Evaluates the request against the rule set.
        Returns the first matching rule's decision.
        """
        for rule in self._rules:
            if self._matches(rule, request):
                return AuthorizationDecision(
                    effect=rule.effect,
                    reason=rule.reason
                )
        
        # Strict default-deny if no rules match
        return AuthorizationDecision(
            effect=Effect.DENY,
            reason="No matching policy rule found; access denied by default."
        )

    def _matches(self, rule: PolicyRule, request: AuthorizationRequest) -> bool:
        """Checks if a request satisfies all non-wildcard fields of a rule."""
        if rule.principal_id is not None and rule.principal_id != request.principal_id:
            return False
        if rule.action is not None and rule.action != request.action:
            return False
        if rule.resource_id is not None and rule.resource_id != request.resource_id:
            return False
        return True