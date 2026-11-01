import pytest
from asg.policy import DeclarativePolicyEngine, PolicyRule
from asg.models import AuthorizationRequest, Effect

@pytest.fixture
def engine():
    return DeclarativePolicyEngine()

def test_default_deny_when_no_rules_exist(engine):
    request = AuthorizationRequest("user_1", "read", "public_data")
    decision = engine.evaluate(request)
    assert decision.effect == Effect.DENY
    assert "default" in decision.reason.lower()

def test_explicit_allow_rule(engine):
    engine.add_rule(PolicyRule(
        principal_id="user_1", action="read", resource_id="public_data",
        effect=Effect.ALLOW, reason="Explicit grant."
    ))
    request = AuthorizationRequest("user_1", "read", "public_data")
    decision = engine.evaluate(request)
    assert decision.effect == Effect.ALLOW

def test_wildcard_principal_rule(engine):
    # Rule: Anyone can read public_data
    engine.add_rule(PolicyRule(
        principal_id=None, action="read", resource_id="public_data",
        effect=Effect.ALLOW, reason="Public resource."
    ))
    
    req_user1 = AuthorizationRequest("user_1", "read", "public_data")
    req_user2 = AuthorizationRequest("user_99", "read", "public_data")
    
    assert engine.evaluate(req_user1).effect == Effect.ALLOW
    assert engine.evaluate(req_user2).effect == Effect.ALLOW

def test_first_match_wins(engine):
    engine.add_rule(PolicyRule(
        principal_id="user_1", action="read", resource_id="data",
        effect=Effect.DENY, reason="Specific deny."
    ))
    engine.add_rule(PolicyRule(
        principal_id="user_1", action="read", resource_id=None,
        effect=Effect.ALLOW, reason="General allow."
    ))
    
    request = AuthorizationRequest("user_1", "read", "data")
    decision = engine.evaluate(request)
    
    assert decision.effect == Effect.DENY
    assert decision.reason == "Specific deny."

def test_dynamic_rule_update(engine):
    """Proves that adding a rule at runtime changes behavior without restart."""
    request = AuthorizationRequest("user_2", "read", "restricted_data")
    
    # Initially denied
    assert engine.evaluate(request).effect == Effect.DENY
    
    # Dynamically add rule
    engine.add_rule(PolicyRule(
        principal_id="user_2", action="read", resource_id="restricted_data",
        effect=Effect.ALLOW, reason="Temporary access granted."
    ))
    
    # Now allowed
    decision = engine.evaluate(request)
    assert decision.effect == Effect.ALLOW