
import pytest

from asg.models import (
    AuthorizationRequest,
    AuthorizationDecision,
    Effect,
)


class TestAuthorizationRequest:
    def test_valid_request(self):
        request = AuthorizationRequest(
            principal_id="agent_01",
            action="read",
            resource_id="public.txt",
        )

        assert request.principal_id == "agent_01"
        assert request.action == "read"
        assert request.resource_id == "public.txt"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("principal_id", ""),
            ("principal_id", "   "),
            ("action", ""),
            ("action", "   "),
            ("resource_id", ""),
            ("resource_id", "   "),
        ],
    )
    def test_rejects_empty_fields(self, field, value):
        values = {
            "principal_id": "agent_01",
            "action": "read",
            "resource_id": "public.txt",
        }
        values[field] = value

        with pytest.raises(ValueError):
            AuthorizationRequest(**values)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("principal_id", None),
            ("action", 123),
            ("resource_id", ["public.txt"]),
        ],
    )
    def test_rejects_invalid_types(self, field, value):
        values = {
            "principal_id": "agent_01",
            "action": "read",
            "resource_id": "public.txt",
        }
        values[field] = value

        with pytest.raises(TypeError):
            AuthorizationRequest(**values)

    def test_request_is_immutable(self):
        request = AuthorizationRequest(
            principal_id="agent_01",
            action="read",
            resource_id="public.txt",
        )

        with pytest.raises(AttributeError):
            request.action = "delete"


class TestAuthorizationDecision:
    def test_valid_allow_decision(self):
        decision = AuthorizationDecision(
            effect=Effect.ALLOW,
            reason="Policy permits this operation",
        )

        assert decision.effect is Effect.ALLOW

    def test_valid_deny_decision(self):
        decision = AuthorizationDecision(
            effect=Effect.DENY,
            reason="Insufficient permissions",
        )

        assert decision.effect is Effect.DENY

    def test_rejects_string_instead_of_effect(self):
        with pytest.raises(TypeError):
            AuthorizationDecision(
                effect="ALLOW",
                reason="Policy permits this operation",
            )

    def test_rejects_empty_reason(self):
        with pytest.raises(ValueError):
            AuthorizationDecision(
                effect=Effect.DENY,
                reason="   ",
            )

    def test_decision_is_immutable(self):
        decision = AuthorizationDecision(
            effect=Effect.DENY,
            reason="Insufficient permissions",
        )

        with pytest.raises(AttributeError):
            decision.effect = Effect.ALLOW
