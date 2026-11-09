import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from asg.models import AuthorizationRequest, Effect
from asg.policy import DeclarativePolicyEngine, PolicyRule


if __name__ == "__main__":
    request = AuthorizationRequest(
        principal_id="golden-principal",
        action="read",
        resource_id="golden-resource",
    )
    cases = {
        "zero_rules": DeclarativePolicyEngine(),
        "matching_allow": DeclarativePolicyEngine(
            [
                PolicyRule(
                    principal_id="golden-principal",
                    action="read",
                    resource_id="golden-resource",
                    effect=Effect.ALLOW,
                    reason="Matching allow rule",
                )
            ]
        ),
        "nonmatching_allow": DeclarativePolicyEngine(
            [
                PolicyRule(
                    principal_id="other-principal",
                    action="read",
                    resource_id="golden-resource",
                    effect=Effect.ALLOW,
                    reason="Nonmatching allow rule",
                )
            ]
        ),
    }
    result = {
        name: {
            "effect": decision.effect.value,
            "reason": decision.reason,
        }
        for name, engine in cases.items()
        for decision in [engine.evaluate(request)]
    }
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (ROOT / "golden" / "policy.json").write_text(output, encoding="utf-8")
