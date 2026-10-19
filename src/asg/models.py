from dataclasses import dataclass
from enum import Enum


class Effect(str, Enum):
    """Possible outcomes of an authorization decision."""

    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class AuthorizationRequest:
    """Represents an operation requesting authorization."""

    principal_id: str
    action: str
    resource_id: str

    def __post_init__(self) -> None:
        fields = {
            "principal_id": self.principal_id,
            "action": self.action,
            "resource_id": self.resource_id,
        }

        for field_name, value in fields.items():
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string"
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} must not be empty"
                )


@dataclass(frozen=True)
class AuthorizationDecision:
    """Represents the outcome of an authorization evaluation."""

    effect: Effect
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.effect, Effect):
            raise TypeError(
                "effect must be an Effect enum value"
            )

        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")
