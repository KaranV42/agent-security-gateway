from dataclasses import dataclass
from typing import Optional, FrozenSet

class ToolValidationError(ValueError):
    """Raised when a tool request fails schema validation."""
    pass

@dataclass(frozen=True)
class ToolSchema:
    """Defines the validation rules for a specific tool."""
    required_args: FrozenSet[str]
    resource_arg: Optional[str] = None
    allowed_resources: Optional[FrozenSet[str]] = None

class ToolRegistry:
    """Maintains the authoritative list of permitted tools and their schemas."""
    
    def __init__(self) -> None:
        self._schemas: dict[str, ToolSchema] = {}

    def register(self, tool_name: str, schema: ToolSchema) -> None:
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("Tool name must be a non-empty string.")
        self._schemas[tool_name] = schema

    def validate(self, tool_name: str, args: dict) -> None:
        """
        Validates the tool name and arguments against the registry.
        Raises ToolValidationError on any failure.
        """
        schema = self._schemas.get(tool_name)
        if schema is None:
            raise ToolValidationError(f"Unknown tool: {tool_name}")

        if not isinstance(args, dict):
            raise ToolValidationError("Arguments must be a dictionary.")

        provided_args = set(args.keys())
        
        # Check for missing required arguments
        missing = schema.required_args - provided_args
        if missing:
            raise ToolValidationError(f"Missing required arguments: {missing}")

        # Check for unexpected arguments
        unexpected = provided_args - schema.required_args
        if unexpected:
            raise ToolValidationError(f"Unexpected arguments: {unexpected}")

        # Check resource allowlist if defined
        if schema.resource_arg and schema.allowed_resources is not None:
            resource_value = args.get(schema.resource_arg)
            if resource_value not in schema.allowed_resources:
                raise ToolValidationError(
                    f"Resource '{resource_value}' is not permitted for tool '{tool_name}'."
                )