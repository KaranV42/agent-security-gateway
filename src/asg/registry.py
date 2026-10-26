from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, FrozenSet, Any

class ToolValidationError(ValueError):
    pass

@dataclass(frozen=True)
class ToolSchema:
    """Defines the validation rules and metadata for a specific tool."""
    description: str = "Execute tool operation."
    required_args: FrozenSet[str] = field(default_factory=frozenset)
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
        schema = self._schemas.get(tool_name)
        if schema is None:
            raise ToolValidationError(f"Unknown tool: {tool_name}")

        if not isinstance(args, dict):
            raise ToolValidationError("Arguments must be a dictionary.")

        provided_args = set(args.keys())
        missing = schema.required_args - provided_args
        if missing:
            raise ToolValidationError(f"Missing required arguments: {missing}")

        unexpected = provided_args - schema.required_args
        if unexpected:
            raise ToolValidationError(f"Unexpected arguments: {unexpected}")

        if schema.resource_arg and schema.allowed_resources is not None:
            resource_value = args.get(schema.resource_arg)
            if resource_value not in schema.allowed_resources:
                raise ToolValidationError(
                    f"Resource '{resource_value}' is not permitted for tool '{tool_name}'."
                )

    def get_openai_tools_schema(self) -> list[dict[str, Any]]:
        """Exports registered tools in OpenAI-compatible function calling format."""
        tools = []
        for name, schema in self._schemas.items():
            properties = {}
            if schema.resource_arg and schema.allowed_resources:
                properties[schema.resource_arg] = {
                    "type": "string",
                    "description": f"Target resource for the operation.",
                    "enum": list(schema.allowed_resources)
                }
            
            # Add any other required args not covered by resource_arg
            for arg in schema.required_args:
                if arg != schema.resource_arg:
                    properties[arg] = {"type": "string", "description": f"Argument: {arg}"}

            tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": schema.description,
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": list(schema.required_args)
                    }
                }
            })
        return tools