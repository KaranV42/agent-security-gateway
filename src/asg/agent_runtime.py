"""Mock agent runtime — requests tools through the ASG only."""

import json

from asg.gateway import ASGGateway


def mock_agent_request() -> dict:
    """Simulate an LLM-generated tool request."""
    return json.loads("""
    {
        "tool": "read_database",
        "args": {
            "table_name": "public_data"
        }
    }
    """)


def run_agent(gateway: ASGGateway) -> list[dict]:
    """Execute the agent's tool request through the gateway."""
    request = mock_agent_request()

    return gateway.execute_tool(
        request["tool"],
        request["args"],
    )