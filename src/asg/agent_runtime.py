import json

from asg.executor import ControlledToolExecutor


def mock_agent_request() -> dict:
    # Deterministic stand-in for an LLM-generated tool call.
    return json.loads("""
    {
        "tool": "read_database",
        "args": {
            "table_name": "public_data"
        }
    }
    """)


def run_agent(executor: ControlledToolExecutor) -> list[dict]:
    request = mock_agent_request()

    return executor.execute_tool(
        request["tool"],
        request["args"],
    )