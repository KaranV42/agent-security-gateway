import pytest

from asg.broker import CredentialBroker
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor, ExecutorInputError


def test_executor_rejects_session_for_different_tool_resource():
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret="test-secret")
    executor = ControlledToolExecutor(connection, broker)
    token = broker.issue_session_token("market_data")

    try:
        with pytest.raises(ExecutorInputError):
            executor.execute_tool(
                "read_client_pii",
                {"table_name": "market_data"},
                token,
            )
    finally:
        connection.close()
