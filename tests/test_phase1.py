import pytest
from asg.database import create_mock_database
from asg.executor import ControlledToolExecutor, ExecutorInputError
from asg.broker import CredentialBroker

TEST_SECRET = "test-secret"

@pytest.fixture
def executor_and_broker():
    connection = create_mock_database()
    broker = CredentialBroker(asg_service_secret=TEST_SECRET)
    yield ControlledToolExecutor(connection, broker), broker
    connection.close()

def test_reads_market_data(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("market_data")
    assert executor.execute_tool("read_market_data", {"table_name": "market_data"}, token)[0]["symbol"] == "AAPL"

def test_rejects_unknown_tool(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("market_data")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("delete_all_data", {}, token)

def test_rejects_unknown_table(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("market_data")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("read_market_data", {"table_name": "unknown_table"}, token)

def test_rejects_raw_sql_input(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("market_data")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("read_market_data", {"table_name": "market_data; DROP TABLE market_data;"}, token)

def test_rejects_extra_arguments(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("market_data")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("read_market_data", {"table_name": "market_data", "sql": "DROP TABLE market_data"}, token)