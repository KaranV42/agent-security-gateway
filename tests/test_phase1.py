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

def test_reads_public_records(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("public_records")
    assert executor.execute_tool("read_data", {"resource_id": "public_records"}, token)[0]["record_id"] == "public-001"

def test_rejects_unknown_tool(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("public_records")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("delete_all_data", {}, token)

def test_rejects_unknown_resource(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("public_records")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("read_data", {"resource_id": "unknown_resource"}, token)

def test_rejects_raw_sql_input(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("public_records")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("read_data", {"resource_id": "public_records'; DROP TABLE public_records;--"}, token)

def test_rejects_extra_arguments(executor_and_broker):
    executor, broker = executor_and_broker
    token = broker.issue_session_token("public_records")
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("read_data", {"resource_id": "public_records", "sql": "DROP TABLE public_records"}, token)