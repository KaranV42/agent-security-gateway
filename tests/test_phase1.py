import pytest

from asg.database import create_mock_database
from asg.executor import (
    ControlledToolExecutor,
    ExecutorInputError,
)


@pytest.fixture
def executor():
    connection = create_mock_database()
    yield ControlledToolExecutor(connection)
    connection.close()


def test_reads_public_data(executor):
    assert executor.execute_tool(
        "read_database",
        {"table_name": "public_data"},
    ) == [
        {"key": "company_name", "value": "Example Company"}
    ]


def test_reads_restricted_data_in_phase1(executor):
    # Authorization is deliberately not implemented yet.
    assert executor.execute_tool(
        "read_database",
        {"table_name": "restricted_data"},
    )[0]["key"] == "ceo_salary"


def test_rejects_unknown_tool(executor):
    with pytest.raises(ExecutorInputError):
        executor.execute_tool("delete_all_data", {})


def test_rejects_unknown_table(executor):
    with pytest.raises(ExecutorInputError):
        executor.execute_tool(
            "read_database",
            {"table_name": "unknown_table"},
        )


def test_rejects_raw_sql_input(executor):
    with pytest.raises(ExecutorInputError):
        executor.execute_tool(
            "read_database",
            {"table_name": "public_data; DROP TABLE public_data;"},
        )


def test_rejects_extra_arguments(executor):
    with pytest.raises(ExecutorInputError):
        executor.execute_tool(
            "read_database",
            {
                "table_name": "public_data",
                "sql": "DROP TABLE public_data",
            },
        )