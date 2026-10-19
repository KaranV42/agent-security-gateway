import sqlite3


def create_mock_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute("""
        CREATE TABLE public_data (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE restricted_data (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    connection.execute(
        "INSERT INTO public_data VALUES (?, ?)",
        ("company_name", "Example Company"),
    )

    connection.execute(
        "INSERT INTO restricted_data VALUES (?, ?)",
        ("ceo_salary", "Confidential mock value"),
    )

    connection.commit()
    return connection