import sqlite3

def create_mock_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.row_factory = sqlite3.Row
    
    connection.execute("""
        CREATE TABLE public_records (
            record_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE restricted_records (
            record_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)
    connection.execute(
        "INSERT INTO public_records VALUES (?, ?, ?)",
        ("public-001", "Example public record", "Synthetic public content"),
    )
    connection.execute(
        "INSERT INTO restricted_records VALUES (?, ?, ?)",
        ("restricted-001", "Example restricted record", "Synthetic restricted content"),
    )
    connection.commit()
    return connection