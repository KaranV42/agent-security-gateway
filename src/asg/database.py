import sqlite3

def create_mock_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.row_factory = sqlite3.Row
    
    connection.execute("""
        CREATE TABLE market_data (
            symbol TEXT PRIMARY KEY,
            price REAL NOT NULL,
            volume INTEGER NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE client_pii (
            client_id TEXT PRIMARY KEY,
            ssn TEXT NOT NULL,
            net_worth REAL NOT NULL
        )
    """)
    connection.execute("INSERT INTO market_data VALUES (?, ?, ?)", ("AAPL", 150.25, 1000000))
    connection.execute("INSERT INTO client_pii VALUES (?, ?, ?)", ("C-9901", "123-45-6789", 2500000.00))
    connection.commit()
    return connection