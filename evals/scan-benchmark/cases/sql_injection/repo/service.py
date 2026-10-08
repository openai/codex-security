import sqlite3


def unsafe_lookup(database: sqlite3.Connection, user_name: str):
    return database.execute(f"SELECT id FROM users WHERE name = '{user_name}'").fetchall()


def safe_lookup(database: sqlite3.Connection, user_name: str):
    return database.execute("SELECT id FROM users WHERE name = ?", (user_name,)).fetchall()
