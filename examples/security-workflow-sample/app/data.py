"""Process-local order data for the sample API."""

import sqlite3

TOKENS = {
    "demo-acme": "acme",
    "demo-beacon": "beacon",
    "demo-cedar": "cedar",
}

ORDERS = [
    ("A-101", "acme", "west", "Acme-only notebook", 1200),
    ("A-102", "acme", "east", "Acme-only pen", 300),
    ("B-201", "beacon", "west", "Beacon-only lamp", 4200),
    ("B-202", "beacon", "east", "Beacon-only chair", 7800),
    ("C-301", "cedar", "west", "Cedar-only mug", 900),
    ("C-302", "cedar", "east", "Cedar-only desk", 11900),
]


def create_database():
    database = sqlite3.connect(":memory:", check_same_thread=False)
    database.row_factory = sqlite3.Row
    database.execute(
        """
        CREATE TABLE orders (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            region TEXT NOT NULL,
            description TEXT NOT NULL,
            amount_cents INTEGER NOT NULL
        )
        """
    )
    database.executemany(
        "INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
        ORDERS,
    )
    database.commit()
    return database


def list_orders(database, tenant_id):
    return database.execute(
        """
        SELECT id, tenant_id, region, description, amount_cents
        FROM orders WHERE tenant_id = ? ORDER BY id
        """,
        (tenant_id,),
    ).fetchall()


def lookup_order(database, order_id):
    return database.execute(
        """
        SELECT id, tenant_id, region, description, amount_cents
        FROM orders WHERE id = ?
        """,
        (order_id,),
    ).fetchone()
