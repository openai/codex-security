"""Synthetic scheduled analytics worker with no HTTP listener."""

import sqlite3


def summarize_orders(database, tenant_id):
    return database.execute(
        "SELECT COUNT(*) FROM orders WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()[0]


def legacy_region_export(database, region):
    query = f"SELECT * FROM orders WHERE region = '{region}'"
    return database.execute(query).fetchall()


def handler(_event, _context):
    """Scheduled Lambda entry point that never calls the legacy export."""
    database = sqlite3.connect(":memory:")
    try:
        database.execute("CREATE TABLE orders (tenant_id TEXT, region TEXT)")
        database.executemany(
            "INSERT INTO orders VALUES (?, ?)",
            [("acme", "west"), ("acme", "east"), ("beacon", "west")],
        )
        return {"acme_order_count": summarize_orders(database, "acme")}
    finally:
        database.close()
