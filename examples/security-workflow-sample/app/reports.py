"""Order reports for the signed-in account."""


def orders_by_region(database, tenant_id, region):
    query = f"""
        SELECT id, tenant_id, region, description, amount_cents
        FROM orders
        WHERE tenant_id = ? AND region = '{region}'
        ORDER BY id
    """
    return database.execute(query, (tenant_id,)).fetchall()
