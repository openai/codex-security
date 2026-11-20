"""Preserve migration receipts from composition previews when opening released history."""

from contextlib import closing

import pytest
from test_workbench_setup_and_migrations import EXPECTED_MIGRATIONS, create_historical_database


@pytest.mark.parametrize(
    "last_preview",
    ["persist scan target executable protection", "persist scan execution sessions"],
)
@pytest.mark.parametrize("first_version", [63, 64, 67])
def test_composition_preview_keeps_receipts_across_released_migrations(
    last_preview: str,
    first_version: int,
) -> None:
    connection, migrate = create_historical_database(first_version)
    preview = [
        (63, "persist composition child membership", "membership"),
        (64, "reuse scan severity assessments", "severity"),
        (65, last_preview, "final"),
        (66, "recover unindexed severity assessments", "unindexed"),
        (67, "repair stored composition membership", "repair"),
        (68, "repair archived composition paths", "paths"),
    ]
    with closing(connection):
        connection.executemany(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            [(version + first_version - 63, name, stamp) for version, name, stamp in preview],
        )
        for _ in range(2):
            migrate(connection)
            rows = connection.execute(
                "SELECT version, name, applied_at FROM schema_migrations WHERE version < 0 "
                "ORDER BY version DESC"
            )
            assert [tuple(row) for row in rows] == [
                (-(version + first_version - 63), name, timestamp)
                for version, name, timestamp in preview
            ]
            assert [
                tuple(row)
                for row in connection.execute(
                    "SELECT version, name FROM schema_migrations WHERE version > 0 ORDER BY version"
                )
            ] == EXPECTED_MIGRATIONS
