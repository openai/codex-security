"""Check upgrades of workbench databases with native investigation allowances."""

from contextlib import closing

import pytest
from test_workbench_setup_and_migrations import (
    create_historical_database,
    insert_historical_row,
    insert_legacy_scan,
    record_migration,
)


@pytest.mark.cross_platform
@pytest.mark.parametrize("preview_slot", [63, 64, 67, 73, None])
def test_allowance_preview_retains_policy_and_applies_canonical_usage_migration(
    preview_slot: int | None,
) -> None:
    db, migrate = create_historical_database(preview_slot or 64)
    with closing(db):
        timestamp = "2026-01-01T00:00:00Z"
        db.execute("ALTER TABLE scans ADD COLUMN investigation_policy TEXT")
        # A released main reader has already replaced this receipt, leaving the column intact.
        if preview_slot is not None:
            record_migration(
                db, preview_slot, "retain native investigation time allowances", timestamp
            )
        insert_historical_row(db, "workspaces", timestamp, id="legacy-workspace")
        insert_legacy_scan(db, timestamp, investigation_policy="saved policy")
        migrate(db)
        allowance = db.execute(
            "SELECT name, applied_at FROM schema_migrations WHERE version = 81"
        ).fetchone()
        assert allowance["name"] == "retain native investigation time allowances"
        if preview_slot is not None:
            assert allowance["applied_at"] == timestamp
        query = "SELECT name, applied_at FROM schema_migrations WHERE version = 63"
        receipt = db.execute(query).fetchone()
        assert receipt["name"] == "retain unverified Deep Scan worker attempts"
        assert db.execute("SELECT count(worker_usage_gap) FROM deep_scan_runs").fetchone()[0] == 0
        migrate(db)
        assert db.execute(query).fetchone() == receipt
        assert db.execute("SELECT investigation_policy FROM scans").fetchone()[0] == "saved policy"
