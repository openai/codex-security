import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const migrationProbe = String.raw`
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])

from workbench_schema import MIGRATIONS, apply_migrations
from workbench_target_state import backfill_security_targets, stable_target_id

scenario = sys.argv[2]
root = Path(sys.argv[3])
timestamp = "2026-08-01T00:00:00Z"
backfill_calls = []

def backfill(connection):
    backfill_calls.append(True)
    backfill_security_targets(connection)

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)
backfill_calls.clear()

existing_path = str(root / "existing-repository")
missing_path = str(root / "deleted-repository")
connection.execute(
    "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    ("target-existing", existing_path, "existing-repository", timestamp, timestamp),
)
connection.executemany(
    "INSERT INTO workspaces (id, target_path, target_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    [
        ("workspace-existing", existing_path, "target-existing", timestamp, timestamp),
        ("workspace-empty", None, None, timestamp, timestamp),
    ],
)

def insert_scan(scan_id, workspace_id, target_path, target_id):
    connection.execute(
        "INSERT INTO scans (id, workspace_id, target_path, target_id, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            workspace_id,
            target_path,
            target_id,
            "synthetic-revision",
            ".",
            "standard",
            str(root / scan_id),
            "complete",
            "reporting",
            timestamp,
            timestamp,
            timestamp,
        ),
    )

insert_scan("scan-existing", "workspace-existing", existing_path, "target-existing")

if scenario == "orphan-scan":
    insert_scan("scan-orphan", "workspace-existing", existing_path, None)
    expected_target_id = "target-existing"
    orphan_path = existing_path
elif scenario in ("dangling-scan", "dangling-workspace", "dangling-targets"):
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    if scenario != "dangling-scan":
        connection.execute(
            "INSERT INTO workspaces (id, target_path, target_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("workspace-orphan", missing_path, "target-dangling", timestamp, timestamp),
        )
    if scenario != "dangling-workspace":
        workspace = (
            "workspace-existing" if scenario == "dangling-scan" else "workspace-orphan"
        )
        insert_scan("scan-orphan", workspace, missing_path, "target-dangling")
    connection.commit()
    connection.execute("PRAGMA foreign_keys = ON")
    expected_target_id = stable_target_id(Path(missing_path))
    orphan_path = missing_path
else:
    connection.execute(
        "INSERT INTO workspaces (id, target_path, target_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("workspace-orphan", missing_path, None, timestamp, timestamp),
    )
    expected_target_id = stable_target_id(Path(missing_path))
    orphan_path = missing_path
    if scenario == "orphan-workspace-and-scan":
        insert_scan("scan-orphan", "workspace-orphan", missing_path, None)

connection.commit()
violations_before_repair = len(connection.execute("PRAGMA foreign_key_check").fetchall())
apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)
apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)

def target_id(table, row_id):
    row = connection.execute(
        f"SELECT target_id FROM {table} WHERE id = ?", (row_id,)
    ).fetchone()
    return row["target_id"] if row is not None else None

print(json.dumps({
    "backfillCalls": len(backfill_calls),
    "emptyWorkspaceTargetId": target_id("workspaces", "workspace-empty"),
    "existingScanTargetId": target_id("scans", "scan-existing"),
    "existingWorkspaceTargetId": target_id("workspaces", "workspace-existing"),
    "expectedTargetId": expected_target_id,
    "foreignKeysEnforced": bool(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
    "foreignKeyViolationsBeforeRepair": violations_before_repair,
    "foreignKeyViolationsAfterRepair": len(
        connection.execute("PRAGMA foreign_key_check").fetchall()
    ),
    "migrationRecorded": connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 16"
    ).fetchone()[0] == "stable repository targets",
    "orphanPathExists": Path(orphan_path).exists(),
    "orphanScanTargetId": target_id("scans", "scan-orphan"),
    "orphanWorkspaceTargetId": target_id("workspaces", "workspace-orphan"),
    "targetCount": connection.execute(
        "SELECT count(*) FROM security_targets"
    ).fetchone()[0],
}))
`;

const repositoryIdentityMigrationProbe = String.raw`
import json
import sqlite3
import sys

sys.path.insert(0, sys.argv[1])

from workbench_schema import MIGRATIONS, apply_migrations, sql_statements
from workbench_target_state import backfill_security_targets

scenario = sys.argv[2]
timestamp = "2026-08-01T00:00:00Z"
backfill_calls = []

def backfill(connection):
    backfill_calls.append(True)
    backfill_security_targets(connection)

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
identity_migration = next(
    migration for migration in MIGRATIONS if migration[1] == "persist repository identities"
)
identity_version = identity_migration[0]
legacy_identity_migration = (
    30, "persist repository identities",
    "ALTER TABLE security_targets ADD COLUMN repository_identity TEXT;\n"
    "CREATE INDEX security_targets_by_repository_identity ON security_targets(repository_identity);\n",
)
historical = tuple(migration for migration in MIGRATIONS if migration[0] <= 28)
published = tuple(
    migration for migration in MIGRATIONS
    if migration[0] < (
        31 if scenario == "pre-release-identity-version31" else
        33 if scenario == "pre-release-identity-version33" else identity_version
    )
)
apply_migrations(
    connection,
    historical if scenario in (
        "out-of-order-publication-migrations", "pre-release-identity-version"
    ) else published,
    lambda: timestamp,
    backfill,
)
backfill_calls.clear()
connection.execute(
    "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    ("target-existing", "/synthetic/deleted-repository", "repository", timestamp, timestamp),
)

if scenario == "recorded-without-column":
    connection.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, ?)",
        (identity_version, "persist repository identities", timestamp),
    )
elif scenario == "recorded-without-index":
    connection.execute(
        "ALTER TABLE security_targets ADD COLUMN repository_identity TEXT"
    )
    connection.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, ?)",
        (identity_version, "persist repository identities", timestamp),
    )

connection.commit()
if scenario == "out-of-order-publication-migrations":
    apply_migrations(
        connection, (*historical, identity_migration), lambda: timestamp, backfill
    )
elif scenario in ("pre-release-identity-version", "pre-release-identity-version31"):
    if scenario == "pre-release-identity-version":
        apply_migrations(
            connection,
            (*historical, legacy_identity_migration),
            lambda: timestamp,
            backfill,
        )
    else:
        connection.executescript(legacy_identity_migration[2])
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            (31, legacy_identity_migration[1], timestamp),
        )
    connection.execute(
        "UPDATE security_targets SET repository_identity = 'synthetic-identity'"
    )
elif scenario == "pre-release-identity-version33":
    for statement in sql_statements(identity_migration[2]):
        connection.execute(statement)
    connection.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, ?)",
        (33, identity_migration[1], timestamp),
    )
    connection.execute(
        "UPDATE security_targets SET repository_identity = 'synthetic-identity'"
    )
apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)
apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)

columns = {
    row["name"]: row
    for row in connection.execute("PRAGMA table_info(security_targets)")
}
indexes = {
    row["name"]: row
    for row in connection.execute("PRAGMA index_list(security_targets)")
}
scan_columns = {
    row["name"]: row for row in connection.execute("PRAGMA table_info(scans)")
}
scan_indexes = {
    row["name"]: row for row in connection.execute("PRAGMA index_list(scans)")
}
print(json.dumps({
    "backfillCalls": len(backfill_calls),
    "hasRepositoryIdentityColumn": "repository_identity" in columns,
    "hasRepositoryIdentityIndex": "security_targets_by_repository_identity" in indexes,
    "identityVersion": identity_version,
    "hasCurrentFindingsSchema": (
        any(row["name"] == "details_json" for row in connection.execute("PRAGMA table_info(findings)"))
        and connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'finding_embeddings'").fetchone() is not None
    ),
    "publicationMigrations": {
        str(row["version"]): row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (29, 30)"
        )
    },
    "teamOnlyPublicationIndexes": sorted(
        row["name"]
        for row in connection.execute("PRAGMA index_list(finding_publications)")
        if row["name"].startswith("finding_publications_team_only_") and row["unique"]
    ),
    "repositoryIdentityColumnIsNullable": not bool(
        columns["repository_identity"]["notnull"]
    ),
    "repositoryIdentityIndexIsUnique": bool(
        indexes["security_targets_by_repository_identity"]["unique"]
    ),
    "hasRepositoryGenerationColumn": "repository_generation" in scan_columns,
    "hasRepositoryGenerationIndex": "scans_by_repository_generation" in scan_indexes,
    "repositoryGenerationColumnIsNullable": not bool(
        scan_columns["repository_generation"]["notnull"]
    ),
    "completionSequenceIsNullable": not bool(
        scan_columns["completion_sequence"]["notnull"]
    ),
    "completionSequenceIndexIsUnique": bool(
        scan_indexes["scans_completion_sequence"]["unique"]
    ),
    "completionSequenceTriggers": sorted(row["name"] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' "
        "AND name LIKE 'scans_assign_%_completion_sequence'"
    )),
    "migrationName": connection.execute(
        "SELECT name FROM schema_migrations WHERE version = ?", (identity_version,)
    ).fetchone()[0],
    "targetIdentity": connection.execute(
        "SELECT repository_identity FROM security_targets"
    ).fetchone()[0],
    "targetId": connection.execute(
        "SELECT id FROM security_targets"
    ).fetchone()[0],
}))
`;

describe("stable workbench target migration", () => {
  test.each([
    ["orphan-scan", "reuses an existing target for an orphaned scan"],
    ["orphan-workspace", "repairs a workspace without an orphaned scan"],
    ["dangling-scan", "repairs a dangling scan foreign key independently"],
    [
      "dangling-workspace",
      "repairs a dangling workspace foreign key independently",
    ],
    [
      "dangling-targets",
      "repairs dangling workspace and scan foreign keys atomically",
    ],
    [
      "orphan-workspace-and-scan",
      "repairs a workspace and scan after their repository is deleted",
    ],
  ] as const)("%s: %s", (scenario) => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null) throw new Error("A Python interpreter is required.");

    const execution = spawnSync(
      python,
      [
        "-I",
        "-B",
        "-c",
        migrationProbe,
        join(PLUGIN_ROOT, "scripts"),
        scenario,
        join(tmpdir(), "codex-security-stable-target-migration", scenario),
      ],
      { encoding: "utf8", timeout: 10_000 },
    );

    expect(execution.status, execution.stderr).toBe(0);
    expect(execution.stderr).toBe("");

    const result = JSON.parse(execution.stdout) as {
      backfillCalls: number;
      emptyWorkspaceTargetId: string | null;
      existingScanTargetId: string;
      existingWorkspaceTargetId: string;
      expectedTargetId: string;
      foreignKeysEnforced: boolean;
      foreignKeyViolationsBeforeRepair: number;
      foreignKeyViolationsAfterRepair: number;
      migrationRecorded: boolean;
      orphanPathExists: boolean;
      orphanScanTargetId: string | null;
      orphanWorkspaceTargetId: string | null;
      targetCount: number;
    };

    expect(result).toMatchObject({
      backfillCalls: 1,
      emptyWorkspaceTargetId: null,
      existingScanTargetId: "target-existing",
      existingWorkspaceTargetId: "target-existing",
      foreignKeysEnforced: true,
      foreignKeyViolationsBeforeRepair:
        scenario === "dangling-targets"
          ? 2
          : scenario.startsWith("dangling-")
            ? 1
            : 0,
      foreignKeyViolationsAfterRepair: 0,
      migrationRecorded: true,
      orphanPathExists: false,
      targetCount: scenario === "orphan-scan" ? 1 : 2,
    });
    expect(result.orphanScanTargetId).toBe(
      scenario === "orphan-workspace" || scenario === "dangling-workspace"
        ? null
        : result.expectedTargetId,
    );
    expect(result.orphanWorkspaceTargetId).toBe(
      scenario === "orphan-scan" || scenario === "dangling-scan"
        ? null
        : result.expectedTargetId,
    );
  });

  test.each([
    [
      "unapplied",
      "applies and backfills the new repository-identity migration",
    ],
    [
      "recorded-without-column",
      "repairs a recorded migration missing its column and index",
    ],
    [
      "recorded-without-index",
      "repairs a recorded migration missing only its index",
    ],
    [
      "out-of-order-publication-migrations",
      "applies published migrations after repository identity was recorded",
    ],
    [
      "pre-release-identity-version",
      "quarantines an unverifiable pre-release identity without changing its target",
    ],
    [
      "pre-release-identity-version31",
      "repairs an already-renumbered pre-release identity migration",
    ],
    [
      "pre-release-identity-version33",
      "preserves the previous identity migration and installs the current findings schema",
    ],
  ] as const)("%s: %s", (scenario) => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null) throw new Error("A Python interpreter is required.");

    const execution = spawnSync(
      python,
      [
        "-I",
        "-B",
        "-c",
        repositoryIdentityMigrationProbe,
        join(PLUGIN_ROOT, "scripts"),
        scenario,
      ],
      { encoding: "utf8", timeout: 10_000 },
    );

    expect(execution.status, execution.stderr).toBe(0);
    expect(execution.stderr).toBe("");
    const result = JSON.parse(execution.stdout) as {
      backfillCalls: number;
      hasRepositoryIdentityColumn: boolean;
      hasRepositoryIdentityIndex: boolean;
      identityVersion: number;
      hasCurrentFindingsSchema: boolean;
      migrationName: string;
      publicationMigrations: Record<string, string>;
      repositoryIdentityColumnIsNullable: boolean;
      repositoryIdentityIndexIsUnique: boolean;
      hasRepositoryGenerationColumn: boolean;
      hasRepositoryGenerationIndex: boolean;
      repositoryGenerationColumnIsNullable: boolean;
      completionSequenceIsNullable: boolean;
      completionSequenceIndexIsUnique: boolean;
      completionSequenceTriggers: string[];
      targetIdentity: string | null;
      targetId: string;
      teamOnlyPublicationIndexes: string[];
    };
    expect(result).toEqual({
      backfillCalls: scenario.startsWith("pre-release-identity-version")
        ? 0
        : 1,
      hasRepositoryIdentityColumn: true,
      hasRepositoryIdentityIndex: true,
      identityVersion: 40,
      hasCurrentFindingsSchema: true,
      migrationName: "persist repository identities",
      publicationMigrations: {
        "29": "persist finding publication associations",
        "30": "preserve team-only finding publication associations",
      },
      repositoryIdentityColumnIsNullable: true,
      repositoryIdentityIndexIsUnique: false,
      hasRepositoryGenerationColumn: true,
      hasRepositoryGenerationIndex: true,
      repositoryGenerationColumnIsNullable: true,
      completionSequenceIsNullable: true,
      completionSequenceIndexIsUnique: true,
      completionSequenceTriggers: [
        "scans_assign_inserted_completion_sequence",
        "scans_assign_updated_completion_sequence",
      ],
      targetIdentity:
        scenario === "pre-release-identity-version33"
          ? "synthetic-identity"
          : null,
      targetId: "target-existing",
      teamOnlyPublicationIndexes: [
        "finding_publications_team_only_external_issue",
        "finding_publications_team_only_occurrence",
      ],
    });
  });
});
