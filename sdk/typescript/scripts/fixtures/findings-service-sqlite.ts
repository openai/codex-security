// Assert persisted findings and embeddings in the smoke-test container.
import assert from "node:assert/strict";
import { chmodSync, cpSync, mkdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type { ScanManifest } from "../../src/models.js";

const importedIds = JSON.parse(process.argv[2]!) as string[];
const expectedIds = importedIds.toSorted();
const { scan } = JSON.parse(
  readFileSync(
    "_bundled_plugin/examples/completed-scan/scan-manifest.json",
    "utf8",
  ),
) as ScanManifest;
const db = new DatabaseSync("/state/workbench.sqlite3");
try {
  db.exec("PRAGMA busy_timeout = 5000");
  assert.ok(
    Number(
      db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()![
        "count"
      ],
    ) > 0,
  );
  const findingIds = db
    .prepare("SELECT id FROM findings ORDER BY id")
    .all()
    .map((row) => row["id"]);
  assert.deepEqual(findingIds, expectedIds);
  const embeddings = db
    .prepare(
      "SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id",
    )
    .all();
  assert.deepEqual(
    embeddings.map((row) => row["finding_id"]),
    expectedIds,
  );
  for (const row of embeddings) {
    const vector = JSON.parse(row["vector_json"] as string);
    assert.equal(
      row["model"],
      "text-embedding-3-large",
      row["finding_id"] as string,
    );
    assert.equal(vector.length, 1536, row["finding_id"] as string);
  }
  const associations = db
    .prepare(
      "SELECT repository_id, finding_id FROM finding_repositories ORDER BY repository_id, finding_id",
    )
    .all()
    .map((row) => [row["repository_id"], row["finding_id"]]);
  assert.deepEqual(
    associations,
    [
      ...importedIds.slice(0, 3).map((id) => [scan.target.targetId, id]),
      ["synthetic-other", importedIds[3]!],
    ].sort(),
  );

  if (process.argv.includes("--expect-groups")) {
    assert.equal(
      db.prepare("SELECT COUNT(*) AS count FROM finding_dedupe_groups").get()![
        "count"
      ],
      1,
    );
    const members = db
      .prepare(
        "SELECT finding_id FROM finding_dedupe_group_members ORDER BY finding_id",
      )
      .all();
    assert.deepEqual(
      members.map((row) => row["finding_id"]),
      importedIds.slice(0, 3).sort(),
    );
  }

  if (process.argv.includes("--prepare-scan")) {
    const sourceDir = "/state/smoke-source";
    mkdirSync(sourceDir, { recursive: true });
    const scanDir = "/state/smoke-scan";
    cpSync("_bundled_plugin/examples/completed-scan", scanDir, {
      recursive: true,
    });
    chmodSync(scanDir, 0o700);
    const timestamp = scan.completedAt!;
    db.exec("BEGIN");
    db.prepare(
      "INSERT OR IGNORE INTO workspaces (id, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000001', ?, ?)",
    ).run(timestamp, timestamp);
    db.prepare(
      "INSERT OR IGNORE INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, '00000000-0000-4000-8000-000000000001', ?, 'revision', '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?, ?)",
    ).run(
      scan.id,
      sourceDir,
      scanDir,
      timestamp,
      timestamp,
      timestamp,
      timestamp,
    );
    db.prepare(
      "INSERT OR IGNORE INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
    ).run(scan.id, timestamp);
    db.exec("COMMIT");
  }
} finally {
  db.close();
}
console.log(`Verified ${expectedIds.length} stored findings and embeddings.`);
