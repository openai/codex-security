// Prepare a synthetic runner scan or check its saved workflows and reviews.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { ScanManifest } from "../../src/models.js";

const packageRoot = "/usr/local/lib/node_modules/@openai/codex-security";
const exampleDir = join(packageRoot, "_bundled_plugin/examples/completed-scan");
const { scan } = JSON.parse(
  readFileSync(join(exampleDir, "scan-manifest.json"), "utf8"),
) as ScanManifest;
// Keep database initialization and migrations in the existing workbench.
const { databasePath } = JSON.parse(
  execFileSync(
    "python3",
    [
      "-I",
      "-B",
      join(packageRoot, "_bundled_plugin/scripts/workbench_db.py"),
      "database-info",
    ],
    { encoding: "utf8" },
  ),
) as { databasePath: string };
const db = new DatabaseSync(databasePath);
try {
  db.exec("PRAGMA busy_timeout = 5000");
  if (process.argv[2] === "--check-workflows") {
    const importedIds = JSON.parse(process.argv[3]!) as string[];
    const workflows = db
      .prepare("SELECT dedupe_status, results_json FROM finding_workflows")
      .all();
    assert.equal(workflows.length, 2);
    for (const row of workflows) {
      const results = JSON.parse(row["results_json"] as string);
      assert.equal(row["dedupe_status"], "completed");
      assert.deepEqual(results.dedupe.duplicateGroups, [
        importedIds.slice(0, 3),
      ]);
      assert.ok(!("dedupePendingWrite" in results));
    }
    const reviews = db
      .prepare(
        "SELECT model, source_content_digest, prompt_digest, contract_digest, result_json FROM finding_workflow_reviews",
      )
      .all();
    const models = new Set<string>();
    const decisions = new Set<string>();
    for (const row of reviews) {
      const result = JSON.parse(row["result_json"] as string);
      const model = row["model"] as string;
      models.add(model);
      assert.ok(row["source_content_digest"]);
      assert.ok(row["prompt_digest"] && row["contract_digest"]);
      for (const decision of "decisions" in result
        ? Object.values(result.decisions)
        : [result]) {
        decisions.add(decision.decision);
        if (decision.decision === "SAME") {
          if (model === "gpt-5.6-luna") {
            assert.ok(!("canonicalFindingId" in decision));
            assert.ok(!("mergedFinding" in decision));
          } else {
            assert.equal(typeof decision.canonicalFindingId, "string");
            assert.equal(
              decision.mergedFinding.findingId,
              decision.canonicalFindingId,
            );
            assert.ok(
              decision.mergedFinding.extensions.mergedOriginals.length > 0,
            );
          }
        }
      }
    }
    assert.deepEqual(models, new Set(["gpt-5.6-luna", "gpt-5.6-sol"]));
    assert.deepEqual(decisions, new Set(["SAME", "DISTINCT"]));
  } else {
    writeFileSync("/state/runner-marker", "synthetic runner state\n");
    const sourceDir = "/output/repository";
    mkdirSync(sourceDir, { recursive: true });
    const scanDir = "/output/smoke-scan";
    cpSync(exampleDir, scanDir, { recursive: true });
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
