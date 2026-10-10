import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as Severity from "../src/workbench/severity.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { assessments, severityCheckpoint, readSeverityClassification } =
  (await importSource("src/workbench/severity.ts")) as typeof Severity;
const { applyMigrations, migrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function open(t: TestContext, path = ":memory:", version?: number) {
  const database = new DatabaseSync(path);
  t.after(() => database.close());
  applyMigrations(
    database,
    migrations.filter(
      (item) => version === undefined || item.version <= version,
    ),
  );
  return database;
}

function save(
  findingId: string,
  scanId = "scan",
): Extract<Severity.SeverityCheckpoint, { action: "save" }> {
  return {
    action: "save",
    scanId,
    finding: {
      findingId,
      fingerprints: { primary: `fingerprint-${findingId}` },
      ruleId: "synthetic-rule",
      identity: { anchor: "synthetic-anchor" },
      evidence: { count: 18446744073709551617n },
    },
    assessment: {
      findingId,
      occurrenceId: `occurrence-${findingId}`,
      inputSha256: "evidence-digest",
      rubricSha256: null,
      knowledgeBaseSha256: null,
      assessedAt: "unused",
      source: "existing-severity",
      decision: "assessed",
      level: "high",
      rubricLabel: null,
      rationale: "Complete\0diagnostic λ",
      confidence: null,
      reviewTrigger: null,
    },
  };
}

function begin(
  scanId: string,
  findingIds: string[],
): Severity.SeverityCheckpoint {
  return {
    action: "begin",
    scanId,
    findingIds,
    assessedAt: "started",
    rubricSha256: null,
    knowledgeBaseSha256: null,
  };
}

function legacyAssessments(
  database: DatabaseSync,
  scanId: string,
  findingIds: string[],
) {
  for (const findingId of findingIds) {
    database
      .prepare(
        `INSERT INTO findings
      (id, fingerprint, rule_id, identity_anchor, created_at, updated_at)
      VALUES (?, ?, 'rule', 'anchor', 'created', 'updated')`,
      )
      .run(findingId, findingId);
    const owner = findingId === "other-scan" ? "other" : scanId;
    const occurrence = `occ_${createHash("sha256").update(`${owner}\0${findingId}`).digest("hex").slice(0, 24)}`;
    database
      .prepare(
        `INSERT INTO finding_severity_assessments
      (finding_id, occurrence_id, input_sha256, assessed_at, source, decision, rationale)
      VALUES (?, ?, 'digest', 'assessed', 'rubric', 'excluded', 'Saved exclusion')`,
      )
      .run(findingId, occurrence);
  }
}

for (const existingAssessment of [false, true]) {
  test(`read-only severity recovery retains current rows and missing legacy rows: ${existingAssessment}`, async (t) => {
    const directory = await temporary.create("severity-legacy-read-");
    const path = join(directory, "workbench.sqlite3");
    const database = open(t, path);
    const findingIds = ["first", "second", "other-scan"];
    legacyAssessments(database, "original-scan", findingIds);
    severityCheckpoint(database, begin("original-scan", findingIds), "started");
    if (existingAssessment) {
      database.exec(`INSERT INTO scan_severity_assessments
        SELECT 'original-scan', assessment.* FROM finding_severity_assessments AS assessment
        WHERE finding_id = 'first';
        UPDATE scan_severity_assessments SET rationale = 'Current exclusion';`);
    }
    const before = await readFile(path);
    const result = readSeverityClassification(path, "original-scan") as {
      assessments: { findingId: string; rationale: string }[];
    };
    assert.deepEqual(
      result.assessments.map((row) => row.findingId),
      ["first", "second"],
    );
    assert.deepEqual(
      result.assessments.map((row) => row.rationale),
      [
        existingAssessment ? "Current exclusion" : "Saved exclusion",
        "Saved exclusion",
      ],
    );
    assert.deepEqual(await readFile(path), before);
  });
}

for (const indexed of [false, true]) {
  for (const latestSelection of [[], ["first"]]) {
    test(`expanded severity selection recovers legacy ownership after migration: ${indexed}/${latestSelection.length}`, (t) => {
      const database = open(t, ":memory:", 41);
      const findingIds = ["first", "second", "other-scan"];
      legacyAssessments(database, "original-scan", findingIds);
      database
        .prepare(
          `INSERT INTO scan_severity_classifications
        (scan_id, finding_ids_json, assessed_at) VALUES ('original-scan', ?, 'assessed')`,
        )
        .run(JSON.stringify(latestSelection));
      if (indexed) {
        database.exec(`INSERT INTO workspaces (id, created_at, updated_at)
          VALUES ('workspace', 'created', 'updated');
          INSERT INTO scans (id, workspace_id, target_path, target_revision, scope,
            mode, scan_dir, status, phase, started_at, created_at, updated_at)
          VALUES ('original-scan', 'workspace', '/synthetic/target', 'revision', '.',
            'standard', '/synthetic/scan', 'complete', 'reporting', 'started', 'created', 'updated');
          INSERT INTO finding_occurrences
            (id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at)
          SELECT occurrence_id, finding_id, 'original-scan', 'Title', 'Summary', 'high', 'high', 'Fix', 'created'
          FROM finding_severity_assessments WHERE finding_id != 'other-scan';`);
      }
      applyMigrations(database, migrations);
      database.exec(`INSERT OR REPLACE INTO scan_severity_assessments
        SELECT 'original-scan', assessment.* FROM finding_severity_assessments AS assessment
        WHERE finding_id = 'first';
        UPDATE scan_severity_assessments SET rationale = 'Current exclusion' WHERE finding_id = 'first';`);
      const result = severityCheckpoint(
        database,
        begin("original-scan", findingIds),
        "started",
      );
      assert.deepEqual(
        result.assessments!.map((row) => row.findingId),
        ["first", "second"],
      );
      assert.deepEqual(
        result.assessments!.map((row) => row.rationale),
        ["Current exclusion", "Saved exclusion"],
      );
      assert.ok(
        result.assessments!.every((row) => row.decision === "excluded"),
      );
      assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
    });
  }
}

test("severity checkpoints retain external findings and isolate each scan's assessments", (t) => {
  const database = open(t);
  const payload = save("finding\0suffix", "scan-a");
  for (const field of [
    "occurrenceId",
    "inputSha256",
    "rubricSha256",
    "knowledgeBaseSha256",
    "rubricLabel",
    "reviewTrigger",
  ] as const)
    payload.assessment[field] = `${field}\0suffix λ`;
  assert.deepEqual(
    severityCheckpoint(
      database,
      begin("scan-a", [payload.finding.findingId]),
      "started",
    ),
    { assessments: [] },
  );
  severityCheckpoint(database, payload, "first\0timestamp");
  const details = database
    .prepare("SELECT details_json FROM findings WHERE id = ?")
    .get(payload.finding.findingId)!.details_json;
  assert.match(String(details), /18446744073709551617/);
  const first = { ...payload.assessment, assessedAt: "first\0timestamp" };
  assert.deepEqual(
    severityCheckpoint(
      database,
      begin("scan-b", [payload.finding.findingId]),
      "started",
    ),
    { assessments: [] },
  );
  payload.scanId = "scan-b";
  payload.finding.identity.anchor = "must-not-replace-existing-finding";
  payload.assessment.level = "low";
  severityCheckpoint(database, payload, "second");
  assert.deepEqual(
    severityCheckpoint(
      database,
      begin("scan-a", [payload.finding.findingId]),
      "restarted",
    ),
    { assessments: [first] },
  );
  assert.deepEqual(assessments(database, [payload.finding.findingId]), []);
  assert.deepEqual(
    assessments(database, [payload.finding.findingId], "scan-b"),
    [{ ...payload.assessment, assessedAt: "second" }],
  );
  assert.equal(
    database
      .prepare("SELECT details_json FROM findings WHERE id = ?")
      .get(payload.finding.findingId)!.details_json,
    details,
  );
});

test("failed assessment writes roll back external finding insertion and preserve the cache", (t) => {
  const database = open(t);
  severityCheckpoint(database, begin("scan", ["saved", "new"]), "started");
  severityCheckpoint(database, save("saved"), "first");
  const invalid = save("new");
  invalid.assessment.findingId = "missing";
  assert.throws(
    () => severityCheckpoint(database, invalid, "second"),
    /FOREIGN KEY/,
  );
  assert.equal(
    database.prepare("SELECT 1 FROM findings WHERE id = 'new'").get(),
    undefined,
  );
  assert.equal(assessments(database, ["saved"], "scan")[0].assessedAt, "first");
  invalid.finding.findingId = "saved\ud800";
  assert.throws(
    () => severityCheckpoint(database, invalid, "third"),
    /valid Unicode/,
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS count FROM findings").get()!.count,
    1,
  );
});

test("severity reads retain requested order and scan scope in a larger assessment cache", (t) => {
  const database = open(t);
  const ids = Array.from({ length: 250 }, (_, index) => `finding-${index}`);
  for (const scanId of ["scan-a", "scan-b"])
    severityCheckpoint(database, begin(scanId, ids), "started");
  for (let index = 0; index < 250; index++) {
    const id = `finding-${index}`;
    severityCheckpoint(database, save(id, "scan-a"), "first");
    const other = save(id, "scan-b");
    other.assessment.level = "medium";
    severityCheckpoint(database, other, "second");
  }
  const selected = ["finding-249", "finding-17", "finding-0"];
  assert.deepEqual(
    assessments(database, selected, "scan-a").map(({ findingId, level }) => ({
      findingId,
      level,
    })),
    selected.map((findingId) => ({ findingId, level: "high" })),
  );
  assert.deepEqual(
    assessments(database, selected, "scan-b").map(({ findingId, level }) => ({
      findingId,
      level,
    })),
    selected.map((findingId) => ({ findingId, level: "medium" })),
  );
});

test("old database reads use legacy assessments without migrating or changing the file", async (t) => {
  const directory = await temporary.create("severity-legacy-");
  const path = join(directory, "workbench.sqlite3");
  const database = open(t, path, 42);
  database.exec(`INSERT INTO scan_severity_classifications (scan_id, finding_ids_json, assessed_at)
    VALUES ('scan', '["finding"]', 'started');
    INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at)
    VALUES ('finding', 'fingerprint', 'rule', 'anchor', 'created', 'updated');
    INSERT INTO finding_severity_assessments
      (finding_id, occurrence_id, input_sha256, assessed_at, source, decision, level, rationale)
    VALUES ('finding', 'occurrence', 'digest', 'assessed', 'existing-severity', 'assessed', 'high', 'Saved');`);
  database
    .prepare(
      "UPDATE scan_severity_classifications SET assessed_at = ?, rubric_sha256 = ?, knowledge_base_sha256 = ? WHERE scan_id = 'scan'",
    )
    .run("started\0suffix", "rubric\0suffix", "knowledge\0suffix");
  const before = await readFile(path);
  const metadata = await stat(path);
  const schema = database
    .prepare("SELECT name, sql FROM sqlite_master ORDER BY name")
    .all();
  const result = readSeverityClassification(path, "scan") as {
    assessments: { findingId: string }[];
    assessedAt: string;
    rubricSha256: string;
    knowledgeBaseSha256: string;
  };
  assert.equal(result.assessedAt, "started\0suffix");
  assert.equal(result.rubricSha256, "rubric\0suffix");
  assert.equal(result.knowledgeBaseSha256, "knowledge\0suffix");
  assert.deepEqual(
    result.assessments.map((row) => row.findingId),
    ["finding"],
  );
  assert.deepEqual(readSeverityClassification(path, "missing"), {});
  assert.deepEqual(await readFile(path), before);
  assert.equal((await stat(path)).mode, metadata.mode);
  assert.deepEqual(
    database.prepare("SELECT name, sql FROM sqlite_master ORDER BY name").all(),
    schema,
  );
  database.exec("DROP TABLE scan_severity_classifications");
  assert.deepEqual(readSeverityClassification(path, "scan"), {});
  const missing = join(directory, "missing.sqlite3");
  assert.throws(() => readSeverityClassification(missing, "scan"));
  await assert.rejects(stat(missing), { code: "ENOENT" });
});

test("recover legacy assessments only for their owning scan and keep read-only recovery unchanged", async (t) => {
  const directory = await temporary.create("severity-owner-");
  const path = join(directory, "workbench.sqlite3");
  const database = open(t, path);
  const occurrence = `occ_${createHash("sha256").update("scan-a\0fingerprint").digest("hex").slice(0, 24)}`;
  database.exec(`INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at)
    VALUES ('finding', 'fingerprint', 'rule', 'anchor', 'created', 'updated');`);
  database
    .prepare(
      `INSERT INTO finding_severity_assessments
    (finding_id, occurrence_id, input_sha256, assessed_at, source, decision, level, rationale)
    VALUES ('finding', ?, 'digest', 'assessed', 'existing-severity', 'assessed', 'high', 'Saved')`,
    )
    .run(occurrence);
  const legacy = assessments(database, ["finding"]);
  assert.deepEqual(
    severityCheckpoint(database, begin("scan-a", ["finding"]), "started"),
    { assessments: legacy },
  );
  assert.deepEqual(
    severityCheckpoint(database, begin("scan-b", ["finding"]), "started"),
    { assessments: [] },
  );
  const before = database
    .prepare("SELECT * FROM scan_severity_assessments")
    .all();
  const recovered = readSeverityClassification(path, "scan-a") as {
    assessments: unknown[];
  };
  assert.deepEqual(recovered.assessments, legacy);
  assert.deepEqual(
    database.prepare("SELECT * FROM scan_severity_assessments").all(),
    before,
  );
  const current = save("finding", "scan-a");
  current.assessment.level = "low";
  severityCheckpoint(database, current, "updated");
  assert.equal(
    severityCheckpoint(database, begin("scan-a", ["finding"]), "started")
      .assessments![0].level,
    "low",
  );
  assert.deepEqual(assessments(database, ["finding"]), legacy);
});
