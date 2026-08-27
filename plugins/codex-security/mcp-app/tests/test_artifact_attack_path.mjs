import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/artifact-attack-path.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  candidateAttackPathsInputSchema,
  recordCodexSecurityCandidateAttackPaths
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const scanId = "11111111-1111-4111-8111-111111111111";
const temporaryRoots = [];

try {
  await testSchemaMatchesDocumentedAttackPathDecisions();
  await testEligibleRowsKeepDiscoveryValidationAndOrder();
  await testUnknownAndDuplicateCandidatesDoNotChangeLedger();
  await testMissingEligibleCandidateDoesNotChangeLedger();
  await testIneligibleCandidatesDoNotChangeLedger();
  await testInvalidAttackPathsDoNotChangeLedger();
  await testDuplicateStoredCandidatesDoNotChangeLedger();
  await testMalformedLedgerIsNotReplaced();
  await testEmptyLedgerAcceptsAnEmptyBatch();
} finally {
  await Promise.all(temporaryRoots.map((root) => rm(root, {
    recursive: true,
    force: true
  })));
}

async function testSchemaMatchesDocumentedAttackPathDecisions() {
  const schema = JSON.parse(await readFile(new URL(
    "../../schemas/tools/candidate-attack-paths.schema.json",
    import.meta.url
  ), "utf8"));

  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(schema.required, ["scanId", "attackPaths"]);
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.$defs.input.required, schema.required);
  assert.deepEqual(schema.$defs.updatesPayload.required, ["attackPaths"]);
  assert.deepEqual(
    schema.$defs.reportableAttackPath.properties.severity.enum,
    ["critical", "high", "medium", "low"]
  );
  assert.equal(schema.$defs.ignoredAttackPath.properties.severity.const, "ignore");
  assert.ok(schema.$defs.deferredAttackPath.required.includes("proof_gap"));

  assert.equal(candidateAttackPathsInputSchema.safeParse({
    scanId,
    attackPaths: [{
      candidateId: "candidate-1",
      attackPath: attackPath()
    }]
  }).success, true);
  assert.equal(candidateAttackPathsInputSchema.safeParse({
    attackPaths: []
  }).success, false);
  assert.equal(candidateAttackPathsInputSchema.safeParse({
    scanId,
    attackPaths: [],
    path: "artifacts/02_discovery/candidate_ledger.jsonl"
  }).success, false);
  assert.equal(candidateAttackPathsInputSchema.safeParse({
    scanId,
    attackPaths: [],
    operation: "append"
  }).success, false);
}

async function testEligibleRowsKeepDiscoveryValidationAndOrder() {
  const fixture = await createFixture("eligible candidates", [
    candidate("candidate-reportable", "reportable"),
    candidate("candidate-suppressed", "suppressed"),
    candidate("candidate-deferred", "deferred"),
    candidate("candidate-without-validation")
  ]);
  const reportable = {
    ...attackPath(),
    existing_extension: { observed: true }
  };
  const deferred = attackPath("deferred");

  const result = await recordCodexSecurityCandidateAttackPaths(fixture.context, {
    attackPaths: [
      { candidateId: "candidate-deferred", attackPath: deferred },
      { candidateId: "candidate-reportable", attackPath: reportable }
    ]
  });

  assert.deepEqual(result, {
    kind: "candidate_attack_paths",
    operation: "replace",
    rowsWritten: 2
  });
  assert.deepEqual(await readRows(fixture), [
    { ...fixture.originalRows[0], attack_path: reportable },
    fixture.originalRows[1],
    { ...fixture.originalRows[2], attack_path: deferred },
    fixture.originalRows[3]
  ]);
  assert.deepEqual(Object.keys(result), ["kind", "operation", "rowsWritten"]);
}

async function testUnknownAndDuplicateCandidatesDoNotChangeLedger() {
  const fixture = await createFixture("unknown and duplicate", [
    candidate("candidate-1", "reportable")
  ]);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [{ candidateId: "candidate-unknown", attackPath: attackPath() }]
    }),
    /unknown candidate candidate-unknown/
  );
  await assertUnchanged(fixture);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [
        { candidateId: "candidate-1", attackPath: attackPath() },
        { candidateId: "candidate-1", attackPath: attackPath("ignore") }
      ]
    }),
    /repeats candidate candidate-1/
  );
  await assertUnchanged(fixture);
}

async function testMissingEligibleCandidateDoesNotChangeLedger() {
  const fixture = await createFixture("missing eligible candidate", [
    candidate("candidate-reportable", "reportable"),
    candidate("candidate-deferred", "deferred")
  ]);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [{
        candidateId: "candidate-reportable",
        attackPath: attackPath()
      }]
    }),
    /missing candidate-deferred/
  );
  await assertUnchanged(fixture);
}

async function testIneligibleCandidatesDoNotChangeLedger() {
  const fixture = await createFixture("ineligible candidates", [
    candidate("candidate-suppressed", "suppressed"),
    candidate("candidate-not-applicable", "not_applicable"),
    candidate("candidate-unvalidated")
  ]);

  for (const row of fixture.originalRows) {
    await assert.rejects(
      recordCodexSecurityCandidateAttackPaths(fixture.context, {
        attackPaths: [{ candidateId: row.candidate_id, attackPath: attackPath() }]
      }),
      /must have a reportable or deferred validation/
    );
    await assertUnchanged(fixture);
  }
}

async function testInvalidAttackPathsDoNotChangeLedger() {
  const fixture = await createFixture("invalid attack judgments", [
    candidate("candidate-1", "reportable")
  ]);
  const invalid = [
    { ...attackPath(), severity: "moderate" },
    { ...attackPath(), decision: "ignore" },
    { ...attackPath(), decision: "deferred" },
    { ...attackPath(), severity_rationale: "  " }
  ];

  for (const value of invalid) {
    const payload = {
      attackPaths: [{ candidateId: "candidate-1", attackPath: value }]
    };
    assert.equal(candidateAttackPathsInputSchema.safeParse({
      scanId,
      ...payload
    }).success, false);
    await assert.rejects(recordCodexSecurityCandidateAttackPaths(
      fixture.context,
      payload
    ));
    await assertUnchanged(fixture);
  }
}

async function testDuplicateStoredCandidatesDoNotChangeLedger() {
  const fixture = await createFixture("duplicate ledger rows", [
    candidate("candidate-1", "reportable"),
    candidate("candidate-1", "deferred")
  ]);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [{ candidateId: "candidate-1", attackPath: attackPath() }]
    }),
    /ledger repeats candidate candidate-1/
  );
  await assertUnchanged(fixture);
}

async function testMalformedLedgerIsNotReplaced() {
  const fixture = await createFixture("malformed ledger", []);
  const malformed = "{not valid JSON}\n";
  await writeFile(fixture.ledgerPath, malformed, "utf8");

  await assert.rejects(recordCodexSecurityCandidateAttackPaths(
    fixture.context,
    { attackPaths: [{ candidateId: "candidate-1", attackPath: attackPath() }] }
  ));
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), malformed);
}

async function testEmptyLedgerAcceptsAnEmptyBatch() {
  const fixture = await createFixture("no candidates", []);

  assert.deepEqual(await recordCodexSecurityCandidateAttackPaths(
    fixture.context,
    { attackPaths: [] }
  ), {
    kind: "candidate_attack_paths",
    operation: "replace",
    rowsWritten: 0
  });
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), "");

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(
      { ...fixture.context, layout: "worker" },
      { attackPaths: [] }
    ),
    /scan-bound artifact context/
  );
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), "");
}

async function createFixture(label, originalRows) {
  const root = await realpath(await mkdtemp(path.join(
    tmpdir(),
    `codex-security-attack-path-${label.replace(/\s+/gu, "-")}-`
  )));
  temporaryRoots.push(root);
  const ledgerPath = path.join(
    root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl"
  );
  await mkdir(path.dirname(ledgerPath), { recursive: true });
  await writeFile(ledgerPath, jsonl(originalRows), "utf8");
  return {
    context: {
      root,
      repoRoot: root,
      layout: "scan",
      scanId
    },
    ledgerPath,
    originalRows: structuredClone(originalRows)
  };
}

function candidate(candidateId, disposition) {
  const row = {
    candidate_id: candidateId,
    cwe_ids: ["CWE-79"],
    locations: [{
      path: "src/handler.ts",
      start_line: 4,
      end_line: 5,
      role: "sink"
    }],
    summary: `Existing discovery evidence for ${candidateId}`,
    evidence: "User-controlled data reaches the rendering sink.",
    context: "The exact Standard discovery row must survive enrichment."
  };
  if (disposition) {
    row.validation = {
      disposition,
      method: "static code trace",
      confidence: "high",
      confidence_rationale: "Source and sink are directly connected.",
      rubric: "Confirmed source, sink, and missing escaping.",
      evidence: "The template renders the supplied request parameter.",
      counterevidence_or_proof_gap: "No escaping is present.",
      remaining_uncertainty: "Runtime deployment configuration."
    };
  }
  return row;
}

function attackPath(decision = "reportable") {
  const value = {
    decision,
    dataflow: "Request parameter flows directly into the template sink.",
    reachability: "The route is reachable through the HTTP handler.",
    counterevidence: "No escaping or authorization control was found.",
    impact: "high",
    likelihood: "medium",
    severity: decision === "ignore" ? "ignore" : "high",
    severity_rationale: "Attacker-controlled markup reaches a sensitive boundary.",
    change_conditions: "Contextual output escaping would remove the issue."
  };
  if (decision === "deferred") {
    value.proof_gap = "Deployment reachability has not been confirmed.";
  }
  return value;
}

async function readRows(fixture) {
  const content = await readFile(fixture.ledgerPath, "utf8");
  return content.split(/\r?\n/u).filter(Boolean).map((line) => JSON.parse(line));
}

async function assertUnchanged(fixture) {
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), jsonl(fixture.originalRows));
}

function jsonl(rows) {
  return rows.map((row) => `${JSON.stringify(row)}\n`).join("");
}
