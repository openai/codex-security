import { jsonLines, readJson, readJsonLines } from "./support/json.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type { RawDiscoveryCandidate } from "../src/artifact-discovery.js";
import type { CandidateValidationRecord } from "../src/artifact-validation-phase.js";
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";

const {
  candidateAttackPathsInputSchema,
  recordCodexSecurityCandidateAttackPaths,
} = await importSource(
  path.join(import.meta.dirname, "../src/artifact-attack-path.ts"),
);

const scanId = "11111111-1111-4111-8111-111111111111";
const temporaryDirectories = createTemporaryDirectories(true);

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
  await temporaryDirectories.cleanup();
}

async function testSchemaMatchesDocumentedAttackPathDecisions() {
  const schema = await readJson(
    import.meta.dirname,
    "../../schemas/tools/candidate-attack-paths.schema.json",
  );

  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual(schema.$defs.input.required, ["scanId", "attackPaths"]);
  assert.equal(schema.$defs.input.additionalProperties, false);
  assert.equal(schema.$ref, "#/$defs/input");
  assert.deepEqual(schema.$defs.updatesPayload.required, ["attackPaths"]);
  assert.deepEqual(schema.$defs.reportableAttackPath.properties.severity.enum, [
    "critical",
    "high",
    "medium",
    "low",
  ]);
  assert.equal(
    schema.$defs.ignoredAttackPath.properties.severity.const,
    "ignore",
  );
  assert.ok(schema.$defs.deferredAttackPath.required.includes("proof_gap"));

  assert.equal(
    candidateAttackPathsInputSchema.safeParse({
      scanId,
      attackPaths: [
        {
          candidateId: "candidate-1",
          attackPath: attackPath(),
        },
      ],
    }).success,
    true,
  );
  assert.equal(
    candidateAttackPathsInputSchema.safeParse({
      attackPaths: [],
    }).success,
    false,
  );
  assert.equal(
    candidateAttackPathsInputSchema.safeParse({
      scanId,
      attackPaths: [],
      path: "artifacts/02_discovery/candidate_ledger.jsonl",
    }).success,
    false,
  );
  assert.equal(
    candidateAttackPathsInputSchema.safeParse({
      scanId,
      attackPaths: [],
      operation: "append",
    }).success,
    false,
  );
}

async function testEligibleRowsKeepDiscoveryValidationAndOrder() {
  const fixture = await createFixture("eligible candidates", [
    candidate("candidate-reportable", "reportable"),
    candidate("candidate-suppressed", "suppressed"),
    candidate("candidate-deferred", "deferred"),
    candidate("candidate-without-validation"),
  ]);
  const reportable = {
    ...attackPath(),
    existing_extension: { observed: true },
  };
  const deferred = attackPath("deferred");

  const result = await recordCodexSecurityCandidateAttackPaths(
    fixture.context,
    {
      attackPaths: [
        { candidateId: "candidate-deferred", attackPath: deferred },
        { candidateId: "candidate-reportable", attackPath: reportable },
      ],
    },
  );

  assert.deepEqual(result, {
    kind: "candidate_attack_paths",
    operation: "replace",
    rowsWritten: 2,
  });
  assert.deepEqual(await readJsonLines(fixture.ledgerPath), [
    { ...fixture.originalRows[0], attack_path: reportable },
    fixture.originalRows[1],
    { ...fixture.originalRows[2], attack_path: deferred },
    fixture.originalRows[3],
  ]);
  assert.deepEqual(Object.keys(result), ["kind", "operation", "rowsWritten"]);
}

async function testUnknownAndDuplicateCandidatesDoNotChangeLedger() {
  const fixture = await createFixture("unknown and duplicate", [
    candidate("candidate-1", "reportable"),
  ]);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [
        { candidateId: "candidate-unknown", attackPath: attackPath() },
      ],
    }),
    /unknown candidate candidate-unknown/,
  );
  await assertUnchanged(fixture);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [
        { candidateId: "candidate-1", attackPath: attackPath() },
        { candidateId: "candidate-1", attackPath: attackPath("ignore") },
      ],
    }),
    /repeats candidate candidate-1/,
  );
  await assertUnchanged(fixture);
}

async function testMissingEligibleCandidateDoesNotChangeLedger() {
  const fixture = await createFixture("missing eligible candidate", [
    candidate("candidate-reportable", "reportable"),
    candidate("candidate-deferred", "deferred"),
  ]);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [
        {
          candidateId: "candidate-reportable",
          attackPath: attackPath(),
        },
      ],
    }),
    /missing candidate-deferred/,
  );
  await assertUnchanged(fixture);
}

async function testIneligibleCandidatesDoNotChangeLedger() {
  const fixture = await createFixture("ineligible candidates", [
    candidate("candidate-suppressed", "suppressed"),
    candidate("candidate-not-applicable", "not_applicable"),
    candidate("candidate-unvalidated"),
  ]);

  for (const row of fixture.originalRows) {
    await assert.rejects(
      recordCodexSecurityCandidateAttackPaths(fixture.context, {
        attackPaths: [
          { candidateId: row.candidate_id, attackPath: attackPath() },
        ],
      }),
      /must have a reportable or deferred validation/,
    );
    await assertUnchanged(fixture);
  }
}

async function testInvalidAttackPathsDoNotChangeLedger() {
  const fixture = await createFixture("invalid attack judgments", [
    candidate("candidate-1", "reportable"),
  ]);
  const invalid = [
    { ...attackPath(), severity: "moderate" },
    { ...attackPath(), decision: "ignore" },
    { ...attackPath(), decision: "deferred" },
    { ...attackPath(), severity_rationale: "  " },
  ];

  for (const value of invalid) {
    const payload = {
      attackPaths: [{ candidateId: "candidate-1", attackPath: value }],
    };
    assert.equal(
      candidateAttackPathsInputSchema.safeParse({
        scanId,
        ...payload,
      }).success,
      false,
    );
    await assert.rejects(
      recordCodexSecurityCandidateAttackPaths(fixture.context, payload),
    );
    await assertUnchanged(fixture);
  }
}

async function testDuplicateStoredCandidatesDoNotChangeLedger() {
  const fixture = await createFixture("duplicate ledger rows", [
    candidate("candidate-1", "reportable"),
    candidate("candidate-1", "deferred"),
  ]);

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [{ candidateId: "candidate-1", attackPath: attackPath() }],
    }),
    /ledger repeats candidate candidate-1/,
  );
  await assertUnchanged(fixture);
}

async function testMalformedLedgerIsNotReplaced() {
  const fixture = await createFixture("malformed ledger", []);
  const malformed = "{not valid JSON}\n";
  await writeFile(fixture.ledgerPath, malformed, "utf8");

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [{ candidateId: "candidate-1", attackPath: attackPath() }],
    }),
  );
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), malformed);
}

async function testEmptyLedgerAcceptsAnEmptyBatch() {
  const fixture = await createFixture("no candidates", []);

  assert.deepEqual(
    await recordCodexSecurityCandidateAttackPaths(fixture.context, {
      attackPaths: [],
    }),
    {
      kind: "candidate_attack_paths",
      operation: "replace",
      rowsWritten: 0,
    },
  );
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), "");

  await assert.rejects(
    recordCodexSecurityCandidateAttackPaths(
      { ...fixture.context, layout: "worker" },
      { attackPaths: [] },
    ),
    /scan-bound artifact context/,
  );
  assert.equal(await readFile(fixture.ledgerPath, "utf8"), "");
}

async function createFixture(
  label: string,
  originalRows: ReturnType<typeof candidate>[],
) {
  const root = await temporaryDirectories.create(
    `codex-security-attack-path-${label.replace(/\s+/gu, "-")}-`,
  );
  const ledgerPath = path.join(
    root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  await mkdir(path.dirname(ledgerPath), { recursive: true });
  await writeFile(ledgerPath, jsonLines(originalRows), "utf8");
  return {
    context: {
      root,
      repoRoot: root,
      layout: "scan",
    },
    ledgerPath,
    originalRows: structuredClone(originalRows),
  };
}

function candidate(
  candidateId: string,
  disposition?: CandidateValidationRecord["disposition"],
) {
  const row: RawDiscoveryCandidate & {
    candidate_id: string;
    validation?: CandidateValidationRecord;
  } = {
    candidate_id: candidateId,
    cwe_ids: ["CWE-79"],
    locations: [
      {
        path: "src/handler.ts",
        start_line: 4,
        end_line: 5,
        role: "sink",
      },
    ],
    summary: `Existing discovery evidence for ${candidateId}`,
    evidence: "User-controlled data reaches the rendering sink.",
    context: "The exact Standard discovery row must survive enrichment.",
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
      remaining_uncertainty: "Runtime deployment configuration.",
    };
  }
  return row;
}

function attackPath(decision = "reportable") {
  const value: Record<string, string> = {
    decision,
    dataflow: "Request parameter flows directly into the template sink.",
    reachability: "The route is reachable through the HTTP handler.",
    counterevidence: "No escaping or authorization control was found.",
    impact: "high",
    likelihood: "medium",
    severity: decision === "ignore" ? "ignore" : "high",
    severity_rationale:
      "Attacker-controlled markup reaches a sensitive boundary.",
    change_conditions: "Contextual output escaping would remove the issue.",
  };
  if (decision === "deferred") {
    value.proof_gap = "Deployment reachability has not been confirmed.";
  }
  return value;
}

async function assertUnchanged(
  fixture: Awaited<ReturnType<typeof createFixture>>,
) {
  assert.equal(
    await readFile(fixture.ledgerPath, "utf8"),
    jsonLines(fixture.originalRows),
  );
}
