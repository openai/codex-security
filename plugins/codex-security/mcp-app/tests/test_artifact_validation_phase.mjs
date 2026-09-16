import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const result = await build({
  bundle: true,
  entryPoints: [new URL("../src/artifact-validation-phase.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  candidateValidationRecordSchema,
  candidateValidationsInputSchema,
  recordCodexSecurityCandidateValidations
} = await import(
  `data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString("base64")}`
);

const toolSchema = JSON.parse(await readFile(
  new URL("../../schemas/tools/candidate-validations.schema.json", import.meta.url),
  "utf8"
));
assert.equal(toolSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
assert.deepEqual(toolSchema.required, ["scanId", "validations"]);
assert.deepEqual(toolSchema.$defs.validationUpdate.required, [
  "candidateId",
  "validation"
]);

const scanId = randomUUID();
const firstValidation = validation("reportable");
const secondValidation = {
  ...validation("deferred"),
  confidence: "low",
  remaining_uncertainty: "A production deployment is not available locally.",
  source: "HTTP request body",
  control: "Template escaping",
  sink: "HTML response",
  preconditions: ["The affected endpoint is reachable."],
  artifact_paths: ["artifacts/02_discovery/validation_artifacts/candidate-b/request.txt"],
  existing_extension: { observed: true }
};
const updates = [
  { candidateId: "candidate-b", validation: secondValidation },
  { candidateId: "candidate-a", validation: firstValidation }
];

assert.equal(candidateValidationsInputSchema.safeParse({
  scanId,
  validations: updates
}).success, true);
assert.equal(candidateValidationsInputSchema.safeParse({ validations: updates }).success, false);
assert.equal(candidateValidationsInputSchema.safeParse({
  scanId: "not-a-scan-id",
  validations: updates
}).success, false);
assert.equal(candidateValidationsInputSchema.safeParse({
  scanId,
  validations: [{ candidateId: "candidate-a", validation: {
    ...firstValidation,
    disposition: "partially_validated"
  } }]
}).success, false);
assert.equal(candidateValidationRecordSchema.safeParse(secondValidation).success, true);
assert.equal(candidateValidationRecordSchema.safeParse({
  ...firstValidation,
  confidence: "certain"
}).success, false);

const root = await realpath(await mkdtemp(path.join(tmpdir(), "codex-security-validation-phase-")));
try {
  const context = await scanContext(root, "scan", scanId);
  const ledger = path.join(root, "scan", "artifacts", "02_discovery", "candidate_ledger.jsonl");
  const original = [
    {
      ...candidate("candidate-a", "src/a.ts"),
      context: "Original discovery context must not change.",
      discovery_extension: { nested: ["preserve", "me"] },
      attack_path: { decision: "reportable", severity: "medium" }
    },
    {
      ...candidate("candidate-b", "src/b.ts"),
      instance: "second-route"
    }
  ];
  await writeJsonl(ledger, original);

  const recorded = await recordCodexSecurityCandidateValidations(context, {
    validations: updates
  });
  assert.deepEqual(recorded, {
    kind: "candidate_validations",
    operation: "replace",
    rowsWritten: 2
  });
  const expected = [
    { ...original[0], validation: firstValidation },
    { ...original[1], validation: secondValidation }
  ];
  assert.deepEqual(await readJsonl(ledger), expected);
  assert.deepEqual((await readJsonl(ledger))[0].attack_path, original[0].attack_path);

  await recordCodexSecurityCandidateValidations(context, { validations: updates });
  assert.deepEqual(await readJsonl(ledger), expected);

  await assertNoMutation(context, ledger, {
    validations: [updates[0]]
  }, /missing candidate-a/);
  await assertNoMutation(context, ledger, {
    validations: [updates[0], { ...updates[1], candidateId: "unknown-candidate" }]
  }, /unknown candidate unknown-candidate/);
  await assertNoMutation(context, ledger, {
    validations: [updates[0], updates[0], updates[1]]
  }, /repeats candidate candidate-b/);
  await assertNoMutation(context, ledger, {
    validations: [{ candidateId: "candidate-a", validation: {
      ...firstValidation,
      confidence: "certain"
    } }, updates[0]]
  }, /confidence/);

  await assertNoMutation({ ...context, layout: "worker" }, ledger, {
    validations: updates
  }, /scan-bound artifact context/);

  await writeJsonl(ledger, [original[0], original[0]]);
  await assertNoMutation(context, ledger, {
    validations: [{ candidateId: "candidate-a", validation: firstValidation }]
  }, /repeats candidate candidate-a/);

  const empty = await scanContext(root, "empty", randomUUID());
  const emptyLedger = path.join(root, "empty", "artifacts", "02_discovery", "candidate_ledger.jsonl");
  await writeJsonl(emptyLedger, []);
  assert.deepEqual(await recordCodexSecurityCandidateValidations(empty, {
    validations: []
  }), {
    kind: "candidate_validations",
    operation: "replace",
    rowsWritten: 0
  });
  assert.deepEqual(await readJsonl(emptyLedger), []);

  if (process.platform !== "win32") {
    const outside = path.join(root, "outside-candidate-ledger.jsonl");
    await writeJsonl(outside, original);
    await rm(ledger);
    await symlink(outside, ledger, "file");
    await assert.rejects(
      recordCodexSecurityCandidateValidations(context, { validations: updates }),
      /symbolic|symlink|canonical|escape|contained|regular/i
    );
    assert.deepEqual(await readJsonl(outside), original);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

async function scanContext(root, directory, scanId) {
  const scanRoot = path.join(root, directory);
  const repository = path.join(root, "repository");
  await Promise.all([
    mkdir(path.join(scanRoot, "artifacts", "02_discovery"), { recursive: true }),
    mkdir(repository, { recursive: true })
  ]);
  return { root: scanRoot, repoRoot: repository, layout: "scan", scanId };
}

function candidate(candidateId, sourcePath) {
  return {
    candidate_id: candidateId,
    cwe_ids: ["CWE-79"],
    locations: [{ path: sourcePath, start_line: 1, end_line: 2, role: "sink" }],
    summary: "Request-controlled content reaches an HTML response.",
    evidence: "A response uses the request body without context-sensitive escaping."
  };
}

function validation(disposition) {
  return {
    disposition,
    method: "Static source-to-sink trace.",
    confidence: "high",
    confidence_rationale: "The vulnerable code path is directly visible.",
    rubric: [
      "The source is attacker-controlled.",
      { criterion: "The HTML sink is reachable.", satisfied: true }
    ],
    evidence: ["The response directly interpolates the request body."],
    counterevidence_or_proof_gap: "No escaping control exists on this path.",
    remaining_uncertainty: ""
  };
}

async function assertNoMutation(context, ledger, input, expectedError) {
  const before = await readFile(ledger, "utf8");
  await assert.rejects(
    recordCodexSecurityCandidateValidations(context, input),
    expectedError
  );
  assert.equal(await readFile(ledger, "utf8"), before);
}

async function writeJsonl(file, rows) {
  await writeFile(file, rows.length > 0
    ? `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`
    : "");
}

async function readJsonl(file) {
  return (await readFile(file, "utf8"))
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}
