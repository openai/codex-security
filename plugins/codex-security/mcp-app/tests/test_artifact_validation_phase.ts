import { jsonLines, readJson, readJsonLines } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type { ArtifactContext } from "../src/artifact-io.js";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";

const {
  candidateValidationsInputSchema,
  recordCodexSecurityCandidateValidations,
} = await importSource(
  new URL("../src/artifact-validation-phase.ts", import.meta.url).pathname,
);

const toolSchema = await readJson(
  import.meta.dirname,
  "../../schemas/tools/candidate-validations.schema.json",
);
assert.equal(
  toolSchema.$schema,
  "https://json-schema.org/draft/2020-12/schema",
);
assert.deepEqual(toolSchema.$defs.input.required, ["scanId", "validations"]);
assert.equal(toolSchema.$ref, "#/$defs/input");
assert.deepEqual(toolSchema.$defs.validationUpdate.required, [
  "candidateId",
  "validation",
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
  artifact_paths: [
    "artifacts/02_discovery/validation_artifacts/candidate-b/request.txt",
  ],
  existing_extension: { observed: true },
};
const updates = [
  { candidateId: "candidate-b", validation: secondValidation },
  { candidateId: "candidate-a", validation: firstValidation },
];

assert.equal(
  candidateValidationsInputSchema.safeParse({
    scanId,
    validations: updates,
  }).success,
  true,
);
assert.equal(
  candidateValidationsInputSchema.safeParse({ validations: updates }).success,
  false,
);
assert.equal(
  candidateValidationsInputSchema.safeParse({
    scanId: "not-a-scan-id",
    validations: updates,
  }).success,
  false,
);
assert.equal(
  candidateValidationsInputSchema.safeParse({
    scanId,
    validations: [
      {
        candidateId: "candidate-a",
        validation: {
          ...firstValidation,
          disposition: "partially_validated",
        },
      },
    ],
  }).success,
  false,
);

const root = await temporaryDirectory("codex-security-validation-phase-", true);
try {
  const context = {
    root: path.join(root, "scan"),
    repoRoot: root,
    layout: "scan" as const,
  };
  const ledger = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  await mkdir(path.dirname(ledger), { recursive: true });
  const original: (ReturnType<typeof candidate> & Record<string, unknown>)[] = [
    {
      ...candidate("candidate-a", "src/a.ts"),
      context: "Original discovery context must not change.",
      discovery_extension: { nested: ["preserve", "me"] },
      attack_path: { decision: "reportable", severity: "medium" },
    },
    {
      ...candidate("candidate-b", "src/b.ts"),
      instance: "second-route",
    },
  ];
  await writeFile(ledger, jsonLines(original));

  const recorded = await recordCodexSecurityCandidateValidations(context, {
    validations: updates,
  });
  assert.deepEqual(recorded, {
    kind: "candidate_validations",
    operation: "replace",
    rowsWritten: 2,
  });
  const expected = [
    { ...original[0], validation: firstValidation },
    { ...original[1], validation: secondValidation },
  ];
  assert.deepEqual(await readJsonLines(ledger), expected);

  await recordCodexSecurityCandidateValidations(context, {
    validations: updates,
  });
  assert.deepEqual(await readJsonLines(ledger), expected);

  await assertNoMutation(
    context,
    ledger,
    {
      validations: [updates[0]],
    },
    /missing candidate-a/,
  );
  await assertNoMutation(
    context,
    ledger,
    {
      validations: [
        updates[0],
        { ...updates[1], candidateId: "unknown-candidate" },
      ],
    },
    /unknown candidate unknown-candidate/,
  );
  await assertNoMutation(
    context,
    ledger,
    {
      validations: [updates[0], updates[0], updates[1]],
    },
    /repeats candidate candidate-b/,
  );
  await assertNoMutation(
    context,
    ledger,
    {
      validations: [
        {
          candidateId: "candidate-a",
          validation: {
            ...firstValidation,
            confidence: "certain",
          },
        },
        updates[0],
      ],
    },
    /confidence/,
  );

  await assertNoMutation(
    { ...context, layout: "worker" },
    ledger,
    {
      validations: updates,
    },
    /scan-bound artifact context/,
  );

  await writeFile(ledger, jsonLines([original[0], original[0]]));
  await assertNoMutation(
    context,
    ledger,
    {
      validations: [
        { candidateId: "candidate-a", validation: firstValidation },
      ],
    },
    /repeats candidate candidate-a/,
  );

  const empty = { ...context, root: path.join(root, "empty") };
  const emptyLedger = path.join(
    empty.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  await mkdir(path.dirname(emptyLedger), { recursive: true });
  await writeFile(emptyLedger, jsonLines([]));
  assert.deepEqual(
    await recordCodexSecurityCandidateValidations(empty, {
      validations: [],
    }),
    {
      kind: "candidate_validations",
      operation: "replace",
      rowsWritten: 0,
    },
  );
  assert.deepEqual(await readJsonLines(emptyLedger), []);

  if (process.platform !== "win32") {
    const outside = path.join(root, "outside-candidate-ledger.jsonl");
    await writeFile(outside, jsonLines(original));
    await rm(ledger);
    await symlink(outside, ledger, "file");
    await assert.rejects(
      recordCodexSecurityCandidateValidations(context, {
        validations: updates,
      }),
      /symbolic|symlink|canonical|escape|contained|regular/i,
    );
    assert.deepEqual(await readJsonLines(outside), original);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

function candidate(candidateId: string, sourcePath: string) {
  return {
    candidate_id: candidateId,
    cwe_ids: ["CWE-79"],
    locations: [{ path: sourcePath, start_line: 1, end_line: 2, role: "sink" }],
    summary: "Request-controlled content reaches an HTML response.",
    evidence:
      "A response uses the request body without context-sensitive escaping.",
  };
}

function validation(disposition: string) {
  return {
    disposition,
    method: "Static source-to-sink trace.",
    confidence: "high",
    confidence_rationale: "The vulnerable code path is directly visible.",
    rubric: [
      "The source is attacker-controlled.",
      { criterion: "The HTML sink is reachable.", satisfied: true },
    ],
    evidence: ["The response directly interpolates the request body."],
    counterevidence_or_proof_gap: "No escaping control exists on this path.",
    remaining_uncertainty: "",
  };
}

async function assertNoMutation(
  context: ArtifactContext,
  ledger: string,
  input: unknown,
  expectedError: RegExp,
) {
  const before = await readFile(ledger, "utf8");
  await assert.rejects(
    recordCodexSecurityCandidateValidations(context, input),
    expectedError,
  );
  assert.equal(await readFile(ledger, "utf8"), before);
}
