import path from "node:path";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import { importSource } from "./import-module.ts";
import { readJson } from "./support/json.ts";
import { finding as fixtureFinding } from "./scan-draft-fixture.ts";

const { artifactSchemaDocuments } = await importSource(
  path.join(import.meta.dirname, "../src/artifact-contracts.ts"),
);
const ajv = new Ajv2020({ strict: false, validateFormats: false });
for (const path of Object.keys(artifactSchemaDocuments)) {
  ajv.addSchema(
    await readJson(import.meta.dirname, `../../schemas/${path}.schema.json`),
  );
}
function jsonSchema(path: string, name: string) {
  return ajv.getSchema(
    `codex-security://schemas/${path}.schema.json#/$defs/${name}`,
  )!;
}

// Ledger readers expose only the first issue; preserve field precedence.
const attackPaths =
  artifactSchemaDocuments["tools/candidate-attack-paths"].$defs;
const attackPath = {
  dataflow: "Request reaches the operation.",
  reachability: "The public handler calls it.",
  counterevidence: "No intervening control.",
  impact: "high",
  likelihood: "high",
};
for (const [schema, input, field] of [
  [
    artifactSchemaDocuments["definitions/discovery-candidate"].$defs
      .discoveryCandidate,
    {},
    "candidate_id",
  ],
  [
    artifactSchemaDocuments["tools/discovery-candidates"].$defs
      .workbenchListCandidatesInput,
    { scanId: 42, cursor: "bad" },
    "scanId",
  ],
  ...[
    [attackPaths.reportableAttackPath, "reportable"],
    [attackPaths.ignoredAttackPath, "ignore"],
    [attackPaths.deferredAttackPath, "deferred"],
  ].map(([schema, decision]) => [
    schema,
    { ...attackPath, decision },
    "severity",
  ]),
] as const) {
  const result = schema.safeParse(input);
  assert.equal(result.success, false);
  assert.deepEqual(result.error?.issues[0]?.path, [field]);
}

// Custom validation exposes JSON-schema diagnostics, including legacy keywords.
for (const [path, name, value, message] of [
  [
    "tools/scan-draft",
    "severity/properties/level",
    null,
    "must be equal to one of the allowed values",
  ],
  ...["disposition", "confidence"].map(
    (field) =>
      [
        "tools/candidate-validations",
        `validationRecord/properties/${field}`,
        null,
        "must be string",
      ] as const,
  ),
  [
    "tools/scan-draft",
    "finding/properties/findingId",
    "invented",
    "boolean schema is false",
  ],
  [
    "tools/scan-draft",
    "finding/properties/writeup/properties/reportPath",
    "invalid",
    'must match pattern "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md$"',
  ],
] as const) {
  const validate = jsonSchema(path, name);
  assert.equal(validate(value), false);
  assert.equal(validate.errors?.[0]?.message, message);
}

// SDK JSON consumers disable formats; native tools retain Zod's UUID and safe
// integer validation. Generated exports must preserve both existing contracts.
const common = artifactSchemaDocuments["definitions/artifact-common"].$defs;
const requiredTextValues = [
  "",
  " \t\r\n",
  "\u0085",
  "\u001c\u001d\u001e\u001f",
  "\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000",
  "\uFEFF",
  "\u0085\uFEFF\u001c",
  "  Required text. \n",
];
const commonJson = await readJson(
  import.meta.dirname,
  "../../schemas/definitions/artifact-common.schema.json",
);
const pythonTextResults = JSON.parse(
  execFileSync(
    process.env.PYTHON || "python3",
    [
      "-c",
      "import json, re, sys; values, pattern = json.load(sys.stdin.buffer); print(json.dumps([[bool(value.strip()), bool(re.search(pattern, value))] for value in values]))",
    ],
    {
      input: JSON.stringify([
        requiredTextValues,
        commonJson.$defs.nonEmptyText.pattern,
      ]),
      encoding: "utf8",
    },
  ),
) as [boolean, boolean][];
const draftFinding = artifactSchemaDocuments["tools/scan-draft"].$defs.finding;
for (const [index, value] of requiredTextValues.entries()) {
  const [valid, pythonSchemaValid] = pythonTextResults[index]!;
  assert.equal(pythonSchemaValid, valid);
  assert.equal(common.nonEmptyText.safeParse(value).success, valid);
  assert.equal(
    jsonSchema("definitions/artifact-common", "nonEmptyText")(value),
    valid,
  );
  for (const field of [
    "title",
    "summary",
    "remediation",
    "confidence.rationale",
    "taxonomy.category",
    "provenance.source",
    "severity.scoringSystem",
  ]) {
    const finding: Record<string, unknown> = {
      ...fixtureFinding("text", "src/file.ts"),
      severity: { level: "high", score: 5, scoringSystem: "synthetic" },
    };
    const parts = field.split(".");
    const object =
      parts.length === 1
        ? finding
        : (finding[parts[0]!] as Record<string, unknown>);
    object[parts.at(-1)!] = value;
    const parsed = draftFinding.safeParse(finding);
    assert.equal(parsed.success, valid, `${field}: ${JSON.stringify(value)}`);
    if (parsed.success) assert.deepEqual(parsed.data, finding);
    assert.equal(jsonSchema("tools/scan-draft", "finding")(finding), valid);
  }
}
const uuid = "61a20957-1be8-4ccf-8de8-eab4061e8cc3";
for (const [value, valid] of [
  [uuid, true],
  ["not-a-uuid", false],
] as const) {
  assert.equal(common.scanId.safeParse(value).success, valid);
  assert.equal(
    jsonSchema("definitions/artifact-common", "scanId")(value),
    true,
  );
  assert.equal(jsonSchema("tools/scan-draft", "scanId")(value), true);
}
const location = artifactSchemaDocuments["tools/scan-draft"].$defs.location;
for (const [startLine, runtime, json] of [
  [1, true, true],
  [0, false, false],
  [1.5, false, false],
  [Number.MAX_SAFE_INTEGER + 1, false, true],
] as const) {
  const value = { path: "src/file.ts", startLine, endLine: startLine };
  assert.equal(location.safeParse(value).success, runtime);
  assert.equal(jsonSchema("tools/scan-draft", "location")(value), json);
}
// Uniqueness is checked on raw values before parsing the text items.
const sourceFindingIds =
  artifactSchemaDocuments["tools/scan-draft"].$defs.finding.shape.provenance
    .shape.sourceFindingIds;
for (const values of [
  [null, null],
  [" ", " "],
]) {
  const result = sourceFindingIds.safeParse(values);
  assert.equal(result.success, false);
  assert.deepEqual(result.error?.issues, [
    {
      code: "custom",
      path: [1],
      message:
        "Array items must be unique: element at index 1 duplicates the one at index 0",
    },
  ]);
}

// Named legacy definitions and cross-document aliases remain addressable.
for (const [path, { $defs }] of Object.entries(
  artifactSchemaDocuments,
) as Array<[string, { $defs: Record<string, unknown> }]>) {
  for (const name of Object.keys($defs)) {
    if (name !== "attackPathFields")
      assert.ok(jsonSchema(path, name), `${path}: ${name}`);
  }
}
