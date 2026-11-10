import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import * as z from "zod/v4";
import { readJson } from "./support/json.ts";

const ajv = new Ajv2020({ strict: false, validateFormats: false });

const canonical = Object.fromEntries(
  await Promise.all(
    ["findings", "scan-manifest", "coverage"].map(async (name) => {
      const schema = await readJson(
        import.meta.dirname,
        `../../schemas/${name}.schema.json`,
      );
      const example = await readJson(
        import.meta.dirname,
        `../../examples/${name === "coverage" ? "legacy-completed-scan" : "completed-scan"}/${name}.json`,
      );
      const validate = ajv.compile(schema);
      assert.equal(validate(example), true, JSON.stringify(validate.errors));
      return [name, { schema, example, validate }];
    }),
  ),
);

// Persisted findings retain legacy values that semantic scan drafts reject.
// Compile the extracted Finding just as SDK deduplication does.
const findingSchema = {
  ...canonical.findings.schema.properties.findings.items,
  $defs: canonical.findings.schema.$defs,
};
const validateFinding = ajv.compile(findingSchema);
const finding = canonical.findings.example.findings[0];
for (const fields of [
  { title: " " },
  {
    locations: [
      { path: "../legacy.ts", startLine: Number.MAX_SAFE_INTEGER + 1 },
    ],
  },
  { rootCause: "", root_cause: null, code_evidence: null },
  { validation: { status: null, evidence: [" "] } },
  { validation: { evidence_refs: ["legacy evidence"] } },
  { code_evidence: [{ id: "legacy", code: "example()" }] },
  {
    attackPath: {
      dataFlow: { evidence_refs: ["legacy evidence"] },
      data_flow: { evidence_refs: ["legacy evidence"] },
      dataflow: { evidence_refs: ["legacy evidence"] },
      reachability: { evidence_refs: ["legacy evidence"] },
      evidence_refs: ["legacy evidence"],
    },
  },
  { attackPath: { dataflow: { extra: true }, impact: { why: " " } } },
  { provenance: { source: " ", sourceFindingIds: [1, 1] } },
])
  assert.equal(
    validateFinding({ ...finding, ...fields }),
    true,
    JSON.stringify(fields),
  );

// Reused nested union branches must keep their constraints and error paths.
assert.equal(
  validateFinding({
    ...finding,
    attackPath: { likelihood: { rationale: 42 } },
  }),
  false,
);
assert.deepEqual(
  validateFinding.errors?.map(({ instancePath, keyword, message }) => ({
    instancePath,
    keyword,
    message,
  })),
  [
    {
      instancePath: "/attackPath/likelihood/rationale",
      keyword: "type",
      message: "must be string",
    },
  ],
);
assert.equal(validateFinding({ ...finding, code_evidence: 42 }), false);
assert.deepEqual(validateFinding.errors?.[0].params, {
  type: ["array", "null"],
});

// Recovery retains the document definitions when validating extracted fragments.
for (const field of ["writeup", "remediationTests", "preventiveControls"]) {
  const validate = ajv.compile({
    ...findingSchema.properties[field],
    $defs: findingSchema.$defs,
  });
  assert.equal(
    validate(
      field === "writeup"
        ? { reportPath: "findings/example/example.md" }
        : ["example"],
    ),
    true,
  );
  assert.equal(
    validate(
      field === "writeup"
        ? { reportPath: "findings/example/different.md" }
        : [""],
    ),
    false,
  );
}

const manifest = canonical["scan-manifest"];
for (const kind of [
  "git_revision",
  "git_worktree",
  "git_diff",
  "directory_snapshot",
]) {
  const document = structuredClone(manifest.example);
  document.scan.target.kind = kind;
  delete document.scan.target.revision;
  delete document.scan.target.snapshotDigest;
  assert.equal(manifest.validate(document), false);
  if (kind === "git_revision") document.scan.target.revision = "";
  else
    document.scan.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`;
  assert.equal(manifest.validate(document), true);
}
for (const directory of ["completed-scan", "legacy-completed-scan"]) {
  const root = join(import.meta.dirname, "../../examples", directory);
  const example = await readJson(root, "scan-manifest.json");
  assert.equal(manifest.validate(example), true);
  const paths = ["findings.json"];
  assert.equal(example.scan.findingsRef, "findings.json");
  if (example.scan.coverageRef) paths.push("coverage.json");
  for (const path of paths) {
    const document = structuredClone(example);
    const artifact = document.scan.artifacts.find(
      (entry: { path: string }) => entry.path === path,
    );
    const bytes = await readFile(join(root, path));
    assert.equal(JSON.parse(bytes.toString("utf8")).scanId, document.scan.id);
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      artifact.sha256,
    );
    document.scan.artifacts = document.scan.artifacts.filter(
      (entry: { path: string }) => entry.path !== path,
    );
    assert.equal(manifest.validate(document), false);
    document.scan.artifacts.push(artifact, artifact);
    assert.equal(manifest.validate(document), false);
  }
}
for (const field of ["mode", "review"]) {
  const document = structuredClone(manifest.example);
  delete document.scan[field];
  assert.equal(manifest.validate(document), false);
}
const coverage = canonical.coverage;
const validateCoverage = new Ajv2020().compile(coverage.schema);
const coverageInZod = z.fromJSONSchema(coverage.schema);
for (const fields of [
  { deferred: [{ id: "task", reason: "Review remains." }] },
  {
    surfaces: [
      {
        id: "surface",
        label: "Source",
        disposition: "needs_follow_up",
        receiptRefs: [],
      },
    ],
  },
])
  assert.equal(coverage.validate({ ...coverage.example, ...fields }), true);

for (const [path, valid] of [
  [".", true],
  ["./src//./name:part/", true],
  [" ", true],
  ["\u0085", true],
  ["\ufeff", true],
  ["src/\u007f", true],
  ["src/..\u2028", true],
  ["src/\u2029emoji-😀", true],
  ["", false],
  ["..", false],
  ["src/../outside", false],
  ["src/\u2028/..", false],
  ["/absolute", false],
  ["C:relative", false],
  ["src\\file", false],
  ["name\n", false],
  ["src/\u0000file", false],
  ["\ud800", false],
  ["\udfff", false],
] as const) {
  const deferred = [{ id: "task", reason: "Review remains.", paths: [path] }];
  const document = { ...coverage.example, deferred };
  assert.equal(validateCoverage(document), valid, JSON.stringify(path));
  assert.equal(
    coverageInZod.safeParse(document).success,
    valid,
    JSON.stringify(path),
  );
}

// Shared named definitions remain available to consumers that extract fragments.
assert.deepEqual(Object.keys(findingSchema.$defs).sort(), [
  "assessment",
  "dataFlow",
  "stringList",
]);
assert.deepEqual(Object.keys(manifest.schema.$defs), ["stringList"]);

// Patch-risk JSON keywords remain authoritative even when they are export metadata.
const patchRisk = await readJson(
  import.meta.dirname,
  "../../schemas/patch-risk-assessment.schema.json",
);
ajv.addSchema(patchRisk);
for (const [pointer, value, keyword] of [
  ["/$defs/stringList", ["same", "same"], "uniqueItems"],
  [
    "/properties/autoMergeExclusions",
    ["migration", "migration"],
    "uniqueItems",
  ],
  [
    "/properties/evidencePlan/items/properties/outcomes",
    { confirmed: "merge" },
    "minProperties",
  ],
  [
    "/properties/evidencePlan/items/properties/outcomes",
    { confirmed: "merge", rejected: "unsupported" },
    "enum",
  ],
] as const) {
  const validate = ajv.getSchema(`${patchRisk.$id}#${pointer}`)!;
  assert.equal(validate(value), false);
  assert.equal(validate.errors?.[0]?.keyword, keyword);
}
