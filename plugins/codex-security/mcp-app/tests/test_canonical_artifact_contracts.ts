import assert from "node:assert/strict";
import Ajv2020 from "ajv/dist/2020.js";
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
        `../../examples/completed-scan/${name}.json`,
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
  if (field === "writeup")
    assert.equal(
      validate({
        reportPath:
          "artifacts/deep-scan/passes/pass-1/findings/example/example.md",
      }),
      true,
    );
  assert.equal(
    validate(
      field === "writeup"
        ? { reportPath: "../findings/example/example.md" }
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
for (const path of ["findings.json", "coverage.json"]) {
  const document = structuredClone(manifest.example);
  const artifact = document.scan.artifacts.find(
    (entry: { path: string }) => entry.path === path,
  );
  document.scan.artifacts = document.scan.artifacts.filter(
    (entry: { path: string }) => entry.path !== path,
  );
  assert.equal(manifest.validate(document), false);
  document.scan.artifacts.push(artifact, artifact);
  assert.equal(manifest.validate(document), false);
}
const coverage = canonical.coverage;
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
