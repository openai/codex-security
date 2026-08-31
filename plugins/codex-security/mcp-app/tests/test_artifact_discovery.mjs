import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/artifact-discovery.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  compactDiscoveryCandidateSchema,
  discoveryCandidatesInputSchema,
  listCodexSecurityCandidates,
  listCodexSecurityCandidatesInputSchema,
  rawDiscoveryCandidateSchema,
  recordCodexSecurityDiscoveryCandidates,
  workbenchDiscoveryCandidatesInputSchema,
  workbenchListCodexSecurityCandidatesInputSchema
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const definitions = JSON.parse(await readFile(path.join(
  pluginRoot,
  "schemas",
  "definitions",
  "discovery-candidate.schema.json"
), "utf8"));
const toolSchemas = JSON.parse(await readFile(path.join(
  pluginRoot,
  "schemas",
  "tools",
  "discovery-candidates.schema.json"
), "utf8"));

assert.equal(
  definitions.$id,
  "codex-security://schemas/definitions/discovery-candidate.schema.json"
);
assert.equal(
  toolSchemas.$id,
  "codex-security://schemas/tools/discovery-candidates.schema.json"
);
assert.deepEqual(definitions.$defs.rawDiscoveryCandidate.required, [
  "cwe_ids",
  "locations",
  "summary",
  "evidence"
]);
assert.equal(definitions.$defs.rawDiscoveryCandidate.additionalProperties, false);
assert.equal("candidate_id" in definitions.$defs.rawDiscoveryCandidate.properties, false);
assert.equal(definitions.$defs.discoveryCandidate.additionalProperties, true);
assert.deepEqual(
  toolSchemas.$defs.recordDiscoveryCandidatesInput.required,
  ["candidates"]
);
assert.deepEqual(
  toolSchemas.$defs.workbenchRecordDiscoveryCandidatesInput.required,
  ["scanId", "candidates"]
);
assert.deepEqual(toolSchemas.$defs.workbenchListCandidatesInput.required, ["scanId"]);

const root = await realpath(await mkdtemp(path.join(tmpdir(), "security-artifact-discovery-")));
try {
  const repoRoot = path.join(root, "repository");
  await mkdir(path.join(repoRoot, "src"), { recursive: true });
  await mkdir(path.join(repoRoot, "support"), { recursive: true });
  await writeFile(path.join(repoRoot, "src", "routes.ts"), "first\nsecond\nthird\n");
  await writeFile(path.join(repoRoot, "src", "query.ts"), "first\nsecond\nthird\n");
  await writeFile(path.join(repoRoot, "support", "helper.ts"), "first\nsecond\n");

  const scan = await createContext(root, repoRoot, "scan", "scan");
  await verifyInputSchema();
  await verifyNormalizationAndPagination(scan);
  await verifyReaderPreservesSharedPhaseRecords(scan);
  await verifyNormalizerFailuresPreserveOutput(scan);
  await verifyDiffInventoryAllowsDeletedFiles(root, repoRoot);
  await verifyEmptyReplacement(scan);
  await verifyWorkerContext(root, repoRoot);
  await verifyMalformedLedgerIsNotModified(root, repoRoot);
  await verifySymlinkRejection(root, repoRoot);
} finally {
  await rm(root, { recursive: true, force: true });
}

async function verifyInputSchema() {
  const candidate = rawCandidate();
  assert.equal(rawDiscoveryCandidateSchema.safeParse(candidate).success, true);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    cwe_ids: [" cwe-089 "]
  }).success, true);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    cwe_ids: []
  }).success, true);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    candidate_id: "candidate-model-invented"
  }).success, false);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    locations: []
  }).success, false);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    locations: [{ path: "src/routes.ts", start_line: 1, role: "invented" }]
  }).success, false);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    locations: [{ path: "src/routes.ts", start_line: 0, role: "sink" }]
  }).success, false);
  assert.equal(rawDiscoveryCandidateSchema.safeParse({
    ...candidate,
    evidence: "  "
  }).success, false);
  assert.equal(discoveryCandidatesInputSchema.safeParse({ candidates: [] }).success, true);
  assert.equal(discoveryCandidatesInputSchema.safeParse({ rows: [candidate] }).success, false);
  assert.equal(discoveryCandidatesInputSchema.safeParse({
    scanId: "scan-fixture",
    candidates: []
  }).success, false);
  assert.equal(workbenchDiscoveryCandidatesInputSchema.safeParse({
    scanId: "scan-fixture",
    candidates: []
  }).success, true);
  assert.equal(workbenchDiscoveryCandidatesInputSchema.safeParse({
    candidates: []
  }).success, false);
  assert.equal(listCodexSecurityCandidatesInputSchema.safeParse({}).success, true);
  assert.equal(listCodexSecurityCandidatesInputSchema.safeParse({
    scanId: "scan-fixture"
  }).success, false);
  assert.equal(workbenchListCodexSecurityCandidatesInputSchema.safeParse({
    scanId: "scan-fixture"
  }).success, true);
  assert.equal(workbenchListCodexSecurityCandidatesInputSchema.safeParse({}).success, false);
  assert.equal(listCodexSecurityCandidatesInputSchema.safeParse({ cursor: "01" }).success, false);
  assert.equal(listCodexSecurityCandidatesInputSchema.safeParse({ limit: 0 }).success, false);
  assert.equal(listCodexSecurityCandidatesInputSchema.safeParse({ limit: 1001 }).success, false);
}

async function verifyNormalizationAndPagination(context) {
  const first = rawCandidate({
    cwe_ids: ["cwe-089", "CWE-89"],
    summary: "Request input reaches a query",
    evidence: "The query interpolates the request parameter",
    context: "First independent review"
  });
  const repeated = rawCandidate({
    locations: [...first.locations].reverse(),
    summary: "A second review confirms the query",
    evidence: "Request data reaches the same query",
    context: "Second independent review"
  });
  const distinct = rawCandidate({
    instance: "sort parameter",
    summary: "A separate parameter reaches the query"
  });

  const result = await recordCodexSecurityDiscoveryCandidates({
    candidates: [first, repeated, distinct]
  }, context);
  assert.deepEqual(result, { operation: "replace", candidatesRecorded: 2 });

  const all = await listCodexSecurityCandidates({}, context);
  assert.equal(all.rows.length, 2);
  for (const row of all.rows) {
    assert.equal(compactDiscoveryCandidateSchema.safeParse(row).success, true);
    assert.match(row.candidate_id, /^candidate-[a-f0-9]{16}$/u);
    assert.deepEqual(row.cwe_ids, ["CWE-89"]);
    assert.equal(row.locations.every((location) => "end_line" in location), true);
  }

  const merged = all.rows.find((row) => row.instance === undefined);
  assert.ok(merged);
  assert.deepEqual(merged.summary.split("\n"), [
    "A second review confirms the query",
    "Request input reaches a query"
  ]);
  assert.deepEqual(merged.context.split("\n"), [
    "First independent review",
    "Second independent review"
  ]);
  assert.ok(all.rows.some((row) => row.instance === "sort parameter"));

  const firstPage = await listCodexSecurityCandidates({ limit: 1 }, context);
  assert.equal(firstPage.rows.length, 1);
  assert.equal(firstPage.nextCursor, "1");
  const secondPage = await listCodexSecurityCandidates({
    cursor: firstPage.nextCursor,
    limit: 1
  }, context);
  assert.deepEqual([...firstPage.rows, ...secondPage.rows], all.rows);
  assert.equal("nextCursor" in secondPage, false);
  await assert.rejects(
    listCodexSecurityCandidates({ cursor: "3" }, context),
    /cursor/u
  );

  const discoveryDirectory = path.join(context.root, "artifacts", "02_discovery");
  assert.deepEqual((await readdir(discoveryDirectory)).sort(), [
    "candidate_ledger.jsonl",
    "in_scope_files.txt"
  ]);
}

async function verifyNormalizerFailuresPreserveOutput(context) {
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl"
  );
  const original = await readFile(destination, "utf8");

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({
      candidates: [rawCandidate({
        locations: [{ path: "src/routes.ts", start_line: 9, role: "sink" }]
      })]
    }, context),
    (error) => error instanceof Error
      && /line range/u.test(error.message)
      && !error.message.includes(context.root)
      && !error.message.includes(context.repoRoot)
  );
  assert.equal(await readFile(destination, "utf8"), original);

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({
      candidates: [rawCandidate({
        locations: [{ path: "support/helper.ts", start_line: 1, role: "sink" }]
      })]
    }, context),
    /at least one in-scope file/u
  );
  assert.equal(await readFile(destination, "utf8"), original);

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({
      candidates: [rawCandidate({
        locations: [{ path: "../outside.ts", start_line: 1, role: "sink" }]
      })]
    }, context),
    /repository-relative path without traversal/u
  );
  assert.equal(await readFile(destination, "utf8"), original);

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({
      candidates: [rawCandidate()]
    }, { ...context, pluginRoot: undefined }),
    /plugin runtime is not bound/u
  );
  assert.equal(await readFile(destination, "utf8"), original);
}

async function verifyDiffInventoryAllowsDeletedFiles(root, repoRoot) {
  const context = await createContext(root, repoRoot, "diff-output", "scan");
  const inventory = path.join(context.root, "artifacts", "02_discovery", "in_scope_files.txt");
  await writeFile(inventory, "src/deleted-guard.ts\nsrc/routes.ts\nsrc/query.ts\n");

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({ candidates: [rawCandidate()] }, context),
    /in-scope file row 1/u
  );

  const diffContext = { ...context, mode: "diff" };
  assert.deepEqual(
    await recordCodexSecurityDiscoveryCandidates({ candidates: [rawCandidate()] }, diffContext),
    { operation: "replace", candidatesRecorded: 1 }
  );
  assert.equal((await listCodexSecurityCandidates({}, diffContext)).rows.length, 1);
}

async function verifyReaderPreservesSharedPhaseRecords(context) {
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl"
  );
  const original = await readFile(destination, "utf8");
  const rows = original.trimEnd().split("\n").map((line) => JSON.parse(line));
  rows[0].validation = {
    disposition: "reportable",
    evidence: "The existing validation phase confirmed the affected code path."
  };
  rows[0].attack_path = {
    disposition: "reportable",
    evidence: "The existing attack-path phase confirmed request reachability."
  };
  await writeFile(destination, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);

  const page = await listCodexSecurityCandidates({}, context);
  assert.deepEqual(page.rows, rows);
  assert.deepEqual(page.rows[0].validation, rows[0].validation);
  assert.deepEqual(page.rows[0].attack_path, rows[0].attack_path);

  await writeFile(destination, original);
}

async function verifyEmptyReplacement(context) {
  const result = await recordCodexSecurityDiscoveryCandidates({ candidates: [] }, context);
  assert.deepEqual(result, { operation: "replace", candidatesRecorded: 0 });
  assert.deepEqual(await listCodexSecurityCandidates({}, context), { rows: [] });
  const content = await readFile(path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl"
  ), "utf8");
  assert.equal(content, "");
}

async function verifyWorkerContext(root, repoRoot) {
  const worker = await createContext(root, repoRoot, "worker-output", "worker");
  const result = await recordCodexSecurityDiscoveryCandidates({
    candidates: [rawCandidate()]
  }, worker);
  assert.deepEqual(result, { operation: "replace", candidatesRecorded: 1 });
  const page = await listCodexSecurityCandidates({}, worker);
  assert.equal(page.rows.length, 1);
  assert.match(page.rows[0].candidate_id, /^candidate-[a-f0-9]{16}$/u);
}

async function verifyMalformedLedgerIsNotModified(root, repoRoot) {
  const context = await createContext(root, repoRoot, "malformed-output", "scan");
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl"
  );
  const malformed = "{not-valid-json}\n";
  await writeFile(destination, malformed);
  await assert.rejects(listCodexSecurityCandidates({}, context), /JSON|schema/u);
  assert.equal(await readFile(destination, "utf8"), malformed);
}

async function verifySymlinkRejection(root, repoRoot) {
  if (process.platform === "win32") return;

  const context = await createContext(root, repoRoot, "unsafe-output", "scan");
  const outside = path.join(root, "outside.jsonl");
  await writeFile(outside, "outside must not change\n");
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl"
  );
  await symlink(outside, destination, "file");

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({ candidates: [rawCandidate()] }, context),
    /safe|regular|symbolic|symlink/u
  );
  assert.equal(await readFile(outside, "utf8"), "outside must not change\n");
  await assert.rejects(listCodexSecurityCandidates({}, context), /safe|regular|symbolic|symlink/u);
}

async function createContext(root, repoRoot, name, layout) {
  const artifactRoot = path.join(root, name);
  const discoveryDirectory = path.join(artifactRoot, "artifacts", "02_discovery");
  await mkdir(discoveryDirectory, { recursive: true });
  await writeFile(
    path.join(discoveryDirectory, "in_scope_files.txt"),
    "src/routes.ts\nsrc/query.ts\n"
  );
  return {
    root: artifactRoot,
    repoRoot,
    layout,
    pluginRoot
  };
}

function rawCandidate(overrides = {}) {
  return {
    cwe_ids: ["CWE-89"],
    locations: [
      { path: "src/routes.ts", start_line: 1, role: "entrypoint" },
      { path: "src/query.ts", start_line: 2, role: "sink" }
    ],
    summary: "Request data reaches an unsafe query",
    evidence: "The request parameter is interpolated into the query",
    ...overrides
  };
}
