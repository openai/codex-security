import { jsonLines, readJson } from "./support/json.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type { ArtifactContext } from "../src/artifact-io.js";
import type {
  RawDiscoveryLocation,
  CompactDiscoveryCandidate,
} from "../src/artifact-discovery.js";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { importSource } from "./import-module.ts";

const {
  compactDiscoveryCandidateSchema,
  discoveryCandidatesInputSchema,
  listCodexSecurityCandidates,
  listCodexSecurityCandidatesInputSchema,
  recordCodexSecurityDiscoveryCandidates,
  workbenchDiscoveryCandidatesInputSchema,
  workbenchListCodexSecurityCandidatesInputSchema,
} = await importSource(
  path.join(import.meta.dirname, "../src/artifact-discovery.ts"),
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/server.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
);

const pluginRoot = path.join(import.meta.dirname, "../../");
const definitions = await readJson(
  pluginRoot,
  "schemas",
  "definitions",
  "discovery-candidate.schema.json",
);
const toolSchemas = await readJson(
  pluginRoot,
  "schemas",
  "tools",
  "discovery-candidates.schema.json",
);

assert.equal(
  definitions.$id,
  "codex-security://schemas/definitions/discovery-candidate.schema.json",
);
assert.equal(
  toolSchemas.$id,
  "codex-security://schemas/tools/discovery-candidates.schema.json",
);
assert.deepEqual(definitions.$defs.rawDiscoveryCandidate.required, [
  "cwe_ids",
  "locations",
  "summary",
  "evidence",
]);
assert.equal(
  definitions.$defs.rawDiscoveryCandidate.additionalProperties,
  false,
);
assert.equal(
  "candidate_id" in definitions.$defs.rawDiscoveryCandidate.properties,
  false,
);
assert.equal(definitions.$defs.discoveryCandidate.additionalProperties, true);
assert.deepEqual(toolSchemas.$defs.recordDiscoveryCandidatesInput.required, [
  "candidates",
]);
assert.deepEqual(
  toolSchemas.$defs.workbenchRecordDiscoveryCandidatesInput.required,
  ["scanId", "candidates"],
);
assert.deepEqual(toolSchemas.$defs.workbenchListCandidatesInput.required, [
  "scanId",
]);

const rootDirectories = createTemporaryDirectories(true);
const root = await rootDirectories.create("security-artifact-discovery-");
const runtimePluginRoot = path.join(root, "plugin");
const repoRoot = path.join(root, "repository");
try {
  await mkdir(path.join(repoRoot, "src"), { recursive: true });
  await mkdir(path.join(repoRoot, "support"), { recursive: true });
  await writeFile(
    path.join(repoRoot, "src", "routes.ts"),
    "first\nsecond\nthird\n",
  );
  await writeFile(
    path.join(repoRoot, "src", "query.ts"),
    "first\nsecond\nthird\n",
  );
  await writeFile(
    path.join(repoRoot, "support", "helper.ts"),
    "first\nsecond\n",
  );

  const scan = await createContext("scan", "scan");
  await verifyInputSchema();
  await verifyNormalizationAndPagination(scan);
  await verifyReaderPreservesSharedPhaseRecords(scan);
  await verifyNormalizerFailuresPreserveOutput(scan);
  await verifyDiffInventoryAllowsDeletedFiles();
  await verifyEmptyReplacement(scan);
  await verifyWorkerContext();
  await verifyMalformedLedgerIsNotModified();
  await verifySymlinkRejection();
} finally {
  await rootDirectories.cleanup();
}

async function verifyInputSchema() {
  const parseCandidate = (value: unknown) =>
    discoveryCandidatesInputSchema.safeParse({ candidates: [value] });
  const candidate = rawCandidate();
  assert.equal(parseCandidate(candidate).success, true);
  assert.equal(
    parseCandidate({
      ...candidate,
      cwe_ids: [" cwe-089 "],
    }).success,
    true,
  );
  assert.equal(
    parseCandidate({
      ...candidate,
      cwe_ids: [],
    }).success,
    true,
  );
  assert.equal(
    parseCandidate({
      ...candidate,
      candidate_id: "candidate-model-invented",
    }).success,
    false,
  );
  assert.equal(
    parseCandidate({
      ...candidate,
      locations: [],
    }).success,
    false,
  );
  assert.equal(
    parseCandidate({
      ...candidate,
      locations: [{ path: "src/routes.ts", start_line: 1, role: "invented" }],
    }).success,
    false,
  );
  assert.equal(
    parseCandidate({
      ...candidate,
      locations: [{ path: "src/routes.ts", start_line: 0, role: "sink" }],
    }).success,
    false,
  );
  assert.equal(
    parseCandidate({
      ...candidate,
      evidence: "  ",
    }).success,
    false,
  );
  assert.equal(
    discoveryCandidatesInputSchema.safeParse({ candidates: [] }).success,
    true,
  );
  assert.equal(
    discoveryCandidatesInputSchema.safeParse({ rows: [candidate] }).success,
    false,
  );
  assert.equal(
    discoveryCandidatesInputSchema.safeParse({
      scanId: "scan-fixture",
      candidates: [],
    }).success,
    false,
  );
  assert.equal(
    workbenchDiscoveryCandidatesInputSchema.safeParse({
      scanId: "scan-fixture",
      candidates: [],
    }).success,
    true,
  );
  assert.equal(
    workbenchDiscoveryCandidatesInputSchema.safeParse({
      candidates: [],
    }).success,
    false,
  );
  assert.equal(
    listCodexSecurityCandidatesInputSchema.safeParse({}).success,
    true,
  );
  assert.equal(
    listCodexSecurityCandidatesInputSchema.safeParse({
      scanId: "scan-fixture",
    }).success,
    false,
  );
  assert.equal(
    workbenchListCodexSecurityCandidatesInputSchema.safeParse({
      scanId: "scan-fixture",
    }).success,
    true,
  );
  assert.equal(
    workbenchListCodexSecurityCandidatesInputSchema.safeParse({}).success,
    false,
  );
  assert.equal(
    listCodexSecurityCandidatesInputSchema.safeParse({ cursor: "01" }).success,
    false,
  );
  assert.equal(
    listCodexSecurityCandidatesInputSchema.safeParse({ limit: 0 }).success,
    false,
  );
  assert.equal(
    listCodexSecurityCandidatesInputSchema.safeParse({ limit: 1001 }).success,
    false,
  );
}

async function verifyNormalizationAndPagination(context: ArtifactContext) {
  const first = rawCandidate({
    cwe_ids: ["cwe-089", "CWE-89"],
    summary: "Request input reaches a query",
    evidence: "The query interpolates the request parameter",
    context: "First independent review",
  });
  const repeated = rawCandidate({
    locations: [...first.locations].reverse(),
    summary: "A second review confirms the query",
    evidence: "Request data reaches the same query",
    context: "Second independent review",
  });
  const distinct = rawCandidate({
    instance: "sort parameter",
    summary: "A separate parameter reaches the query",
  });

  const result = await recordCodexSecurityDiscoveryCandidates(
    {
      candidates: [first, repeated, distinct],
    },
    context,
  );
  assert.deepEqual(result, { operation: "replace", candidatesRecorded: 2 });

  const all = await listCodexSecurityCandidates({}, context);
  assert.equal(all.rows.length, 2);
  for (const row of all.rows) {
    assert.equal(compactDiscoveryCandidateSchema.safeParse(row).success, true);
    assert.match(row.candidate_id, /^candidate-[a-f0-9]{16}$/u);
    assert.deepEqual(row.cwe_ids, ["CWE-89"]);
    assert.equal(
      row.locations.every(
        (location: RawDiscoveryLocation) => "end_line" in location,
      ),
      true,
    );
  }

  const merged = all.rows.find(
    (row: CompactDiscoveryCandidate) => row.instance === undefined,
  );
  assert.ok(merged);
  assert.deepEqual(merged.summary.split("\n"), [
    "A second review confirms the query",
    "Request input reaches a query",
  ]);
  assert.deepEqual(merged.context.split("\n"), [
    "First independent review",
    "Second independent review",
  ]);
  assert.ok(
    all.rows.some(
      (row: CompactDiscoveryCandidate) => row.instance === "sort parameter",
    ),
  );

  const firstPage = await listCodexSecurityCandidates({ limit: 1 }, context);
  assert.equal(firstPage.rows.length, 1);
  assert.equal(firstPage.nextCursor, "1");
  const secondPage = await listCodexSecurityCandidates(
    {
      cursor: firstPage.nextCursor,
      limit: 1,
    },
    context,
  );
  assert.deepEqual([...firstPage.rows, ...secondPage.rows], all.rows);
  assert.equal("nextCursor" in secondPage, false);
  await assert.rejects(
    listCodexSecurityCandidates({ cursor: "3" }, context),
    /cursor/u,
  );

  const discoveryDirectory = path.join(
    context.root,
    "artifacts",
    "02_discovery",
  );
  assert.deepEqual((await readdir(discoveryDirectory)).sort(), [
    "candidate_ledger.jsonl",
    "in_scope_files.txt",
  ]);
}

async function verifyNormalizerFailuresPreserveOutput(
  context: ArtifactContext,
) {
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  const original = await readFile(destination, "utf8");

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates(
      {
        candidates: [
          rawCandidate({
            locations: [{ path: "src/routes.ts", start_line: 9, role: "sink" }],
          }),
        ],
      },
      context,
    ),
    (error) =>
      error instanceof Error &&
      /line range/u.test(error.message) &&
      !error.message.includes(context.root) &&
      !error.message.includes(context.repoRoot),
  );
  assert.equal(await readFile(destination, "utf8"), original);

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates(
      {
        candidates: [
          rawCandidate({
            locations: [
              { path: "support/helper.ts", start_line: 1, role: "sink" },
            ],
          }),
        ],
      },
      context,
    ),
    /at least one in-scope file/u,
  );
  assert.equal(await readFile(destination, "utf8"), original);

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates(
      {
        candidates: [
          rawCandidate({
            locations: [{ path: "../outside.ts", start_line: 1, role: "sink" }],
          }),
        ],
      },
      context,
    ),
    /repository-relative path without traversal/u,
  );
  assert.equal(await readFile(destination, "utf8"), original);

  const inventory = path.join(path.dirname(destination), "in_scope_files.txt");
  const scope = await readFile(inventory);
  await writeFile(inventory, Buffer.from([0xff]));
  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates({ candidates: [] }, context),
    /UTF-8|encoded data/,
  );
  assert.equal(await readFile(destination, "utf8"), original);
  await writeFile(inventory, scope);

  assert.deepEqual(
    await recordCodexSecurityDiscoveryCandidates(
      { candidates: [rawCandidate()] },
      { ...context, pluginRoot: undefined },
    ),
    { operation: "replace", candidatesRecorded: 1 },
  );
}

async function verifyDiffInventoryAllowsDeletedFiles() {
  const context = await createContext("diff-output", "scan");
  const repository = path.join(root, "diff-repository");
  await mkdir(repository);
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", repository, ...args], {
      encoding: "utf8",
    }).trim();
  const commit = (stage = true) => {
    if (stage) git("add", "-A");
    git(
      "-c",
      "user.name=Synthetic",
      "-c",
      "user.email=synthetic@example.test",
      "commit",
      "-qm",
      "fixture",
    );
    return git("rev-parse", "HEAD");
  };
  git("init", "-q");
  await writeFile(
    path.join(repository, "deleted.ts"),
    "one\rtwo\r\nthree\nfour",
  );
  await writeFile(path.join(repository, "changed.ts"), "one\ntwo\n");
  await writeFile(path.join(repository, "support.ts"), "support\n");
  const linkBlob = execFileSync(
    "git",
    ["-C", repository, "hash-object", "-w", "--stdin"],
    { input: "support.ts", encoding: "utf8" },
  ).trim();
  git("add", "-A");
  git(
    "update-index",
    "--add",
    "--cacheinfo",
    `120000,${linkBlob},base-link.ts`,
  );
  const baseRevision = commit(false);
  await rm(path.join(repository, "deleted.ts"));
  await writeFile(path.join(repository, "changed.ts"), "one\ntwo\nthree\n");
  await writeFile(path.join(repository, "head-only.ts"), "one\ntwo\n");
  git("add", "-A");
  git("update-index", "--add", "--cacheinfo", `120000,${linkBlob},link.ts`);
  const headRevision = commit(false);
  await rm(path.join(repository, "head-only.ts"));
  await writeFile(path.join(repository, "changed.ts"), "current\n");
  await writeFile(
    path.join(repository, "unrelated.ts"),
    "unrelated current source\n",
  );
  commit();
  if (process.platform === "win32") {
    git("mv", "changed.ts", "temporary.ts");
    git("mv", "temporary.ts", "CHANGED.ts");
    commit();
  }
  const inventory = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "in_scope_files.txt",
  );
  await writeFile(inventory, "deleted.ts\r\nchanged.ts\r\nhead-only.ts\r\n");
  const record = (scan: ArtifactContext, paths: [string, number][]) =>
    recordCodexSecurityDiscoveryCandidates(
      {
        candidates: [
          rawCandidate({
            locations: paths.map(([path, end_line]) => ({
              path,
              start_line: 1,
              end_line,
              role: "sink",
            })),
          }),
        ],
      },
      scan,
    );
  for (const kind of ["commit", "range", "working_tree"]) {
    const scan: ArtifactContext = {
      ...context,
      repoRoot: repository,
      pluginRoot,
      pythonCommand: undefined,
      mode: "diff",
      targetContract: { diffTarget: { kind, baseRevision, headRevision } },
    };
    if (kind === "working_tree")
      await writeFile(inventory, "deleted.ts\nchanged.ts\n");
    const sources: [string, number][] =
      kind === "working_tree"
        ? [
            ["deleted.ts", 4],
            ["changed.ts", 1],
            ["support.ts", 1],
          ]
        : [
            ["deleted.ts", 4],
            ["changed.ts", 3],
            ["head-only.ts", 2],
            ["support.ts", 1],
          ];
    assert.deepEqual(await record(scan, sources), {
      operation: "replace",
      candidatesRecorded: 1,
    });
    const destination = path.join(
      path.dirname(inventory),
      "candidate_ledger.jsonl",
    );
    const accepted = await readFile(destination, "utf8");
    await assert.rejects(
      record(
        { ...scan, pythonCommand: path.join(root, "missing-python") },
        sources,
      ),
      { code: "ENOENT" },
    );
    assert.equal(await readFile(destination, "utf8"), accepted);
    await assert.rejects(
      record(
        {
          ...scan,
          targetContract: {
            diffTarget: {
              kind,
              baseRevision: "missing-revision",
              headRevision,
            },
          },
        },
        sources,
      ),
      /fatal: (?:ambiguous argument|bad revision)/,
    );
    for (const [file, line] of sources.filter(
      ([file]) => file !== "support.ts",
    )) {
      await assert.rejects(record(scan, [[file, line + 1]]), /line range/);
      assert.equal(await readFile(destination, "utf8"), accepted);
    }
    for (const file of [
      "missing.ts",
      "link.ts",
      "base-link.ts",
      "../outside.ts",
    ]) {
      await assert.rejects(record(scan, [[file, 1]]));
      assert.equal(await readFile(destination, "utf8"), accepted);
    }
    await assert.rejects(
      record(scan, [["support.ts", 1]]),
      /at least one in-scope/,
    );
    if (kind === "working_tree") {
      git(
        "rm",
        "--cached",
        process.platform === "win32" ? "CHANGED.ts" : "changed.ts",
      );
      await writeFile(
        path.join(repository, ".git", "info", "exclude"),
        "changed.ts\nCHANGED.ts\n",
      );
      await record(scan, [["changed.ts", 1]]);
      await assert.rejects(record(scan, [["changed.ts", 2]]), /line range/);
    }
    if (process.platform === "win32") {
      for (const prefix of ["", "./", ".\\", ".//./"]) {
        await record(scan, [
          [`${prefix}SUPPORT.TS`, 1],
          [`${prefix}DELETED.TS`, 4],
          [`${prefix}CHANGED.ts`, kind === "working_tree" ? 1 : 3],
        ]);
        const candidate = JSON.parse(await readFile(destination, "utf8"));
        assert.ok(
          candidate.locations.some(
            (location: { path: string }) => location.path === "deleted.ts",
          ),
        );
        if (kind !== "working_tree")
          assert.ok(
            candidate.locations.some(
              (location: { path: string }) => location.path === "changed.ts",
            ),
          );
      }
      if (kind !== "working_tree") {
        await assert.rejects(
          record(scan, [["UNRELATED.TS", 1]]),
          /no selected source/,
        );
      }
    }
    if (kind !== "working_tree")
      await assert.rejects(
        record(scan, [["unrelated.ts", 1]]),
        /no selected source/,
      );
  }
}

async function verifyReaderPreservesSharedPhaseRecords(
  context: ArtifactContext,
) {
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  const original = await readFile(destination, "utf8");
  const rows = original
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  rows[0].validation = {
    disposition: "reportable",
    evidence: "The existing validation phase confirmed the affected code path.",
  };
  rows[0].attack_path = {
    disposition: "reportable",
    evidence: "The existing attack-path phase confirmed request reachability.",
  };
  await writeFile(destination, jsonLines(rows));

  const page = await listCodexSecurityCandidates({}, context);
  assert.deepEqual(page.rows, rows);

  await writeFile(destination, original);
}

async function verifyEmptyReplacement(context: ArtifactContext) {
  const result = await recordCodexSecurityDiscoveryCandidates(
    { candidates: [] },
    context,
  );
  assert.deepEqual(result, { operation: "replace", candidatesRecorded: 0 });
  assert.deepEqual(await listCodexSecurityCandidates({}, context), {
    rows: [],
  });
  const content = await readFile(
    path.join(
      context.root,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl",
    ),
    "utf8",
  );
  assert.equal(content, "");
}

async function verifyWorkerContext() {
  const worker = await createContext("worker-output", "worker");
  const result = await recordCodexSecurityDiscoveryCandidates(
    {
      candidates: [rawCandidate()],
    },
    worker,
  );
  assert.deepEqual(result, { operation: "replace", candidatesRecorded: 1 });
  const page = await listCodexSecurityCandidates({}, worker);
  assert.equal(page.rows.length, 1);
  assert.match(page.rows[0].candidate_id, /^candidate-[a-f0-9]{16}$/u);
}

async function verifyMalformedLedgerIsNotModified() {
  const context = await createContext("malformed-output", "scan");
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  const malformed = "{not-valid-json}\n";
  await writeFile(destination, malformed);
  await assert.rejects(
    listCodexSecurityCandidates({}, context),
    /JSON|schema/u,
  );
  assert.equal(await readFile(destination, "utf8"), malformed);
}

async function verifySymlinkRejection() {
  if (process.platform === "win32") return;

  const context = await createContext("unsafe-output", "scan");
  const outside = path.join(root, "outside.jsonl");
  await writeFile(outside, "outside must not change\n");
  const destination = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  await symlink(outside, destination, "file");

  await assert.rejects(
    recordCodexSecurityDiscoveryCandidates(
      { candidates: [rawCandidate()] },
      context,
    ),
    /safe|regular|symbolic|symlink/u,
  );
  assert.equal(await readFile(outside, "utf8"), "outside must not change\n");
  await assert.rejects(
    listCodexSecurityCandidates({}, context),
    /safe|regular|symbolic|symlink/u,
  );
}

async function createContext(
  name: string,
  layout: ArtifactContext["layout"],
): Promise<ArtifactContext> {
  const artifactRoot = path.join(root, name);
  const discoveryDirectory = path.join(
    artifactRoot,
    "artifacts",
    "02_discovery",
  );
  await mkdir(discoveryDirectory, { recursive: true });
  await writeFile(
    path.join(discoveryDirectory, "in_scope_files.txt"),
    "src/routes.ts\nsrc/query.ts\n",
  );
  return {
    root: artifactRoot,
    repoRoot,
    layout,
    pluginRoot: runtimePluginRoot,
    pythonCommand: path.join(root, "python-must-not-run"),
  };
}

function rawCandidate(overrides = {}) {
  return {
    cwe_ids: ["CWE-89"],
    locations: [
      { path: "src/routes.ts", start_line: 1, role: "entrypoint" },
      { path: "src/query.ts", start_line: 2, role: "sink" },
    ],
    summary: "Request data reaches an unsafe query",
    evidence: "The request parameter is interpolated into the query",
    ...overrides,
  };
}
