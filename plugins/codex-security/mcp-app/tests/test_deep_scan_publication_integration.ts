import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test, type TestContext } from "node:test";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { buildServer } from "./build-server.ts";
import { importModule } from "./import-module.ts";
import type { RunArtifactWorkbench } from "../src/artifact-context.ts";
import type {
  DeepScanRunState,
  DeepScanWorkerMutation,
} from "../src/deep-scan/types.ts";
import type {
  DeepScanPublication,
  ScanDraftInput,
} from "../src/artifact-scan-draft.ts";

type HostModule = Pick<
  typeof import("../src/deep-scan/store.ts"),
  "WorkbenchDeepScanStore"
> &
  Pick<
    typeof import("../src/deep-scan/coordinator.ts"),
    "DeepScanCoordinator"
  > &
  Pick<
    typeof import("../src/artifact-context.ts"),
    "createScanArtifactContext"
  > &
  Pick<
    typeof import("../src/artifact-scan-draft.ts"),
    "recordCodexSecurityScanDraftViaWorkbench"
  >;
type ToolResult = Awaited<ReturnType<Client["callTool"]>>;
interface FixturePaths {
  target?: string;
  scanRoot?: string;
}
type Scenario = readonly [
  label: string,
  offsets: readonly [number, number],
  ids: readonly [string, string],
  paths?: FixturePaths,
  recoveryOnly?: boolean,
  reducerLabels?: readonly [string, string],
];
type PublicationFixture = Awaited<ReturnType<typeof createFixture>>;

const execFileAsync = promisify(execFile);
const testsRoot = path.dirname(fileURLToPath(import.meta.url));
const mcpAppRoot = path.resolve(testsRoot, "..");
const pluginRoot = path.resolve(mcpAppRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
const python = process.env.PYTHON?.trim() || "python3";
const owner = "publication-test-owner";
const coverage = {
  completeness: "complete",
  surfaces: [],
  explicitExclusions: [],
  deferred: [],
};
const highId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const lowId = "00000000-0000-4000-8000-000000000001";
const bundleRoot = await mkdtemp(
  path.join(tmpdir(), "deep-publication-bundle-"),
);
after(() => rm(bundleRoot, { recursive: true, force: true }));
const serverPath = path.join(bundleRoot, "server.cjs");
await buildServer(serverPath, {
  define: {
    __dirname: JSON.stringify(mcpAppRoot),
    "import.meta.url": "__filename",
  },
  target: "node20",
});
const host = (await importModule({
  stdin: {
    contents: [
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";',
    ].join("\n"),
    resolveDir: mcpAppRoot,
  },
  loader: { ".md": "text" },
})) as HostModule;
const {
  WorkbenchDeepScanStore,
  DeepScanCoordinator,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = host;

test("public partial drafts retain checkpoints after coordinator adoption", async (t) => {
  const fixture = await createFixture(t);
  const { run, store, call, runWorkbench } = fixture;
  assertSuccess(
    await call(
      "record_codex_security_scan_draft",
      partial(run, "generation-one"),
    ),
  );
  const first = await checkpoints(run);
  // Main retains the submitted checkpoint and normalized parent snapshot.
  assert.equal(Object.keys(first).length, 2);
  const claim = await store.claimCoordinator({
    scanId: run.scanId,
    threadId: owner,
  });
  assert.equal(claim.acquired, true);
  assert.equal(claim.run.coordinatorGeneration, 2);

  assertSuccess(
    await call(
      "record_codex_security_scan_draft",
      partial(run, "generation-two"),
    ),
  );
  const retained = await checkpoints(run);
  assert.equal(Object.keys(retained).length, 4);
  for (const [name, bytes] of Object.entries(first))
    assert.equal(retained[name], bytes);
  assert.deepEqual(
    new Set(
      Object.values(retained).flatMap((bytes) =>
        JSON.parse(bytes).coverage.deferred.map(
          (item: { candidateId: string }) => item.candidateId,
        ),
      ),
    ),
    new Set(["generation-one", "generation-two"]),
  );

  const before = await snapshot(run);
  assertToolError(
    await call("record_codex_security_scan_draft", {
      ...partial(run, "unfenced-final"),
      complete: true,
    }),
    /current coordinator lease/,
  );
  const context = await createScanArtifactContext(run.scanId, runWorkbench, {
    requireRunning: true,
  });
  await assert.rejects(
    recordCodexSecurityScanDraftViaWorkbench(
      context,
      partial(run, "stale-generation"),
      runWorkbench,
      undefined,
      { coordinatorGeneration: 1, resultPath: null },
    ),
    /newer generation/,
  );
  assertToolError(
    await call("complete_codex_security_scan", { scanId: run.scanId }),
    /deep/i,
  );
  assert.deepEqual(await snapshot(run), before);
  assert.deepEqual(await readdir(path.join(run.scanDir, "drafts")), []);
});

const scenarios: Scenario[] = [
  ["increasing timestamps", [1, 2], [highId, lowId]],
  ["equal timestamps and descending UUIDs", [1, 1], [highId, lowId]],
  ["decreasing timestamps", [2, 1], [lowId, highId]],
  ["equal timestamps and ascending UUIDs", [1, 1], [lowId, highId]],
  [
    "legacy reducer label",
    [1, 1],
    [highId, lowId],
    undefined,
    false,
    ["dedup-0002-legacy", "dedup-0001"],
  ],
  [
    "large reducer sequence",
    [1, 1],
    [highId, lowId],
    undefined,
    false,
    ["dedup-9007199254740992", "dedup-9007199254740993"],
  ],
  [
    "scan root collision, live publication",
    [1, 1],
    [highId, lowId],
    { scanRoot: "dedup-123/scans" },
  ],
  [
    "scan root collision, recovery",
    [1, 1],
    [highId, lowId],
    { scanRoot: "dedup-123/scans" },
    true,
  ],
  [
    "target name collision, live publication",
    [1, 1],
    [highId, lowId],
    { target: "dedup-456-target" },
  ],
  [
    "target name collision, recovery",
    [1, 1],
    [highId, lowId],
    { target: "dedup-456-target" },
    true,
  ],
];
for (const [
  label,
  offsets,
  ids,
  paths,
  recoveryOnly,
  reducerLabels,
] of scenarios) {
  test(`selected reducer survives recovery and public completion: ${label}`, async (t) => {
    const fixture = await createFixture(t, paths);
    const { run, store, call, runWorkbench, instant } = fixture;
    assertSuccess(
      await call(
        "record_codex_security_scan_draft",
        partial(run, "parent-checkpoint-only"),
      ),
    );
    const parentCheckpoints = await checkpoints(run);
    assert.equal(Object.keys(parentCheckpoints).length, 2);
    const claimed = await store.claimCoordinator({
      scanId: run.scanId,
      threadId: owner,
    });
    assert.equal(claimed.run.coordinatorGeneration, 2);
    assert.equal(claimed.run.config.stopAfterNoNew, 4);
    const results = await commitReducers(fixture, offsets, ids, reducerLabels);
    const persisted = await store.get(run.scanId, owner);
    assert.equal(persisted.noNewStreak, 4);
    assert.ok(persisted.persistedWorkers);
    assert.deepEqual(
      persisted.persistedWorkers
        .filter((worker) => worker.kind === "discovery")
        .map((worker) => worker.mergeState),
      Array(4).fill("merged"),
    );
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });
    const publish = async (index: number, coordinatorGeneration = 2) =>
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        {
          ...JSON.parse(await readFile(results[index], "utf8")),
          coverage,
        },
        runWorkbench,
        undefined,
        { coordinatorGeneration, resultPath: results[index] },
      );

    if (!recoveryOnly) {
      await publish(1);
      const selected = await snapshot(run);
      await assert.rejects(publish(0), /superseded publication selection/);
      await assert.rejects(publish(1, 1), /newer generation/);
      assert.deepEqual(await snapshot(run), selected);
    }

    const publications: DeepScanPublication[] = [];
    const coordinator = new DeepScanCoordinator({
      run: persisted,
      store,
      pluginRoot,
      executor: {
        run() {
          throw new Error("Recovery must reuse the committed workers.");
        },
      },
      clock: { now: () => Date.parse(instant), sleep: async () => {} },
      onComplete: async (draft, signal, publication) => {
        publications.push(publication);
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          draft,
          runWorkbench,
          signal,
          publication,
        );
        await assertInterleavedProgressRetained(fixture);
      },
    });
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 30_000);
    assert.equal(
      terminal?.status,
      "succeeded",
      terminal?.error ?? "Coordinator did not succeed",
    );
    assert.deepEqual(publications, [
      { coordinatorGeneration: 2, resultPath: results[1] },
    ]);

    const beforeCompletion = await snapshot(run);
    const lateDraft = partial(run, "late-parent-checkpoint");
    assertToolError(await call("record_codex_security_scan_draft", lateDraft));
    assert.deepEqual(await snapshot(run), beforeCompletion);
    assertSuccess(
      await call("complete_codex_security_scan", { scanId: run.scanId }),
    );
    const sealed = await snapshot(run);
    const manifest = JSON.parse(sealed.files["scan-manifest.json"]);
    assert.equal(
      manifest.scan.threatModel.summary,
      reducerLabels?.[1] ?? "dedup-0002",
    );
    assert.ok(manifest.scan.sealedAt);
    assert.deepEqual(JSON.parse(sealed.files["findings.json"]).findings, []);
    assert.deepEqual(JSON.parse(sealed.files["coverage.json"]).deferred, []);
    assert.ok(sealed.files["report.md"]);
    for (const [name, bytes] of Object.entries(parentCheckpoints)) {
      assert.equal(
        sealed.checkpoints[name],
        bytes,
        "completion retains the immutable parent checkpoint",
      );
    }
    assert.deepEqual(sealed.checkpoints, beforeCompletion.checkpoints);
    assertSuccess(
      await call("complete_codex_security_scan", { scanId: run.scanId }),
    );
    assert.deepEqual(
      await snapshot(run),
      sealed,
      "completion replay is byte-stable",
    );
    assertToolError(await call("record_codex_security_scan_draft", lateDraft));
    assert.deepEqual(
      await snapshot(run),
      sealed,
      "late writes cannot replace sealed results",
    );
  });
}

for (const [claimed, outputFailure] of [
  [false, false],
  [false, true],
  [true, false],
  [true, true],
]) {
  test(`legacy discovery parent with claimed=${claimed} ${outputFailure ? "retains failure after an output write error" : "retains progress before first completion"}`, async (t) => {
    const fixture = await createFixture(t);
    const { run, store, call, runWorkbench } = fixture;
    if (claimed) {
      const claim = await store.claimCoordinator({
        scanId: run.scanId,
        threadId: owner,
      });
      assert.equal(claim.acquired, true);
      assert.equal(claim.run.coordinatorGeneration, 2);
    }
    await commitReducers(fixture, [1, 2], [highId, lowId]);
    const discovery = path.join(run.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    await writeFile(path.join(discovery, "in_scope_files.txt"), "fixture.py\n");
    await writeFile(path.join(discovery, "candidate_ledger.jsonl"), "");
    const manifestPath = path.join(run.scanDir, "coordinator-manifest.json");
    await writeFile(manifestPath, "{}\n");
    const terminal = await store.finish({
      scanId: run.scanId,
      reason: "saturated",
      manifestPath,
      omittedWorkerIds: [],
    });
    assert.equal(terminal.status, "succeeded");
    assert.equal(terminal.coordinatorGeneration, claimed ? 2 : 1);
    assert.equal(terminal.manifestPath, manifestPath);
    if (!outputFailure) {
      assertSuccess(
        await call(
          "record_codex_security_scan_draft",
          partial(run, "legacy-progress"),
        ),
      );
      const progress = await checkpoints(run);
      assert.ok(Object.keys(progress).length > 0);
      assertToolError(
        await call("complete_codex_security_scan", { scanId: run.scanId }),
        /incomplete/,
      );
      assert.deepEqual(await checkpoints(run), progress);
    }
    assertSuccess(
      await call("record_codex_security_scan_draft", {
        scanId: run.scanId,
        complete: true,
        findings: [],
        coverage,
      }),
    );
    if (outputFailure) {
      const report = path.join(run.scanDir, "report.html");
      await mkdir(report);
      assertToolError(
        await call("complete_codex_security_scan", { scanId: run.scanId }),
        /report\.html/,
      );
      await rm(report, { recursive: true });
      const context = await runWorkbench(["get-scan", "--scan-id", run.scanId]);
      assert.equal(
        (context.scan as { progress: { status: string } }).progress.status,
        "failed",
      );
      const interrupted = await snapshot(run);
      assertToolError(
        await call("record_codex_security_scan_draft", {
          ...partial(run, "late-legacy-draft"),
          complete: true,
          threatModel: { summary: "Late replacement" },
        }),
      );
      assert.deepEqual(await snapshot(run), interrupted);
      assertToolError(
        await call("complete_codex_security_scan", { scanId: run.scanId }),
        /running/,
      );
    } else {
      assertSuccess(
        await call("complete_codex_security_scan", { scanId: run.scanId }),
      );
    }
  });
}

for (const complete of [false, true]) {
  test(`legacy terminal aggregate rejects late public drafts with complete=${complete}`, async (t) => {
    const fixture = await createFixture(t);
    const { run, store, call, runWorkbench } = fixture;
    await commitReducers(fixture, [1, 2], [highId, lowId]);
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });
    const draft: ScanDraftInput = {
      scanId: run.scanId,
      complete: true,
      findings: [],
      coverage,
      threatModel: { summary: "Selected aggregate" },
    };
    await assert.rejects(
      recordCodexSecurityScanDraftViaWorkbench(context, draft, async (args) => {
        await runWorkbench(args);
        throw new Error("Synthetic lost publication response");
      }),
      /lost publication response/,
    );
    const published = await snapshot(run);
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      draft,
      runWorkbench,
    );
    assert.deepEqual(await snapshot(run), published);
    await assertInterleavedProgressRetained(fixture);
    const terminal = await store.finish({
      scanId: run.scanId,
      reason: "saturated",
      manifestPath: path.join(run.scanDir, "scan-manifest.json"),
      omittedWorkerIds: [],
    });
    assert.equal(terminal.status, "succeeded");
    assert.equal(terminal.coordinatorGeneration, 1);
    const report = path.join(run.scanDir, "report.html");
    await mkdir(report);
    assertToolError(
      await call("complete_codex_security_scan", { scanId: run.scanId }),
      /report\.html/,
    );
    await rm(report, { recursive: true });
    const interrupted = await snapshot(run);
    assertToolError(
      await call("record_codex_security_scan_draft", {
        ...partial(run, "late-progress"),
        complete,
        threatModel: { summary: "Late replacement" },
      }),
      /terminal|publication/,
    );
    assert.deepEqual(await snapshot(run), interrupted);
    assertSuccess(
      await call("complete_codex_security_scan", { scanId: run.scanId }),
    );
    const completed = await snapshot(run);
    assert.deepEqual(
      JSON.parse(completed.files["coverage.json"]),
      JSON.parse(interrupted.files["coverage.json"]),
    );
    assert.equal(
      JSON.parse(completed.files["scan-manifest.json"]).scan.threatModel
        .summary,
      "Selected aggregate",
    );
    assert.deepEqual(completed.checkpoints, interrupted.checkpoints);
  });
}

for (const claimed of [false, true]) {
  test(`partial drafts retain a capped publication with claimed=${claimed}`, async (t) => {
    const fixture = await createFixture(t);
    const { run, store, call, runWorkbench, instant } = fixture;
    const selectedRun = claimed
      ? (await store.claimCoordinator({ scanId: run.scanId, threadId: owner }))
          .run
      : run;
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });
    const elapsedSeconds = ((run.config.maxTimeHours ?? 1) + 1) * 3_600;
    fixture.setTime(elapsedSeconds);
    const deadline = Date.parse(instant) + elapsedSeconds * 1_000;
    const coordinator = new DeepScanCoordinator({
      run: selectedRun,
      store,
      pluginRoot,
      executor: {
        run() {
          throw new Error("Expired coordinator must not start a worker.");
        },
      },
      clock: { now: () => deadline, sleep: async () => {} },
      onComplete: async (draft, signal, publication) => {
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          draft,
          runWorkbench,
          signal,
          claimed ? publication : undefined,
        );
        await assertInterleavedProgressRetained(fixture);
      },
    });
    coordinator.start();
    const terminal = await coordinator.wait(undefined, 30_000);
    assert.equal(
      terminal?.status,
      "succeeded",
      terminal?.error ?? "Coordinator did not succeed",
    );
    assert.equal(terminal?.terminalReason, "capped");

    const report = path.join(run.scanDir, "report.html");
    await mkdir(report);
    assertToolError(
      await call("complete_codex_security_scan", { scanId: run.scanId }),
      /report\.html/,
    );
    await rm(report, { recursive: true });
    const interrupted = await snapshot(run);
    assert.equal(
      JSON.parse(interrupted.files["coverage.json"]).completeness,
      "partial",
    );
    assertToolError(
      await call(
        "record_codex_security_scan_draft",
        partial(run, "late-progress"),
      ),
      /coordinator lease|terminal/,
    );
    assert.deepEqual(await snapshot(run), interrupted);
    assertSuccess(
      await call("complete_codex_security_scan", { scanId: run.scanId }),
    );
    const completed = await snapshot(run);
    assert.ok(JSON.parse(completed.files["scan-manifest.json"]).scan.sealedAt);
    assert.deepEqual(
      JSON.parse(completed.files["coverage.json"]),
      JSON.parse(interrupted.files["coverage.json"]),
    );
    assert.deepEqual(completed.checkpoints, interrupted.checkpoints);
    assert.equal((await store.get(run.scanId, owner)).terminalReason, "capped");
  });
}

for (const status of ["failed", "interrupted"] as const) {
  test(`selected publication retains ${status} and exact failure replay`, async (t) => {
    const { run, store, runWorkbench } = await createFixture(t);
    await store.claimCoordinator({ scanId: run.scanId, threadId: owner });
    const context = await createScanArtifactContext(run.scanId, runWorkbench, {
      requireRunning: true,
    });
    const draft: ScanDraftInput = {
      scanId: run.scanId,
      findings: [],
      coverage,
    };
    const publication = { coordinatorGeneration: 2, resultPath: null };
    await assert.rejects(
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        draft,
        async (args) => {
          await runWorkbench(args);
          throw new Error("Synthetic lost publication response");
        },
        undefined,
        publication,
      ),
      /lost publication response/,
    );
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      draft,
      runWorkbench,
      undefined,
      publication,
    );
    const message = "Synthetic failure after publication";
    const failed = await store.fail(run.scanId, message, status);
    assert.equal(failed.status, status);
    assert.equal(
      failed.manifestPath,
      path.join(run.scanDir, "scan-manifest.json"),
    );
    assert.deepEqual(await store.fail(run.scanId, message, status), failed);
    await assert.rejects(
      store.fail(run.scanId, message + " changed", status),
      /immutable/,
    );
    const differentManifest = path.join(run.scanDir, "different-manifest.json");
    await writeFile(differentManifest, "{}\n");
    await assert.rejects(
      store.fail(run.scanId, message, status, differentManifest),
      /immutable/,
    );
  });
}

async function assertInterleavedProgressRetained(fixture: PublicationFixture) {
  const { run, call } = fixture;
  const before = await snapshot(run);
  const progress = {
    scanId: run.scanId,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: [
        {
          id: "interleaved-progress",
          candidateId: "interleaved-progress",
          reason: "Synthetic review remains pending.",
          paths: ["fixture.py"],
        },
      ],
    },
    threatModel: { summary: "Unselected progress model" },
  };
  assertSuccess(await call("record_codex_security_scan_draft", progress));
  const after = await snapshot(run);
  assert.deepEqual(after.files, before.files);
  for (const [name, contents] of Object.entries(before.checkpoints))
    assert.equal(after.checkpoints[name], contents);
  const added = Object.keys(after.checkpoints).filter(
    (name) => !(name in before.checkpoints),
  );
  assert.equal(added.length, 1);
  assert.deepEqual(JSON.parse(after.checkpoints[added[0]]), progress);
}

async function createFixture(t: TestContext, paths: FixturePaths = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "deep-publication-"));
  let client: Client | undefined;
  t.after(async () => {
    await client?.close();
    await rm(root, { recursive: true, force: true });
  });
  const targetPath = path.join(root, paths.target ?? "target");
  await mkdir(targetPath);
  await writeFile(
    path.join(targetPath, "fixture.py"),
    "# Synthetic publication fixture\n",
  );
  const environment: Record<string, string> = Object.fromEntries(
    Object.entries({
      ...process.env,
      CODEX_HOME: path.join(root, "home"),
      CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      CODEX_SECURITY_SCAN_ROOT: path.join(root, paths.scanRoot ?? "scans"),
    }).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
  delete environment.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
  const instant = new Date().toISOString();
  let now = instant;
  const runWorkbench: RunArtifactWorkbench = async (args, input) => {
    const child = execFileAsync(
      python,
      [path.join(testsRoot, "clock_workbench.py"), workbenchPath, ...args],
      {
        cwd: pluginRoot,
        env: { ...environment, TEST_WORKBENCH_NOW: now },
        timeout: 30_000,
        maxBuffer: 4 * 1024 * 1024,
      },
    );
    assert.ok(child.child.stdin);
    child.child.stdin.end(input);
    return JSON.parse((await child).stdout) as Record<string, unknown>;
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  const run = await store.begin({
    targetPath,
    scope: ".",
    threadId: owner,
    scanRoot: environment.CODEX_SECURITY_SCAN_ROOT,
  });
  client = new Client({ name: "publication-integration", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath, "--stdio"],
    cwd: mcpAppRoot,
    env: environment,
    stderr: "pipe",
  });
  if (transport.stderr instanceof Readable) transport.stderr.resume();
  await client.connect(transport);
  return {
    run,
    store,
    runWorkbench,
    instant,
    setTime(offset: number) {
      now = new Date(Date.parse(instant) + offset * 1_000).toISOString();
    },
    call(name: string, args: Record<string, unknown> | ScanDraftInput) {
      assert.ok(client);
      return client.callTool({
        name,
        arguments: { ...args },
        _meta: { "openai/threadId": owner },
      });
    },
  };
}

async function commitReducers(
  fixture: PublicationFixture,
  offsets: readonly [number, number],
  ids: readonly [string, string],
  reducerLabels?: readonly [string, string],
) {
  const { run, store } = fixture;
  const results = [];
  for (let batch = 0; batch < 2; batch++) {
    const workerIds = [];
    for (let index = batch * 2 + 1; index <= batch * 2 + 2; index++) {
      const id = `10000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
      const label = `discovery-${String(index).padStart(4, "0")}`;
      const artifact = await workerArtifact(run, "workers", label);
      const update: DeepScanWorkerMutation = {
        id,
        scanId: run.scanId,
        kind: "discovery",
        status: "running",
        attempt: 1,
        ...artifact,
      };
      await store.updateWorker(update);
      const resultManifestPath = path.join(artifact.artifactDir, "result.json");
      await writeFile(
        resultManifestPath,
        JSON.stringify({ scanId: run.scanId, findings: [], coverage }),
      );
      await store.updateWorker({
        ...update,
        status: "succeeded",
        resultManifestPath,
      });
      workerIds.push(id);
    }
    const label =
      reducerLabels?.[batch] ?? `dedup-${String(batch + 1).padStart(4, "0")}`;
    const artifact = await workerArtifact(run, "dedup", label);
    const id = ids[batch];
    await store.claimDedup({ id, scanId: run.scanId, workerIds, ...artifact });
    await store.updateWorker({
      id,
      scanId: run.scanId,
      kind: "dedup",
      status: "running",
      attempt: 1,
      ...artifact,
    });
    const resultManifestPath = path.join(artifact.artifactDir, "result.json");
    await writeFile(
      resultManifestPath,
      JSON.stringify({
        scanId: run.scanId,
        findings: [],
        threatModel: { summary: label },
      }),
    );
    fixture.setTime(offsets[batch]);
    await store.commitDedup({
      id,
      scanId: run.scanId,
      resultManifestPath,
      newFindings: 0,
    });
    fixture.setTime(0);
    results.push(resultManifestPath);
  }
  return results;
}

async function workerArtifact(
  run: DeepScanRunState,
  kind: "workers" | "dedup",
  label: string,
) {
  const artifactDir = path.join(
    run.scanDir,
    "artifacts",
    "deep_discovery",
    kind,
    label,
    "output",
  );
  const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
  await mkdir(artifactDir, { recursive: true });
  await writeFile(promptPath, `Synthetic ${label}\n`);
  return { artifactDir, promptPath };
}

function partial(run: DeepScanRunState, candidateId: string): ScanDraftInput {
  return {
    scanId: run.scanId,
    complete: false,
    findings: [],
    coverage: {
      ...coverage,
      completeness: "partial",
      deferred: [
        {
          candidateId,
          reason: "Synthetic review remains pending.",
          paths: ["fixture.py"],
        },
      ],
    },
  };
}

async function checkpoints(run: DeepScanRunState) {
  const directory = path.join(run.scanDir, "checkpoints");
  const files: Record<string, string> = {};
  for (const name of await readdir(directory))
    files[name] = await readFile(path.join(directory, name), "utf8");
  return files;
}

async function snapshot(run: DeepScanRunState) {
  const files: Record<string, string> = {};
  for (const name of [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
    "checkpoint-head.json",
    "threatmodel.md",
  ]) {
    try {
      files[name] = await readFile(path.join(run.scanDir, name), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return { files, checkpoints: await checkpoints(run) };
}

function assertSuccess(result: ToolResult) {
  assert.notEqual(result.isError, true, JSON.stringify(result));
}

function assertToolError(result: ToolResult, pattern?: RegExp) {
  assert.equal(result.isError, true, JSON.stringify(result));
  if (pattern) assert.match(JSON.stringify(result), pattern);
}
