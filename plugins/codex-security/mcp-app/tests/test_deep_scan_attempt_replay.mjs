import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { importNativeModule as importModule } from "./import-module.ts";
import { finding as fixtureFinding } from "./scan-draft-fixture.ts";

const app = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const plugin = path.resolve(app, "..");
const module = await importModule({
  loader: { ".md": "text" },
  stdin: {
    resolveDir: app,
    contents: [
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { DeepScanWorkerRunner } from "./src/deep-scan/worker-runner.ts";',
      'export { recordCodexSecurityWorkerScanDraft } from "./src/artifact-scan-draft.ts";',
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { createDeepScanArtifacts, ensureDeepScanDirectories } from "./src/deep-scan/artifacts.ts";',
    ].join("\n"),
  },
});
const {
  WorkbenchDeepScanStore,
  DeepScanWorkerRunner,
  recordCodexSecurityWorkerScanDraft,
  DeepScanCoordinator,
  createDeepScanArtifacts,
  ensureDeepScanDirectories,
} = module;
const execute = promisify(execFile);
for (const responseLosses of [3, 1]) await testResponseLoss(responseLosses);

async function testResponseLoss(responseLosses) {
  const root = await mkdtemp(path.join(tmpdir(), "deep-attempt-receipt-"));
  const target = path.join(root, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(root, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
  };
  const counts = new Map();
  const receipts = new Map();
  const raw = async (args) => {
    const { stdout } = await execute(
      process.env.PYTHON || "python3",
      [path.join(plugin, "scripts/workbench_db.py"), ...args],
      {
        env: environment,
        timeout: 30_000,
        maxBuffer: 4 * 1024 * 1024,
      },
    );
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(async (args) => {
    const result = await raw(args);
    const key =
      args[0] === "record-deep-scan-iteration"
        ? "merge"
        : args[0] === "upsert-deep-scan-worker" &&
            args[args.indexOf("--status") + 1] === "succeeded"
          ? "acceptance"
          : null;
    const operation =
      key === "acceptance"
        ? `${key}:${args[args.indexOf("--worker-id") + 1]}`
        : key;
    if (key) {
      counts.set(key, (counts.get(key) ?? 0) + 1);
      const receipt =
        key === "acceptance"
          ? result.deepScan.workerReceipt
          : result.deepScan.workers.find(
              (worker) => worker.id === args[args.indexOf("--worker-id") + 1],
            );
      if (!receipts.has(operation)) receipts.set(operation, receipt);
      else
        assert.deepEqual(
          receipt,
          receipts.get(operation),
          "replay returns the original operation receipt",
        );
      if (counts.get(key) <= responseLosses) {
        const error = new Error("fixture response lost after committed write");
        error.code = "ETIMEDOUT";
        throw error;
      }
    }
    return result;
  });
  try {
    await mkdir(target);
    await writeFile(path.join(target, "fixture.py"), "print('fixture')\n");
    const scanDir = path.join(root, "scan");
    await mkdir(scanDir, { mode: 0o700 });
    const registered = await raw([
      "register-cli-scan",
      "--scan-dir",
      scanDir,
      "--repository",
      target,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "deep",
        repository: target,
        target: { kind: "paths", paths: ["fixture.py"] },
      }),
    ]);
    const run = await store.begin({
      scanId: registered.scanId,
      threadId: "fixture-owner",
      scanRoot: path.join(root, "scans"),
    });
    const artifacts = createDeepScanArtifacts(run.scanDir);
    await ensureDeepScanDirectories(artifacts);
    const ref = "artifacts/evidence.txt";
    await writeFile(path.join(run.scanDir, ref), "shared evidence\n");
    let executions = 0;
    const runner = new DeepScanWorkerRunner({
      run,
      store,
      artifacts,
      pluginRoot: plugin,
      signal: new AbortController().signal,
      random: () => 0.5,
      log: () => {},
      retryDelaysMs: [],
      clock: { now: () => Date.now(), sleep: async () => {} },
      executor: {
        async run(request) {
          executions++;
          await request.onThreadStarted?.(`fixture-session-${executions}`);
          const draft = {
            scanId: run.scanId,
            findings: [],
            threatModel: { summary: "Synthetic fixture." },
          };
          const output = request.artifactContext.root;
          const review = {
            id: "review",
            label: "Fixture",
            disposition: "no_issue_found",
            receiptRefs: [ref],
          };
          draft.reviewState = {
            completeness: "complete",
            surfaces: [review],
            explicitExclusions: [],
            deferred: [],
          };
          if (executions === 2) {
            // The draft writer confirms the shared file before a worker-local shadow exists.
            await recordCodexSecurityWorkerScanDraft(
              {
                ...request.artifactContext,
                scanId: run.scanId,
                repoRoot: target,
              },
              draft,
            );
          } else {
            review.provenance = { scanReceiptRefs: [ref] };
            await writeFile(
              path.join(output, "result.json"),
              JSON.stringify(draft),
            );
          }
          await mkdir(path.dirname(path.join(output, ref)), {
            recursive: true,
          });
          await writeFile(path.join(output, ref), "worker evidence\n");
          return { threadId: `fixture-session-${executions}` };
        },
      },
    });
    if (responseLosses === 3) {
      const outcome = await runner
        .runDiscoveryWorker(randomUUID(), "discovery-1")
        .catch((error) => error);
      assert.equal(
        counts.get("acceptance"),
        3,
        "the runner must not multiply the store's retry policy",
      );
      assert.match(outcome.message, /response lost/);
      assert.equal(executions, 1);
      return;
    }
    const discovery = await runner.runDiscoveryWorker(
      randomUUID(),
      "discovery-1",
    );
    assert.equal(discovery.status, "succeeded", discovery.error?.message);
    assert.notEqual(
      discovery.worker.resultPath,
      path.join(discovery.worker.artifactDir, "result.json"),
    );
    const second = await runner.runDiscoveryWorker(randomUUID(), "discovery-2");
    assert.equal(second.status, "succeeded", second.error?.message);
    // Acceptance receipts are operation-specific, so only the first discovery loses a response.
    await rm(path.join(discovery.worker.artifactDir, "result.json"));
    const recover = async () =>
      new DeepScanCoordinator({
        run: await store.get(run.scanId, "fixture-owner"),
        store,
        pluginRoot: plugin,
        executor: {
          run: async () =>
            assert.fail("accepted recovery must not execute another model"),
        },
      });
    const coordinator = await recover();
    const recovered = await coordinator.recoverAcceptedDiscoveries();
    assert.deepEqual(
      recovered.map((worker) => worker.resultPath),
      [discovery.worker.resultPath, second.worker.resultPath],
    );
    const result = { scanId: run.scanId, findings: [] };
    assert.deepEqual(await coordinator.mergeAcceptedBatch(result, recovered), {
      counts: [0, 0],
      stop: undefined,
    });
    const refs = result.sourceCoverage.surfaces.map(
      (surface) => surface.receiptRefs[0],
    );
    assert.deepEqual(
      await Promise.all(
        refs.map((ref) => readFile(path.join(run.scanDir, ref), "utf8")),
      ),
      ["worker evidence\n", "shared evidence\n"],
    );
    const output = path.join(artifacts.dedupRoot, "dedup-1", "output");
    await mkdir(output, { recursive: true });
    const resultPath = path.join(output, "result.json");
    const bytes = JSON.stringify(result);
    await writeFile(resultPath, bytes);
    const id = randomUUID();
    const persisted = await store.recordIteration({
      id,
      scanId: run.scanId,
      resultPath,
      workerIds: recovered.map((worker) => worker.id),
      noNewStreak: 2,
      consecutiveErrors: 0,
    });
    assert.equal(counts.get("merge"), 2);
    assert.equal(executions, 2);
    assert.deepEqual(
      persisted.persistedDedupInputs.map((input) => input.attempt),
      [1, 1],
    );
    const frozen = persisted.persistedWorkers.find(
      (worker) => worker.id === id,
    ).acceptedResultPath;
    assert.notEqual(frozen, resultPath);
    await rm(resultPath);
    const resumed = await recover();
    assert.deepEqual(await resumed.restoreUnion(resultPath, recovered), {
      result,
      resultPath: frozen,
    });
    assert.equal(await readFile(frozen, "utf8"), bytes);
    await writeFile(discovery.worker.resultPath, "\n", { flag: "a" });
    await assert.rejects(
      resumed.recoverAcceptedDiscoveries(),
      /changed after acceptance/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

for (const [workflowVersion, missing] of [
  ["deep-security-scan/v2", true],
  ["deep-security-scan/v1", false],
  ["deep-security-scan/v1", true],
])
  await testAcceptedWriteupRecovery(workflowVersion, missing);

async function testAcceptedWriteupRecovery(workflowVersion, missing) {
  const root = await mkdtemp(path.join(tmpdir(), "deep-accepted-writeup-"));
  const target = path.join(root, "target");
  const environment = {
    ...process.env,
    CODEX_HOME: path.join(root, "home"),
    CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
  };
  const raw = async (args) => {
    const selected = [...args];
    if (selected[0] === "begin-deep-scan") {
      selected[selected.indexOf("--workflow-version") + 1] = workflowVersion;
    }
    const { stdout } = await execute(
      process.env.PYTHON || "python3",
      [path.join(plugin, "scripts/workbench_db.py"), ...selected],
      { env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024 },
    );
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(raw);
  try {
    await mkdir(target);
    await writeFile(path.join(target, "fixture.py"), "print('fixture')\n");
    const run = await store.begin({
      targetPath: target,
      scope: ".",
      threadId: "fixture-owner",
      scanRoot: path.join(root, "scans"),
    });
    assert.equal(run.workflowVersion, workflowVersion);
    const artifacts = createDeepScanArtifacts(run.scanDir);
    await ensureDeepScanDirectories(artifacts);
    const reportPath = "findings/accepted/accepted.md";
    await mkdir(path.join(run.scanDir, "findings", "accepted"), {
      recursive: true,
    });
    await writeFile(
      path.join(run.scanDir, reportPath),
      "Synthetic accepted evidence.\n",
    );
    const runner = new DeepScanWorkerRunner({
      run,
      store,
      artifacts,
      pluginRoot: plugin,
      signal: new AbortController().signal,
      random: () => 0.5,
      log: () => {},
      retryDelaysMs: [],
      clock: { now: () => Date.now(), sleep: async () => {} },
      executor: {
        async run(request) {
          await request.onThreadStarted?.("fixture-worker-session");
          await writeFile(
            path.join(request.artifactContext.root, "result.json"),
            JSON.stringify({
              scanId: run.scanId,
              findings: [
                {
                  ...fixtureFinding("accepted", "fixture.py"),
                  writeup: { reportPath },
                },
              ],
              reviewState: {
                completeness: "complete",
                surfaces: [],
                explicitExclusions: [],
                deferred: [],
              },
            }),
          );
          return { threadId: "fixture-worker-session" };
        },
      },
    });
    const accepted = await runner.runDiscoveryWorker(
      randomUUID(),
      "discovery-1",
    );
    assert.equal(accepted.status, "succeeded", accepted.error?.message);
    const before = await readFile(accepted.worker.resultPath);
    if (missing) await rm(path.join(run.scanDir, reportPath));
    const snapshot = await store.get(run.scanId, "fixture-owner");
    const resumed = new DeepScanCoordinator({
      run: snapshot,
      store,
      pluginRoot: plugin,
      executor: {
        run: async () =>
          assert.fail("accepted recovery must not rerun a model"),
      },
    });
    if (missing && workflowVersion === "deep-security-scan/v2") {
      await assert.rejects(
        resumed.recoverAcceptedDiscoveries(),
        /writeup.reportPath/,
      );
    } else {
      const recovered = await resumed.recoverAcceptedDiscoveries();
      assert.equal(recovered.length, 1);
      assert.equal(recovered[0].resultPath, accepted.worker.resultPath);
      const result = JSON.parse(
        await readFile(recovered[0].resultPath, "utf8"),
      );
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].writeup.reportPath, reportPath);
    }
    assert.deepEqual(
      await readFile(accepted.worker.resultPath),
      before,
      "recovery preserves accepted bytes",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
