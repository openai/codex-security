import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const execFileAsync = promisify(execFile);
const appRoot = fileURLToPath(new URL("..", import.meta.url));
const pluginRoot = path.resolve(appRoot, "..");
const bundle = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityWorkerScanDraft, recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";'
    ].join("\n"),
    resolveDir: appRoot
  },
  loader: { ".md": "text" },
  format: "esm",
  platform: "node",
  write: false
});
const { DeepScanCoordinator, WorkbenchDeepScanStore, createScanArtifactContext, recordCodexSecurityWorkerScanDraft, recordCodexSecurityScanDraftViaWorkbench } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);
const root = await mkdtemp(path.join(tmpdir(), "deep-scan-sequence-"));
const targetPath = path.join(root, "target");
const stateDir = path.join(root, "state");
const codexHome = path.join(root, "home");
const environment = { ...process.env, CODEX_HOME: codexHome, CODEX_SECURITY_STATE_DIR: stateDir };
const python = process.env.PYTHON?.trim() || "python3";
const runWorkbench = async (args) => {
  const { stdout } = await execFileAsync(python, [path.join(pluginRoot, "scripts/workbench_db.py"), ...args], {
    cwd: pluginRoot, env: environment, timeout: 30_000, maxBuffer: 4 * 1024 * 1024
  });
  return JSON.parse(stdout);
};
let coordinator;
try {
  await mkdir(targetPath);
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
  await writeFile(path.join(codexHome, "codex-security/config.toml"),
    "[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = 3\nmax_discovery_runs = 2\n");
  const threadId = "sequence-recovery-owner";
  let store = new WorkbenchDeepScanStore(runWorkbench);
  const { run } = await store.begin({ targetPath, scope: ".", threadId, scanRoot: path.join(root, "scans") });
  await store.claimCoordinator({ scanId: run.scanId, threadId });
  const workers = [];
  for (const sequence of [1, 2]) {
    const label = `discovery-${String(sequence).padStart(4, "0")}`;
    const workerRoot = path.join(run.scanDir, "artifacts/deep_discovery/workers", label);
    const worker = {
      id: randomUUID(), scanId: run.scanId, kind: "discovery", status: "running",
      promptPath: path.join(workerRoot, "prompt.md"), artifactDir: path.join(workerRoot, "output"), attempt: 1
    };
    await mkdir(worker.artifactDir, { recursive: true });
    await writeFile(worker.promptPath, `Original ${label} prompt.\n`);
    await store.updateWorker(worker);
    workers.push(worker);
  }
  const checkpointContext = (worker) => ({
    root: worker.artifactDir, repoRoot: targetPath, layout: "worker", scanId: run.scanId, workerId: worker.id,
    onCheckpoint: async (checkpointPath) => {
      await runWorkbench(["record-scan-checkpoint", "--scan-id", run.scanId, "--checkpoint-path", checkpointPath]);
    }
  });
  const draft = (complete) => ({
    scanId: run.scanId, complete, findings: [],
    coverage: {
      completeness: complete ? "complete" : "partial", reviewedFiles: complete ? ["fixture.py"] : [],
      surfaces: [], explicitExclusions: [], deferred: []
    }
  });
  await recordCodexSecurityWorkerScanDraft(checkpointContext(workers[1]), draft(false));
  const originalPrompt = await readFile(workers[1].promptPath);
  const originalHead = await readFile(path.join(workers[1].artifactDir, "checkpoint-head.json"));
  const rotated = [];
  let claim;
  for (const generation of [3, 4]) {
    await execFileAsync(python, ["-c", [
      "import sqlite3, sys",
      "with sqlite3.connect(sys.argv[1]) as connection:",
      "    connection.execute(\"UPDATE deep_scan_runs SET phase = 'discovery', updated_at = '2000-01-01T00:00:00Z' WHERE scan_id = ?\", (sys.argv[2],))"
    ].join("\n"), path.join(stateDir, "workbench.sqlite3"), run.scanId]);
    store = new WorkbenchDeepScanStore(runWorkbench);
    claim = await store.claimCoordinator({ scanId: run.scanId, threadId });
    assert.equal(claim.acquired, true);
    assert.equal(claim.run.coordinatorGeneration, generation);
    assert.equal(claim.run.dispatchedCount, 1, "only the checkpoint-backed discovery retains its dispatched slot");
    assert.equal(claim.run.persistedWorkers.find((worker) => worker.id === workers[0].id).status, "canceled");
    const worker = claim.run.persistedWorkers.find((worker) => worker.id === workers[1].id);
    assert.equal(worker.status, "queued");
    assert.equal(worker.completionSequence, undefined, "the checkpoint is not a completed discovery");
    assert.notEqual(worker.artifactDir, rotated.at(-1)?.artifactDir ?? workers[1].artifactDir);
    assert.deepEqual(await readFile(worker.promptPath), originalPrompt);
    assert.deepEqual(await readFile(path.join(worker.artifactDir, "checkpoint-head.json")), originalHead);
    rotated.push(worker);
    if (generation === 3) {
      await store.updateWorker({ ...worker, scanId: run.scanId, status: "running", attempt: 2 });
    }
  }
  // An expired process can still finish in its old output, which must remain isolated.
  await writeFile(path.join(workers[1].artifactDir, "result.json"), "old writer output\n");
  const discoveries = [];
  coordinator = new DeepScanCoordinator({
    run: claim.run, store, pluginRoot, threadId, retryDelaysMs: [],
    onComplete: async (completed) => {
      const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
      await recordCodexSecurityScanDraftViaWorkbench(context, { ...completed, complete: true }, runWorkbench);
    },
    executor: {
      async run(request) {
        if (request.kind === "discovery") {
          const worker = { id: request.artifactContext.workerId, artifactDir: request.artifactContext.root };
          discoveries.push({ id: worker.id, directory: path.basename(path.dirname(worker.artifactDir)) });
          if (discoveries.length === 1) {
            assert.equal(worker.id, workers[1].id);
            assert.equal(worker.artifactDir, rotated[1].artifactDir);
            assert.match(await readFile(request.promptPath, "utf8"), /Continue this saved discovery/);
          }
          await recordCodexSecurityWorkerScanDraft(checkpointContext(worker), draft(true));
        } else {
          await writeFile(path.join(request.artifactContext.root, "result.json"), JSON.stringify({ scanId: run.scanId, findings: [] }));
        }
        return { finalResponse: "Complete", threadId: `fixture-${randomUUID()}` };
      }
    }
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 30_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.terminalReason, "capped");
  assert.equal(terminal.dispatchedCount, 2);
  assert.equal(discoveries.length, 2);
  assert.equal(discoveries[1].directory, "discovery-0003");
  assert.notEqual(discoveries[1].id, workers[1].id);
  assert.deepEqual(rotated.map((worker) => path.basename(path.dirname(worker.artifactDir))), [
    "discovery-0002-generation-3", "discovery-0002-generation-4"
  ]);
  assert.deepEqual(await readFile(workers[1].promptPath), originalPrompt);
  assert.equal(await readFile(path.join(workers[1].artifactDir, "result.json"), "utf8"), "old writer output\n");
  const completed = await store.get(run.scanId, threadId);
  assert.equal(completed.persistedWorkers.filter((worker) => worker.kind === "discovery" && worker.status === "succeeded").length, 2);
} finally {
  coordinator?.cancel("fixture cleanup");
  await coordinator?.settled();
  await rm(root, { recursive: true, force: true });
}
