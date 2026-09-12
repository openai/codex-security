import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { build } from "esbuild";

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const exec = promisify(execFile);
const bundled = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";',
    ].join("\n"),
    resolveDir: path.join(pluginRoot, "mcp-app"),
  },
  format: "esm", platform: "node", loader: { ".md": "text" }, write: false,
});
export async function publishCoverageFixture(root, completeness, { resume = false } = {}) {
  const runtimePath = path.join(root, "fixture-runtime.mjs");
  await writeFile(runtimePath, bundled.outputFiles[0].contents);
  const { DeepScanCoordinator, WorkbenchDeepScanStore, createScanArtifactContext, recordCodexSecurityScanDraftViaWorkbench } = await import(pathToFileURL(runtimePath).href);
  const targetPath = path.join(root, "target");
  const codexHome = path.join(root, "codex-home");
  const scanRoot = path.join(root, "scans");
  const threadId = "coverage-fixture-owner";
  const statuses = completeness === "partial" ? ["partial", "complete", "unknown"]
    : completeness === "unknown" ? ["unknown", "complete"] : ["complete"];
  await mkdir(scanRoot, { mode: 0o700 });
  await mkdir(targetPath, { recursive: true });
  await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
  await writeFile(path.join(targetPath, "source.py"), "# Synthetic source\n");
  await writeFile(path.join(codexHome, "codex-security", "config.toml"),
    `[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = ${statuses.length}\nmax_discovery_runs = ${statuses.length}\n`);
  const runWorkbench = async (args) => {
    const { stdout } = await exec(process.env.PYTHON || "python3", [path.join(pluginRoot, "scripts", "workbench_db.py"), ...args], {
      env: { ...process.env, CODEX_HOME: codexHome, CODEX_SECURITY_STATE_DIR: path.join(root, "state") },
    });
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  let { run } = await store.begin({ targetPath, scope: ".", threadId, scanRoot });
  const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
  const rawSources = new Map();
  const writeDiscovery = async (artifactDir, index) => {
    const status = statuses[index];
    const pending = completeness === "partial" && status !== "complete";
    const coverage = {
      completeness: status,
      surfaces: [{ id: "shared-surface", label: "Archive route", disposition: pending ? "needs_follow_up" : "no_issue_found", receiptRefs: ["artifacts/review.md"] }],
      explicitExclusions: [{ pattern: "vendor/", reason: "External dependency." }],
      deferred: pending ? [{ id: "same-id", candidateId: "candidate-1", reason: index === 0 ? "Verify entry boundaries." : "Verify symbolic links.", paths: ["source.py"], surfaceIds: ["shared-surface"] }] : [],
      openQuestions: pending ? [{ question: `Deployment question ${index + 1}.` }] : [],
    };
    await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
    await writeFile(path.join(artifactDir, "artifacts", "review.md"), "Synthetic review evidence.\n");
    const resultPath = path.join(artifactDir, "result.json");
    const bytes = JSON.stringify({ scanId: run.scanId, complete: true, findings: [], coverage });
    await writeFile(resultPath, bytes);
    rawSources.set(resultPath, bytes);
  };
  if (resume) {
    const workers = [];
    for (const index of statuses.keys()) {
      const workerRoot = path.join(run.scanDir, "artifacts", "deep_discovery", "workers", `discovery-${String(index + 1).padStart(4, "0")}`);
      const artifactDir = path.join(workerRoot, "output");
      const worker = { id: randomUUID(), scanId: run.scanId, kind: "discovery", promptPath: path.join(workerRoot, "prompt.md"), artifactDir, attempt: index === 0 ? 2 : 1 };
      await writeDiscovery(artifactDir, index);
      await writeFile(worker.promptPath, "Synthetic discovery prompt.\n");
      for (const status of ["queued", "running", "succeeded"]) {
        await store.updateWorker({ ...worker, status, ...(status === "succeeded" ? { resultManifestPath: path.join(artifactDir, "result.json") } : {}) });
      }
      workers.push(worker);
    }
    const artifactDir = path.join(run.scanDir, "artifacts", "deep_discovery", "dedup", "dedup-0001", "output");
    const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
    await mkdir(artifactDir, { recursive: true });
    await writeFile(promptPath, "Synthetic reducer prompt.\n");
    const id = randomUUID();
    await store.claimDedup({ id, scanId: run.scanId, workerIds: workers.map((worker) => worker.id), artifactDir, promptPath });
    const resultManifestPath = path.join(artifactDir, "result.json");
    // Legacy accepted reducers omitted coverage entirely.
    await writeFile(resultManifestPath, JSON.stringify({ scanId: run.scanId, findings: [] }));
    await store.commitDedup({ id, scanId: run.scanId, newFindings: 0, resultManifestPath });
    run = await store.get(run.scanId, threadId);
  }
  let discoveryCalls = 0;
  const executor = {
    async run(request) {
      assert.equal(resume, false, "accepted legacy sources should resume without new model work");
      const thread = request.resumeThreadId ?? randomUUID();
      await request.onThreadStarted?.(thread);
      if (request.kind === "discovery") {
        discoveryCalls++;
        const index = Number(path.basename(path.dirname(request.promptPath)).split("-").at(-1)) - 1;
        if (index === 0 && !request.resumeThreadId) return { threadId: thread, finalResponse: "Continue the unfinished audit." };
        await writeDiscovery(request.artifactContext.root, index);
      } else {
        await writeFile(path.join(request.artifactContext.root, "result.json"), JSON.stringify({ scanId: run.scanId, findings: [] }));
      }
      return { threadId: thread, finalResponse: "Audit finished." };
    },
  };
  const coordinator = new DeepScanCoordinator({
    run, store, executor, pluginRoot, retryDelaysMs: [1],
    onComplete: async (draft, signal) => {
      await recordCodexSecurityScanDraftViaWorkbench(context, draft, runWorkbench, signal);
    },
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 30_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.noNewStreak, statuses.length, "source coverage must not change stopping policy");
  assert.equal(discoveryCalls, resume ? 0 : statuses.length + 1);
  await runWorkbench(["complete-scan", "--scan-id", run.scanId]);
  for (const [file, bytes] of rawSources) assert.equal(await readFile(file, "utf8"), bytes);
  return { scanDir: run.scanDir, threadId, terminal };
}
