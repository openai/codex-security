import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
      'export { createDeepScanArtifacts } from "./src/deep-scan/artifacts.ts";',
      'export { validateDiscoveryArtifacts } from "./src/deep-scan/artifact-validation.ts";',
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench, saveScanDraftCheckpoint } from "./src/artifact-scan-draft.ts";',
      'export { recordCodexSecurityDeepReduction, getCodexSecurityDeepReducerInputs } from "./src/artifact-deep-reducer.ts";',
    ].join("\n"),
    resolveDir: path.join(pluginRoot, "mcp-app"),
  },
  format: "esm", platform: "node", loader: { ".md": "text" }, write: false,
});
export async function publishCoverageFixture(root, completeness, {
  resume = false,
  continueAfterResume = false,
  immutableInputs = false,
  materialFindings = false,
  discardMutableResults = false,
  legacyAttempts = false,
  splitSeededReducers = false,
  selectedRecovery = false,
} = {}) {
  const runtimePath = path.join(root, "fixture-runtime.mjs");
  await writeFile(runtimePath, bundled.outputFiles[0].contents);
  const { DeepScanCoordinator, createDeepScanArtifacts, validateDiscoveryArtifacts, WorkbenchDeepScanStore, createScanArtifactContext, recordCodexSecurityScanDraftViaWorkbench, recordCodexSecurityDeepReduction, getCodexSecurityDeepReducerInputs, saveScanDraftCheckpoint } = await import(pathToFileURL(runtimePath).href);
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
  const runWorkbench = async (args, input, selectFinalization = false) => {
    const script = path.join(pluginRoot, "scripts", "workbench_db.py");
    const pythonArgs = selectFinalization
      ? ["-c", "import runpy, sys; script = sys.argv.pop(1); runpy.run_path(script)['main'](select_finalization=True)", script, ...args]
      : [script, ...args];
    const execution = exec(process.env.PYTHON || "python3", pythonArgs, {
      env: { ...process.env, CODEX_HOME: codexHome, CODEX_SECURITY_STATE_DIR: path.join(root, "state") },
    });
    if (input !== undefined) execution.child.stdin.end(input);
    const { stdout } = await execution;
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  let { run } = await store.begin({ targetPath, scope: ".", threadId, scanRoot });
  assert.equal(run.workflowVersion, "deep-security-scan/v2", "new scans use persisted finalization");
  if (selectedRecovery) {
    ({ run } = await store.claimCoordinator({ scanId: run.scanId, threadId }));
  } else {
    // Seed an existing v1 run for legacy direct publication and in-memory coverage recovery.
    await exec(process.env.PYTHON || "python3", ["-c", [
      "import sqlite3, sys",
      "with sqlite3.connect(sys.argv[1]) as db:",
      "    db.execute(\"UPDATE deep_scan_runs SET workflow_version = 'deep-scan-mcp/v1' WHERE scan_id = ?\", (sys.argv[2],))",
    ].join("\n"), path.join(root, "state", "workbench.sqlite3"), run.scanId]);
    run = await store.get(run.scanId, threadId);
    assert.equal(run.workflowVersion, "deep-scan-mcp/v1");
  }
  const context = await createScanArtifactContext(run.scanId, runWorkbench, { requireRunning: true });
  const rawSources = new Map();
  const writeReduction = async (context) => {
    const inputs = await getCodexSecurityDeepReducerInputs(context);
    const sources = [...(inputs.previous?.findings ?? []), ...inputs.discoveries.flatMap((source) => source.result.findings)];
    const findings = [];
    if (sources.length) {
      const finding = structuredClone(sources[0]);
      finding.provenance.sourceFindingIds = [...new Set(sources.flatMap((source) => source.provenance.sourceFindingIds))];
      delete finding.provenance.sourceFindings;
      findings.push(finding);
    }
    await recordCodexSecurityDeepReduction(context, { scanId: run.scanId, findings });
  };
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
    const findings = materialFindings && index < 2 ? [{
      ruleId: "archive-extraction", identity: { anchor: "archive-destination" },
      title: "Archive entries can escape the destination",
      summary: "Archive extraction requires both entry containment and symbolic-link handling.",
      severity: { level: "high" },
      confidence: { level: "high", rationale: "Synthetic accepted source evidence." },
      taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
      locations: [{ path: "source.py", startLine: 1, endLine: 1 }],
      remediation: materialRemediations[index],
      remediationTests: [materialRemediationTests[index]],
      provenance: { source: "local_plugin" },
    }] : [];
    const bytes = JSON.stringify({ scanId: run.scanId, complete: true, findings, coverage });
    await writeFile(resultPath, bytes);
    rawSources.set(resultPath, bytes);
    if (immutableInputs) {
      await saveScanDraftCheckpoint({ root: artifactDir, repoRoot: targetPath, layout: "worker" }, JSON.parse(bytes));
      const head = JSON.parse(await readFile(path.join(artifactDir, "checkpoint-head.json"), "utf8"));
      const acceptedPath = path.join(artifactDir, "checkpoints", head.checkpoint);
      rawSources.set(acceptedPath, await readFile(acceptedPath, "utf8"));
      return acceptedPath;
    }
    return resultPath;
  };
  if (resume) {
    const workers = [];
    const seeded = continueAfterResume ? statuses.slice(0, -1) : statuses;
    for (const index of seeded.keys()) {
      const workerRoot = path.join(run.scanDir, "artifacts", "deep_discovery", "workers", `discovery-${String(index + 1).padStart(4, "0")}`);
      const artifactDir = path.join(workerRoot, "output");
      const worker = { id: randomUUID(), scanId: run.scanId, kind: "discovery", promptPath: path.join(workerRoot, "prompt.md"), artifactDir, attempt: index === 0 ? 2 : 1 };
      const writtenPath = await writeDiscovery(artifactDir, index);
      const resultManifestPath = discardMutableResults ? path.join(artifactDir, "result.json") : writtenPath;
      await writeFile(worker.promptPath, "Synthetic discovery prompt.\n");
      for (const status of ["queued", "running", "succeeded"]) {
        await store.updateWorker({ ...worker, status, ...(status === "succeeded" ? { resultManifestPath } : {}) });
      }
      workers.push({ ...worker, resultPath: resultManifestPath });
    }
    const batches = splitSeededReducers ? [workers.slice(0, 2), workers.slice(2)] : [workers];
    let lastReducerId;
    let lastReducerReference;
    for (const [index, batch] of batches.entries()) {
      const label = `dedup-${String(index + 1).padStart(4, "0")}`;
      const artifactDir = path.join(run.scanDir, "artifacts", "deep_discovery", "dedup", label, "output");
      const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
      await mkdir(artifactDir, { recursive: true });
      await writeFile(promptPath, "Synthetic reducer prompt.\n");
      const id = randomUUID();
      const claimed = await store.claimDedup({ id, scanId: run.scanId, workerIds: batch.map((worker) => worker.id), artifactDir, promptPath });
      if (discardMutableResults) {
        await store.updateWorker({ id, scanId: run.scanId, kind: "dedup", status: "running", artifactDir, promptPath, attempt: 1 });
      }
      const resultManifestPath = path.join(artifactDir, "result.json");
      // Legacy accepted reducers omitted coverage entirely.
      if (materialFindings) {
        await writeReduction({
          root: artifactDir, repoRoot: targetPath, scanId: run.scanId, layout: "reducer",
          deepReducer: {
            scanRoot: run.scanDir,
            claimedWorkers: batch.map((worker) => {
              const input = claimed.persistedDedupInputs.find((input) => input.dedupWorkerId === id && input.discoveryWorkerId === worker.id);
              return { ...worker, resultPath: input.resultManifestPath ?? worker.resultPath, attempt: input.attempt ?? worker.attempt };
            }),
            persistSourceCoverage: selectedRecovery,
            previousReducerResultPath: claimed.persistedMergeClaims?.find((claim) => claim.workerId === id)?.previousResultPath,
          },
        });
      } else {
        await writeFile(resultManifestPath, JSON.stringify({ scanId: run.scanId, findings: [] }));
      }
      rawSources.set(resultManifestPath, await readFile(resultManifestPath, "utf8"));
      const committed = await store.commitDedup({ id, scanId: run.scanId, newFindings: materialFindings && index === 0 ? 1 : 0, resultManifestPath });
      lastReducerReference = committed.committedMerge.resultManifestPath;
      lastReducerId = id;
    }
    if (legacyAttempts) {
      // Migrated discoveries and prior reducers can have frozen claims without attempt rows.
      await exec(process.env.PYTHON || "python3", ["-c", [
        "import sqlite3, sys",
        "with sqlite3.connect(sys.argv[1]) as db:",
        "    db.execute(\"DELETE FROM deep_scan_attempts WHERE worker_id != ?\", (sys.argv[2],))",
      ].join("\n"), path.join(root, "state", "workbench.sqlite3"), lastReducerId]);
    }
    run = await store.get(run.scanId, threadId);
    if (discardMutableResults) {
      for (const worker of run.persistedWorkers) {
        const acceptedPath = worker.acceptedResultPath ?? run.persistedDedupInputs
          .find((input) => input.discoveryWorkerId === worker.id)?.resultManifestPath
          ?? run.persistedMergeClaims.find((claim) => claim.previousWorkerId === worker.id)?.previousResultPath;
        assert.ok(acceptedPath, "the real store retains an accepted reference");
        assert.notEqual(acceptedPath, worker.resultManifestPath);
        rawSources.set(acceptedPath, await readFile(acceptedPath, "utf8"));
        rawSources.delete(worker.resultManifestPath);
        await rm(worker.resultManifestPath);
      }
    }
    if (selectedRecovery) {
      run = await store.selectFinalization({
        scanId: run.scanId, reason: "capped", manifestPath: path.join(run.scanDir, "scan-manifest.json"),
        resultPath: lastReducerReference, omittedWorkerIds: [],
      });
    }
  }
  let discoveryCalls = 0;
  const executor = {
    async run(request) {
      assert.equal(resume && !continueAfterResume, false, "accepted legacy sources should resume without new model work");
      const thread = request.resumeThreadId ?? randomUUID();
      await request.onThreadStarted?.(thread);
      if (request.kind === "discovery") {
        discoveryCalls++;
        const index = Number(path.basename(path.dirname(request.promptPath)).split("-").at(-1)) - 1;
        if (index === 0 && !request.resumeThreadId) return { threadId: thread, finalResponse: "Continue the unfinished audit." };
        await writeDiscovery(request.artifactContext.root, index);
      } else {
        if (immutableInputs) {
          const current = await store.get(run.scanId, threadId);
          for (const claimed of request.artifactContext.deepReducer.claimedWorkers) {
            const accepted = current.persistedWorkers.find((worker) => worker.id === claimed.id);
            assert.equal(claimed.resultPath, accepted.acceptedResultPath ?? accepted.resultManifestPath, "the reducer uses the exact accepted input");
            assert.equal(claimed.artifactDir, accepted.artifactDir, "receipts retain their original output owner");
          }
        }
        await writeReduction({ ...request.artifactContext, repoRoot: targetPath, scanId: run.scanId });
      }
      return { threadId: thread, finalResponse: "Audit finished." };
    },
  };
  let publicationCalls = 0;
  const options = {
    run, store, executor, pluginRoot, retryDelaysMs: [1],
    onComplete: async (draft, signal, publication) => {
      publicationCalls++;
      if (selectedRecovery && publicationCalls === 1) throw new Error("Synthetic selected publication failure");
      await recordCodexSecurityScanDraftViaWorkbench(context, draft, runWorkbench, signal, selectedRecovery ? publication : undefined);
    },
  };
  const coordinator = new DeepScanCoordinator(options);
  coordinator.start();
  let terminal;
  if (selectedRecovery) {
    await assert.rejects(coordinator.wait(undefined, 30_000), /Synthetic selected publication failure/);
    const pending = await store.get(run.scanId, threadId);
    assert.equal(pending.status, "running");
    assert.deepEqual(pending.finalizationInput, run.finalizationInput);
    const worker = pending.persistedWorkers.find((worker) => worker.kind === "discovery");
    const rejected = { scanId: run.scanId, complete: false, findings: [], coverage: {
      completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [],
    } };
    await saveScanDraftCheckpoint({ root: worker.artifactDir, repoRoot: targetPath, layout: "worker" }, rejected);
    const replacement = path.join(worker.artifactDir, "result.json");
    await writeFile(replacement, JSON.stringify(rejected));
    await assert.rejects(validateDiscoveryArtifacts(createDeepScanArtifacts(run.scanDir), replacement, run.scanId), /only a checkpoint/);
    const headPath = path.join(worker.artifactDir, "checkpoint-head.json");
    const head = JSON.parse(await readFile(headPath, "utf8"));
    for (const file of [replacement, headPath, path.join(worker.artifactDir, "checkpoints", head.checkpoint)]) {
      rawSources.set(file, await readFile(file, "utf8"));
    }
    const restarted = new DeepScanCoordinator({ ...options, run: pending });
    restarted.start();
    terminal = await restarted.wait(undefined, 30_000);
    assert.deepEqual(terminal.finalizationInput, run.finalizationInput);
    assert.equal(publicationCalls, 2);
  } else {
    terminal = await coordinator.wait(undefined, 30_000);
  }
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.noNewStreak, materialFindings ? (resume && !continueAfterResume && !splitSeededReducers ? 0 : 1) : statuses.length,
    "source coverage must not change stopping policy");
  assert.equal(discoveryCalls, resume ? (continueAfterResume ? 1 : 0) : statuses.length + 1);
  const accepted = await store.get(run.scanId, threadId);
  for (const worker of accepted.persistedWorkers.filter((worker) => worker.kind === "dedup")) {
    const resultPath = worker.acceptedResultPath
      ?? accepted.persistedMergeClaims.find((claim) => claim.previousWorkerId === worker.id)?.previousResultPath
      ?? worker.resultManifestPath;
    const result = JSON.parse(await readFile(resultPath, "utf8"));
    assert.equal(Object.hasOwn(result, "sourceCoverage"), selectedRecovery, "coverage persistence follows the accepted workflow version");
    if (!rawSources.has(worker.resultManifestPath)) {
      for (const name of await readdir(path.join(worker.artifactDir, "checkpoints"))) {
        const checkpoint = JSON.parse(await readFile(path.join(worker.artifactDir, "checkpoints", name), "utf8"));
        assert.equal(Object.hasOwn(checkpoint, "sourceCoverage"), selectedRecovery, "checkpoint coverage follows the accepted workflow version");
      }
    }
  }
  await runWorkbench(["complete-scan", "--scan-id", run.scanId]);
  for (const [file, bytes] of rawSources) assert.equal(await readFile(file, "utf8"), bytes);
  return { scanDir: run.scanDir, threadId, terminal };
}

export const materialRemediations = [
  "Check the destination before writing the archive entry.",
  "Reject symbolic links before opening the destination.",
];
export const materialRemediationTests = [
  "Reject an archive entry outside the destination.",
  "Reject a symbolic link inside the destination.",
];

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await publishCoverageFixture(process.argv[2], process.argv[3], { resume: process.argv[4] === "true", continueAfterResume: process.argv[5] === "true" });
  process.stdout.write(JSON.stringify(result));
}
