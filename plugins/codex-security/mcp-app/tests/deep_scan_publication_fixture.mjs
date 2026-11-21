import assert from "node:assert/strict";
import { WORKBENCH_PYTHON } from "../src/server/workbench-process.ts";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { workbenchArgs } from "../src/workbench-arguments.ts";
import { readJson } from "./support/json.ts";
import { fixturePython } from "./support/python.ts";
import { importNativeModule } from "./import-module.ts";

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const exec = promisify(execFile);
const {
  DeepScanCoordinator,
  createDeepScanArtifacts,
  validateDiscoveryArtifacts,
  WorkbenchDeepScanStore,
  parseDeepScan,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
  recordCodexSecurityWorkerScanDraft,
  mergeBatch,
  saveScanDraftCheckpoint,
} = await importNativeModule({
  stdin: {
    contents: [
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { createDeepScanArtifacts } from "./src/deep-scan/artifacts.ts";',
      'export { validateDiscoveryArtifacts } from "./src/deep-scan/artifact-validation.ts";',
      'export { parseDeepScan, WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench, recordCodexSecurityWorkerScanDraft, saveScanDraftCheckpoint } from "./src/artifact-scan-draft.ts";',
      'export { mergeBatch } from "./src/deep-scan/iteration.ts";',
    ].join("\n"),
    resolveDir: path.join(pluginRoot, "mcp-app"),
  },
  loader: { ".md": "text" },
});

export async function publishCoverageFixture(
  root,
  completeness,
  {
    resume = false,
    continueAfterResume = false,
    immutableInputs = false,
    materialFindings = false,
    discardMutableResults = false,
    legacyAttempts = false,
    splitSeededReducers = false,
    selectedRecovery = false,
    sourceProvenance,
    discoveryReceiptRetry,
  } = {},
) {
  const targetPath = path.join(root, "target");
  const codexHome = path.join(root, "codex-home");
  const scanRoot = path.join(root, "scans");
  const threadId = "coverage-fixture-owner";
  const statuses =
    completeness === "partial"
      ? ["partial", "complete", "unknown"]
      : completeness === "unknown"
        ? ["unknown", "complete"]
        : ["complete"];
  await mkdir(scanRoot, { mode: 0o700 });
  await mkdir(targetPath, { recursive: true });
  await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
  await writeFile(path.join(targetPath, "source.py"), "# Synthetic source\n");
  await writeFile(
    path.join(codexHome, "codex-security", "config.toml"),
    `[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = ${statuses.length}\nmax_discovery_runs = ${statuses.length}\n`,
  );
  const runWorkbench = async (args, input, selectFinalization = false) => {
    const script = path.join(pluginRoot, "scripts", "workbench_db.py");
    const pythonArgs = [
      "-c",
      WORKBENCH_PYTHON,
      script,
      ...(selectFinalization ? ["select_finalization"] : []),
    ];
    const execution = exec(fixturePython, pythonArgs, {
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      },
    });
    execution.child.stdin.write(JSON.stringify(args) + "\n");
    execution.child.stdin.end(input);
    const { stdout } = await execution;
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  const input = { targetPath, scope: ".", threadId, scanRoot };
  const legacy = workbenchArgs("begin-deep-scan", {
    ...input,
    workflowVersion: "deep-scan-mcp/v1",
  });
  let run = selectedRecovery
    ? await store.begin(input)
    : parseDeepScan(await runWorkbench(legacy));
  assert.equal(
    run.workflowVersion,
    selectedRecovery ? "deep-security-scan/v2" : "deep-scan-mcp/v1",
  );
  if (selectedRecovery)
    ({ run } = await store.claimCoordinator({ scanId: run.scanId, threadId }));
  const artifacts = createDeepScanArtifacts(run.scanDir);
  const context = await createScanArtifactContext(run.scanId, runWorkbench, {
    requireRunning: true,
  });
  const rawSources = new Map();
  // Both reports describe the same extraction operation and provide its source.
  const compare = async (prompt, schema) => {
    const input = JSON.parse(prompt.split("\n").at(-1));
    if (schema.properties.sources)
      return JSON.stringify({
        sources: input.map(({ id }) => ({
          id,
          same: true,
          survivingPaths: [],
        })),
      });
    if (schema.properties.reviews)
      return JSON.stringify({
        reviews: input.pairs.map(({ id }) => ({
          pair: id,
          decision: "same",
          leftEvidence: 0,
          rightEvidence: 0,
        })),
      });
    return JSON.stringify({
      defects: [
        {
          operation: "extract",
          failure: "unconfined destination",
          path: "source.py",
          reports: input.map(({ id }) => ({ id, evidence: 0 })),
        },
      ],
      uncertain: [],
    });
  };
  const writeDiscovery = async (artifactDir, index) => {
    const status = statuses[index];
    const pending = completeness === "partial" && status !== "complete";
    const coverage = {
      completeness: status,
      surfaces: [
        {
          id: "shared-surface",
          label: "Archive route",
          disposition: pending ? "needs_follow_up" : "no_issue_found",
          receiptRefs: ["artifacts/review.md"],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor/", reason: "External dependency." },
      ],
      deferred: pending
        ? [
            {
              id: "same-id",
              candidateId: "candidate-1",
              reason:
                index === 0
                  ? "Verify entry boundaries."
                  : "Verify symbolic links.",
              paths: ["source.py"],
              surfaceIds: ["shared-surface"],
            },
          ]
        : [],
      openQuestions: pending
        ? [{ question: `Deployment question ${index + 1}.` }]
        : [],
    };
    if (sourceProvenance !== undefined) {
      for (const field of [
        "surfaces",
        "explicitExclusions",
        "deferred",
        "openQuestions",
      ]) {
        for (const item of coverage[field])
          item.provenance = structuredClone(sourceProvenance);
      }
    }
    await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
    await writeFile(
      path.join(artifactDir, "artifacts", "review.md"),
      "Synthetic review evidence.\n",
    );
    const resultPath = path.join(artifactDir, "result.json");
    const findings =
      materialFindings && index < 2
        ? [
            {
              ruleId: "archive-extraction",
              identity: { anchor: "archive-destination" },
              title: "Archive entries can escape the destination",
              summary:
                "Archive extraction requires both entry containment and symbolic-link handling.",
              severity: { level: "high" },
              confidence: {
                level: "high",
                rationale: "Synthetic accepted source evidence.",
              },
              taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
              locations: [{ path: "source.py", startLine: 1, endLine: 1 }],
              codeEvidence: [
                {
                  id: "extract",
                  label: "Extraction",
                  explanation: "Unconfined destination",
                  path: "source.py",
                  startLine: 1,
                  code: "archive.extract(member, destination)",
                },
              ],
              remediation: materialRemediations[index],
              remediationTests: [materialRemediationTests[index]],
              provenance: { source: "local_plugin" },
            },
          ]
        : [];
    const bytes = JSON.stringify({
      scanId: run.scanId,
      complete: true,
      findings,
      reviewState: coverage,
    });
    await writeFile(resultPath, bytes);
    rawSources.set(resultPath, bytes);
    if (immutableInputs) {
      await saveScanDraftCheckpoint(
        { root: artifactDir, repoRoot: targetPath, layout: "worker" },
        JSON.parse(bytes),
      );
      const head = await readJson(artifactDir, "checkpoint-head.json");
      const acceptedPath = path.join(
        artifactDir,
        "checkpoints",
        head.checkpoint,
      );
      rawSources.set(acceptedPath, await readFile(acceptedPath, "utf8"));
      return acceptedPath;
    }
    return resultPath;
  };
  if (resume) {
    const workers = [];
    const seeded = continueAfterResume ? statuses.slice(0, -1) : statuses;
    for (const index of seeded.keys()) {
      const workerRoot = path.join(
        artifacts.workersRoot,
        `discovery-${String(index + 1).padStart(4, "0")}`,
      );
      const artifactDir = path.join(workerRoot, "output");
      const worker = {
        id: randomUUID(),
        scanId: run.scanId,
        kind: "discovery",
        promptPath: path.join(workerRoot, "prompt.md"),
        artifactDir,
        attempt: index === 0 ? 2 : 1,
      };
      const writtenPath = await writeDiscovery(artifactDir, index);
      const resultManifestPath = discardMutableResults
        ? path.join(artifactDir, "result.json")
        : writtenPath;
      await writeFile(worker.promptPath, "Synthetic discovery prompt.\n");
      for (const status of ["queued", "running", "succeeded"]) {
        await store.updateWorker({
          ...worker,
          status,
          ...(status === "succeeded" ? { resultManifestPath } : {}),
        });
      }
      workers.push({ ...worker, resultPath: resultManifestPath });
    }
    const batches = splitSeededReducers
      ? [workers.slice(0, 2), workers.slice(2)]
      : [workers];
    const aggregate = { scanId: run.scanId, findings: [] };
    let noNewStreak = 0;
    let lastReducerId;
    let lastReducerReference;
    for (const [index, batch] of batches.entries()) {
      const label = `dedup-${String(index + 1).padStart(4, "0")}`;
      const artifactDir = path.join(artifacts.dedupRoot, label, "output");
      await mkdir(artifactDir, { recursive: true });
      const id = randomUUID();
      const state = await store.get(run.scanId, threadId);
      const accepted = await Promise.all(
        batch.map(async (worker) => {
          const stored = state.persistedWorkers.find(
            ({ id }) => id === worker.id,
          );
          const resultPath = stored.acceptedResultPath ?? worker.resultPath;
          const result = await validateDiscoveryArtifacts(
            artifacts,
            resultPath,
            run.scanId,
            {
              accepted: true,
              artifactDir: worker.artifactDir,
              resultSha256: stored.acceptedResultSha256,
            },
          );
          return { ...worker, result, resultPath };
        }),
      );
      for (const count of await mergeBatch(
        aggregate,
        accepted,
        run.scanDir,
        compare,
        (error) => {
          throw error;
        },
      ))
        noNewStreak = count ? 0 : noNewStreak + 1;
      const { sourceCoverage, ...legacy } = aggregate;
      const resultManifestPath = path.join(artifactDir, "result.json");
      const bytes = JSON.stringify(selectedRecovery ? aggregate : legacy);
      await writeFile(resultManifestPath, bytes);
      rawSources.set(resultManifestPath, bytes);
      const committed = await store.recordIteration({
        id,
        scanId: run.scanId,
        workerIds: batch.map(({ id }) => id),
        resultPath: resultManifestPath,
        noNewStreak,
        consecutiveErrors: 0,
      });
      lastReducerReference = committed.persistedWorkers.find(
        (worker) => worker.id === id,
      ).acceptedResultPath;
      lastReducerId = id;
    }
    if (legacyAttempts) {
      // Earlier writers stored attempts for the final reducer only, or no frozen bindings.
      await exec(fixturePython, [
        "-c",
        `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    if sys.argv[3] == "before-bindings":
        db.execute("DELETE FROM deep_scan_attempts")
        db.execute("DELETE FROM deep_scan_merge_claims")
        db.execute("UPDATE deep_scan_dedup_inputs SET attempt=NULL, result_manifest_path=NULL, result_manifest_sha256=NULL")
        db.execute("UPDATE deep_scan_workers SET attempt=0 WHERE kind=?", ("dedup",))
        db.execute("UPDATE deep_scan_workers SET completed_at=? WHERE status=?", ("2020-01-01T00:00:00Z", "succeeded"))
    else:
        db.execute("DELETE FROM deep_scan_attempts WHERE worker_id != ?", (sys.argv[2],))
`,
        path.join(root, "state", "workbench.sqlite3"),
        lastReducerId,
        String(legacyAttempts),
      ]);
    }
    if (legacyAttempts === "before-bindings") {
      ({ run } = await store.claimCoordinator({
        scanId: run.scanId,
        threadId,
      }));
    } else {
      run = await store.get(run.scanId, threadId);
    }
    if (discardMutableResults) {
      for (const worker of run.persistedWorkers) {
        const acceptedPath =
          worker.acceptedResultPath ??
          run.persistedDedupInputs.find(
            (input) => input.discoveryWorkerId === worker.id,
          )?.resultManifestPath ??
          run.persistedMergeClaims.find(
            (claim) => claim.previousWorkerId === worker.id,
          )?.previousResultPath;
        assert.ok(acceptedPath, "the real store retains an accepted reference");
        assert.notEqual(acceptedPath, worker.resultManifestPath);
        rawSources.set(acceptedPath, await readFile(acceptedPath, "utf8"));
        rawSources.delete(worker.resultManifestPath);
        await rm(worker.resultManifestPath);
      }
    }
    if (selectedRecovery) {
      run = await store.selectFinalization({
        scanId: run.scanId,
        reason: "capped",
        manifestPath: path.join(run.scanDir, "scan-manifest.json"),
        resultPath: lastReducerReference,
        omittedWorkerIds: [],
      });
    }
  }
  let discoveryCalls = 0;
  const executor = {
    compareFindings: (prompt, _cwd, _signal, schema) => compare(prompt, schema),
    async run(request) {
      assert.equal(
        resume && !continueAfterResume,
        false,
        "accepted legacy sources should resume without new model work",
      );
      const thread = request.resumeThreadId ?? randomUUID();
      await request.onThreadStarted?.(thread);
      if (request.kind === "discovery") {
        discoveryCalls++;
        const artifactDir = request.artifactContext.root;
        const worker = path.basename(path.dirname(artifactDir));
        const index = Number(worker.split("-").at(-1)) - 1;
        if (discoveryReceiptRetry && discoveryCalls === 1) {
          await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
          await writeFile(
            path.join(artifactDir, "artifacts", "old-review.md"),
            "Archived review evidence.\n",
          );
          await recordCodexSecurityWorkerScanDraft(
            {
              ...request.artifactContext,
              repoRoot: targetPath,
              scanId: run.scanId,
            },
            {
              scanId: run.scanId,
              complete: false,
              findings: [],
              reviewState: {
                completeness: "partial",
                surfaces: [
                  {
                    id: "archived-surface",
                    label: "Archived boundary",
                    disposition: "no_issue_found",
                    receiptRefs: ["artifacts/old-review.md"],
                  },
                ],
                explicitExclusions: [],
                deferred: [],
              },
            },
          );
          // A returned partial draft fails validation and triggers the real archive/retry path.
          return { threadId: thread, finalResponse: "Checkpoint recorded." };
        }
        if (!discoveryReceiptRetry && index === 0 && !request.resumeThreadId)
          return {
            threadId: thread,
            finalResponse: "Continue the unfinished audit.",
          };
        await writeDiscovery(artifactDir, index);
        if (discoveryReceiptRetry) {
          const archived = path.join(
            path.dirname(artifactDir),
            "attempts",
            "attempt-01",
            "artifacts",
            "old-review.md",
          );
          rawSources.set(archived, "Archived review evidence.\n");
          if (discoveryReceiptRetry === "collision") {
            const current = path.join(
              artifactDir,
              "artifacts",
              "old-review.md",
            );
            await writeFile(current, "New retry evidence.\n");
            rawSources.set(current, "New retry evidence.\n");
          }
          const resultPath = path.join(artifactDir, "result.json");
          const result = await readJson(resultPath);
          await recordCodexSecurityWorkerScanDraft(
            {
              ...request.artifactContext,
              repoRoot: targetPath,
              scanId: run.scanId,
            },
            result,
          );
          rawSources.set(resultPath, await readFile(resultPath, "utf8"));
        }
      }
      return { threadId: thread, finalResponse: "Audit finished." };
    },
  };
  let publicationCalls = 0;
  const options = {
    run,
    store,
    executor,
    pluginRoot,
    retryDelaysMs: [1],
    onComplete: async (draft, signal, publication) => {
      publicationCalls++;
      if (selectedRecovery && publicationCalls === 1)
        throw new Error("Synthetic selected publication failure");
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        draft,
        runWorkbench,
        signal,
        selectedRecovery || legacyAttempts === "before-bindings"
          ? publication
          : undefined,
      );
    },
  };
  const coordinator = new DeepScanCoordinator(options);
  coordinator.start();
  let terminal;
  if (selectedRecovery) {
    await assert.rejects(
      coordinator.wait(undefined),
      /Synthetic selected publication failure/,
    );
    const pending = await store.get(run.scanId, threadId);
    assert.equal(pending.status, "running");
    assert.deepEqual(pending.finalizationInput, run.finalizationInput);
    const worker = pending.persistedWorkers.find(
      (worker) => worker.kind === "discovery",
    );
    const rejected = {
      scanId: run.scanId,
      complete: false,
      findings: [],
      reviewState: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    };
    await saveScanDraftCheckpoint(
      { root: worker.artifactDir, repoRoot: targetPath, layout: "worker" },
      rejected,
    );
    const replacement = path.join(worker.artifactDir, "result.json");
    await writeFile(replacement, JSON.stringify(rejected));
    await assert.rejects(
      validateDiscoveryArtifacts(artifacts, replacement, run.scanId),
      /only a checkpoint/,
    );
    const headPath = path.join(worker.artifactDir, "checkpoint-head.json");
    const head = await readJson(headPath);
    for (const file of [
      replacement,
      headPath,
      path.join(worker.artifactDir, "checkpoints", head.checkpoint),
    ]) {
      rawSources.set(file, await readFile(file, "utf8"));
    }
    const restarted = new DeepScanCoordinator({ ...options, run: pending });
    restarted.start();
    terminal = await restarted.wait(undefined, 30_000);
    assert.deepEqual(terminal.finalizationInput, run.finalizationInput);
    assert.equal(publicationCalls, 2);
  } else {
    terminal = await coordinator.wait(undefined);
  }
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(
    terminal.noNewStreak,
    statuses.length - (materialFindings ? 1 : 0),
    "source coverage must not change stopping policy",
  );
  assert.equal(
    discoveryCalls,
    resume ? (continueAfterResume ? 1 : 0) : statuses.length + 1,
  );
  const accepted = await store.get(run.scanId, threadId);
  for (const worker of accepted.persistedWorkers.filter(
    (worker) => worker.kind === "dedup",
  )) {
    const resultPath =
      worker.acceptedResultPath ??
      accepted.persistedMergeClaims.find(
        (claim) => claim.previousWorkerId === worker.id,
      )?.previousResultPath ??
      worker.resultManifestPath;
    const result = await readJson(resultPath);
    assert.equal(
      Object.hasOwn(result, "sourceCoverage"),
      selectedRecovery,
      "coverage persistence follows the accepted workflow version",
    );
  }
  await runWorkbench(["complete-scan", "--scan-id", run.scanId]);
  for (const [file, bytes] of rawSources)
    assert.equal(await readFile(file, "utf8"), bytes);
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
  const result = await publishCoverageFixture(
    process.argv[2],
    process.argv[3],
    {
      resume: process.argv[4] === "true",
      continueAfterResume: process.argv[5] === "true",
    },
  );
  process.stdout.write(JSON.stringify(result));
}
