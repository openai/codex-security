import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { importModule } from "./import-module.ts";

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const exec = promisify(execFile);
const runtime = await importModule({
  bundle: true,
  stdin: {
    contents: [
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { createDeepScanArtifacts } from "./src/deep-scan/artifacts.ts";',
      'export { validateDiscoveryArtifacts } from "./src/deep-scan/artifact-validation.ts";',
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { recordCodexSecurityScanDraftViaWorkbench, saveScanDraftCheckpoint } from "./src/artifact-scan-draft.ts";',
      'export { mergeBatch } from "./src/deep-scan/iteration.ts";',
    ].join("\n"),
    resolveDir: path.join(pluginRoot, "mcp-app"),
  },
  format: "esm",
  platform: "node",
  loader: { ".md": "text" },
  write: false,
});
export async function publishCoverageFixture(
  root,
  completeness,
  {
    resume = false,
    continueAfterResume = false,
    immutableInputs = false,
    materialFindings = false,
  } = {},
) {
  const {
    DeepScanCoordinator,
    createDeepScanArtifacts,
    validateDiscoveryArtifacts,
    WorkbenchDeepScanStore,
    createScanArtifactContext,
    recordCodexSecurityScanDraftViaWorkbench,
    mergeBatch,
    saveScanDraftCheckpoint,
  } = runtime;
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
  const runWorkbench = async (args, input) => {
    const pythonArgs = [
      path.join(pluginRoot, "scripts", "workbench_db.py"),
      ...args,
    ];
    const execution = exec(process.env.PYTHON || "python3", pythonArgs, {
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      },
    });
    if (input !== undefined) execution.child.stdin.end(input);
    const { stdout } = await execution;
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  let run = await store.begin({ targetPath, scope: ".", threadId, scanRoot });
  assert.equal(
    run.workflowVersion,
    "deep-security-scan/v1",
    "the prior reader starts the legacy workflow",
  );
  // Seed an existing v1 run for legacy direct publication and in-memory coverage recovery.
  await exec(process.env.PYTHON || "python3", [
    "-c",
    [
      "import sqlite3, sys",
      "with sqlite3.connect(sys.argv[1]) as db:",
      "    db.execute(\"UPDATE deep_scan_runs SET workflow_version = 'deep-scan-mcp/v1' WHERE scan_id = ?\", (sys.argv[2],))",
    ].join("\n"),
    path.join(root, "state", "workbench.sqlite3"),
    run.scanId,
  ]);
  run = await store.get(run.scanId, threadId);
  assert.equal(run.workflowVersion, "deep-scan-mcp/v1");
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
      const head = JSON.parse(
        await readFile(path.join(artifactDir, "checkpoint-head.json"), "utf8"),
      );
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
        run.scanDir,
        "artifacts",
        "deep_discovery",
        "workers",
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
      const resultManifestPath = await writeDiscovery(artifactDir, index);
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
    const aggregate = { scanId: run.scanId, findings: [] };
    let noNewStreak = 0;

    const label = "dedup-0001";
    const artifactDir = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "dedup",
      label,
      "output",
    );
    await mkdir(artifactDir, { recursive: true });
    const id = randomUUID();
    const state = await store.get(run.scanId, threadId);
    const accepted = await Promise.all(
      workers.map(async (worker) => {
        const stored = state.persistedWorkers.find(
          ({ id }) => id === worker.id,
        );
        const resultPath = stored.acceptedResultPath ?? worker.resultPath;
        const result = await validateDiscoveryArtifacts(
          createDeepScanArtifacts(run.scanDir),
          resultPath,
          run.scanId,
          {
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
    const bytes = JSON.stringify(legacy);
    await writeFile(resultManifestPath, bytes);
    rawSources.set(resultManifestPath, bytes);
    await store.recordIteration({
      id,
      scanId: run.scanId,
      workerIds: workers.map(({ id }) => id),
      resultPath: resultManifestPath,
      noNewStreak,
      consecutiveErrors: 0,
    });
    run = await store.get(run.scanId, threadId);
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
        const index =
          Number(
            path
              .basename(path.dirname(request.artifactContext.root))
              .split("-")
              .at(-1),
          ) - 1;
        if (index === 0 && !request.resumeThreadId)
          return {
            threadId: thread,
            finalResponse: "Continue the unfinished audit.",
          };
        await writeDiscovery(request.artifactContext.root, index);
      }
      return { threadId: thread, finalResponse: "Audit finished." };
    },
  };
  const options = {
    run,
    store,
    executor,
    pluginRoot,
    retryDelaysMs: [1],
    onComplete: async (draft, signal) => {
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        draft,
        runWorkbench,
        signal,
      );
    },
  };
  const coordinator = new DeepScanCoordinator(options);
  coordinator.start();
  const terminal = await coordinator.wait(undefined);
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
    const result = JSON.parse(await readFile(resultPath, "utf8"));
    assert.equal(
      Object.hasOwn(result, "sourceCoverage"),
      false,
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
