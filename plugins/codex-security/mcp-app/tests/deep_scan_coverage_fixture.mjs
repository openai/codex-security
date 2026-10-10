import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fsPromises } from "node:fs";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual, promisify } from "node:util";
import { build } from "esbuild";

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const exec = promisify(execFile);
const bundled = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { archiveDirectory } from "./src/deep-scan/artifacts.ts";',
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { getCodexSecurityCompletedScan, recordCodexSecurityWorkerScanDraft, recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";',
      'export { recordCodexSecurityDeepReduction } from "./src/artifact-deep-reducer.ts";',
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
    stopAfterDraft = false,
    receiptRetry = false,
    streamRetry = false,
    closeGeneric = false,
    failClosedResult = false,
    workflowVersion,
    directFile = false,
    omitCoverageIds = false,
    competingIds = false,
    namedRetry = false,
    linkedRetry = false,
    missingProjection = false,
    changedRetry = false,
    sameAttemptChange = false,
    duplicateRows = false,
    interruptReducer,
    checkpointOnly = false,
    parentTiming,
    descriptiveVariants = false,
    provenanceKind = "descriptive",
  } = {},
) {
  const runtimePath = path.join(root, "fixture-runtime.mjs");
  await writeFile(runtimePath, bundled.outputFiles[0].contents);
  const {
    archiveDirectory,
    getCodexSecurityCompletedScan,
    DeepScanCoordinator,
    WorkbenchDeepScanStore,
    createScanArtifactContext,
    recordCodexSecurityScanDraftViaWorkbench,
    recordCodexSecurityWorkerScanDraft,
    recordCodexSecurityDeepReduction,
  } = await import(pathToFileURL(runtimePath).href);
  const targetPath = path.join(root, "target");
  const codexHome = path.join(root, "codex-home");
  const scanRoot = path.join(root, "scans");
  const threadId = "coverage-fixture-owner";
  const statuses = interruptReducer
    ? ["partial", "partial", "partial"]
    : completeness === "partial"
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
  const runWorkbench = async (args) => {
    if (workflowVersion && args[0] === "begin-deep-scan") {
      // Exercise the existing persisted-version boundary without changing launch defaults.
      args = [...args];
      args[args.indexOf("--workflow-version") + 1] = workflowVersion;
    }
    const { stdout } = await exec(
      process.env.PYTHON || "python3",
      [path.join(pluginRoot, "scripts", "workbench_db.py"), ...args],
      {
        env: {
          ...process.env,
          CODEX_HOME: codexHome,
          CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
        },
      },
    );
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  let run = await store.begin({ targetPath, scope: ".", threadId, scanRoot });
  if (workflowVersion) assert.equal(run.workflowVersion, workflowVersion);
  const context = await createScanArtifactContext(run.scanId, runWorkbench, {
    requireRunning: true,
  });
  const rawSources = new Map();
  const writeReceiptAttempt = async (artifactDir) => {
    await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
    await writeFile(
      path.join(artifactDir, "artifacts", "prior.txt"),
      "Archived receipt.\n",
    );
    await recordCodexSecurityWorkerScanDraft(
      {
        root: artifactDir,
        layout: "worker",
        repoRoot: targetPath,
        scanId: run.scanId,
      },
      {
        scanId: run.scanId,
        complete: false,
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [
            {
              id: "prior",
              label: "Prior review",
              disposition: "no_issue_found",
              receiptRefs: ["artifacts/prior.txt"],
            },
          ],
          explicitExclusions: [],
          deferred: [],
        },
      },
    );
  };
  const writeDiscovery = async (artifactDir, index, archived = false) => {
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
    if (closeGeneric) {
      coverage.completeness = "partial";
      coverage.surfaces[0].disposition = "needs_follow_up";
      coverage.deferred = [
        {
          id: "review-task",
          reason: "Finish the source review.",
          surfaceIds: ["shared-surface"],
        },
      ];
    }
    if (interruptReducer) {
      coverage.surfaces[0].id = `surface-${index}`;
      coverage.surfaces[0].label = `Archive route ${index}`;
      for (const deferred of coverage.deferred) {
        deferred.id = `follow-up-${index}`;
        deferred.surfaceIds = [`surface-${index}`];
        delete deferred.candidateId;
      }
    }
    if (namedRetry) {
      coverage.surfaces[0].receiptRefs = [];
      for (const deferred of coverage.deferred) {
        delete deferred.candidateId;
        if (!linkedRetry) delete deferred.surfaceIds;
      }
    }
    if (omitCoverageIds && !archived && (!interruptReducer || index === 0)) {
      for (const surface of coverage.surfaces) delete surface.id;
      for (const deferred of coverage.deferred) {
        delete deferred.id;
        delete deferred.candidateId;
        if (!linkedRetry) delete deferred.surfaceIds;
      }
    }
    if (archived && changedRetry) {
      coverage.surfaces[0].label = "Earlier independent route";
      for (const deferred of coverage.deferred)
        deferred.reason = "An earlier independent observation.";
    }
    if (duplicateRows)
      coverage.surfaces.push(structuredClone(coverage.surfaces[0]));
    if (competingIds) {
      coverage.surfaces.push({ ...coverage.surfaces[0], id: "owned-surface" });
      if (coverage.deferred.length)
        coverage.deferred.push({
          ...coverage.deferred[0],
          id: "owned-deferred",
        });
    }
    for (const field of [
      "surfaces",
      "explicitExclusions",
      "deferred",
      "openQuestions",
    ]) {
      for (const item of coverage[field]) {
        item.provenance = {
          description: `Original ${field} context.`,
          details: { evidence: ["source review"] },
          workerId: "untrusted-worker",
          attempt: 99,
          sourceId: "untrusted-source",
          candidateId: "untrusted-candidate",
        };
        if (provenanceKind === "owner-only") {
          delete item.provenance.description;
          delete item.provenance.details;
        } else if (provenanceKind === "absent") delete item.provenance;
      }
      if (descriptiveVariants && coverage[field].length) {
        const second = structuredClone(coverage[field][0]);
        if (typeof second.id === "string") second.id += "-independent";
        if (typeof second.candidateId === "string")
          second.candidateId += "-independent";
        second.provenance.description = `Independent ${field} context.`;
        second.provenance.details = { evidence: ["independent source review"] };
        coverage[field].push(second);
      }
    }
    await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
    await writeFile(
      path.join(artifactDir, "artifacts", "review.md"),
      "Synthetic review evidence.\n",
    );
    const resultPath = path.join(artifactDir, "result.json");
    const bytes = JSON.stringify({
      scanId: run.scanId,
      complete: !archived,
      findings: [],
      coverage,
    });
    if (receiptRetry) {
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          repoRoot: targetPath,
          layout: "worker",
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete: true,
          findings: [],
          coverage: {
            completeness: status,
            surfaces: [
              {
                id: "current",
                label: "Current review",
                disposition: "no_issue_found",
                receiptRefs: ["artifacts/review.md"],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        },
      );
    } else if (directFile && !archived) {
      await writeFile(resultPath, bytes);
    } else {
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          repoRoot: targetPath,
          layout: "worker",
          scanId: run.scanId,
        },
        JSON.parse(bytes),
      );
      if (closeGeneric) {
        const before = await readFile(resultPath, "utf8");
        const closed = JSON.parse(bytes);
        closed.coverage.completeness = "complete";
        closed.coverage.surfaces[0].disposition = "no_issue_found";
        closed.coverage.deferred = [];
        closed.coverage.resolvedDeferred = [
          { id: "review-task", reason: "Source review completed." },
        ];
        const originalRename = fsPromises.rename;
        let failures = 0;
        fsPromises.rename = async (source, destination) => {
          if (failClosedResult && destination === resultPath) {
            failures++;
            throw Object.assign(
              new Error("Synthetic result replacement failure."),
              { code: "EIO" },
            );
          }
          return originalRename(source, destination);
        };
        try {
          const publication = recordCodexSecurityWorkerScanDraft(
            {
              root: artifactDir,
              repoRoot: targetPath,
              layout: "worker",
              scanId: run.scanId,
            },
            closed,
          );
          if (failClosedResult)
            await assert.rejects(
              publication,
              /Synthetic result replacement failure/,
            );
          else await publication;
        } finally {
          fsPromises.rename = originalRename;
        }
        assert.equal(failures, Number(failClosedResult));
        if (failClosedResult)
          assert.equal(await readFile(resultPath, "utf8"), before);
        const head = JSON.parse(
          await readFile(
            path.join(artifactDir, "checkpoint-head.json"),
            "utf8",
          ),
        );
        const selected = JSON.parse(
          await readFile(
            path.join(artifactDir, "checkpoints", head.checkpoint),
            "utf8",
          ),
        );
        assert.deepEqual(
          selected.coverage.resolvedDeferred,
          closed.coverage.resolvedDeferred,
        );
        assert.equal(
          selected.coverage.surfaces[0].disposition,
          "no_issue_found",
        );
      }
      for (const name of archived
        ? []
        : await readdir(path.join(artifactDir, "checkpoints"))) {
        const checkpointPath = path.join(artifactDir, "checkpoints", name);
        rawSources.set(checkpointPath, await readFile(checkpointPath, "utf8"));
      }
    }
    if (!archived) {
      rawSources.set(resultPath, await readFile(resultPath, "utf8"));
      if (namedRetry && index === 0) {
        const archive = path.join(
          path.dirname(artifactDir),
          "attempts",
          "attempt-01",
        );
        for (const name of await readdir(archive, { recursive: true })) {
          if (name.endsWith(".json") || name.endsWith(".md")) {
            const file = path.join(archive, name);
            rawSources.set(file, await readFile(file, "utf8"));
          }
        }
      }
    }
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
      if (receiptRetry || (namedRetry && index === 0)) {
        if (receiptRetry) await writeReceiptAttempt(artifactDir);
        else await writeDiscovery(artifactDir, index, true);
        await archiveDirectory(
          artifactDir,
          path.join(workerRoot, "attempts", "attempt-01"),
        );
      }
      await writeDiscovery(artifactDir, index);
      await writeFile(worker.promptPath, "Synthetic discovery prompt.\n");
      for (const status of ["queued", "running", "succeeded"]) {
        await store.updateWorker({
          ...worker,
          status,
          ...(status === "succeeded"
            ? { resultManifestPath: path.join(artifactDir, "result.json") }
            : {}),
        });
      }
      workers.push(worker);
    }
    const artifactDir = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "dedup",
      "dedup-0001",
      "output",
    );
    const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
    await mkdir(artifactDir, { recursive: true });
    await writeFile(promptPath, "Synthetic reducer prompt.\n");
    const id = randomUUID();
    await store.claimDedup({
      id,
      scanId: run.scanId,
      workerIds: (interruptReducer ? workers.slice(0, 2) : workers).map(
        (worker) => worker.id,
      ),
      artifactDir,
      promptPath,
    });
    const resultManifestPath = path.join(artifactDir, "result.json");
    if (interruptReducer) {
      const reducer = {
        id,
        scanId: run.scanId,
        kind: "dedup",
        promptPath,
        artifactDir,
        attempt: 1,
      };
      await store.updateWorker({ ...reducer, status: "running" });
      const publishParent = async () => {
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          {
            scanId: run.scanId,
            complete: true,
            findings: [],
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [],
              reviews: [],
            },
          },
          runWorkbench,
        );
        for (const name of [
          "coverage.json",
          "findings.json",
          "scan-manifest.json",
          "checkpoint-head.json",
          ...(await readdir(path.join(run.scanDir, "checkpoints"))).map(
            (name) => `checkpoints/${name}`,
          ),
        ])
          await utimes(path.join(run.scanDir, name), 1, 1);
      };
      if (parentTiming === "older") await publishParent();
      if (checkpointOnly) await mkdir(resultManifestPath);
      const writing = recordCodexSecurityDeepReduction(
        {
          root: artifactDir,
          layout: "reducer",
          repoRoot: targetPath,
          scanId: run.scanId,
          deepReducer: {
            scanRoot: run.scanDir,
            persistSourceCoverage: true,
            claimedWorkers: workers.slice(0, 2).map((worker) => ({
              id: worker.id,
              resultPath: path.join(worker.artifactDir, "result.json"),
              attempt: worker.attempt,
            })),
          },
        },
        { scanId: run.scanId, findings: [] },
      );
      if (checkpointOnly) {
        await assert.rejects(writing, /(?:EISDIR|EPERM|EACCES|ENOTEMPTY)/);
        await rm(resultManifestPath, { recursive: true });
        await assert.rejects(readFile(resultManifestPath), { code: "ENOENT" });
      } else await writing;
      const checkpoints = await readdir(path.join(artifactDir, "checkpoints"));
      assert.equal(checkpoints.length, 1);
      const selected = path.join(artifactDir, "checkpoints", checkpoints[0]);
      const result = JSON.parse(await readFile(selected, "utf8"));
      if (!checkpointOnly)
        assert.deepEqual(
          JSON.parse(await readFile(resultManifestPath, "utf8")),
          result,
        );
      if (parentTiming === "newer") {
        await utimes(selected, 0, 0);
        await publishParent();
      }
      for (const file of checkpointOnly
        ? [selected]
        : [resultManifestPath, selected])
        rawSources.set(file, await readFile(file, "utf8"));
      for (const worker of workers) {
        const receipt = path.join(worker.artifactDir, "artifacts", "review.md");
        rawSources.set(receipt, await readFile(receipt, "utf8"));
      }
      const represented = result.sourceCoverage;
      for (const worker of workers.slice(0, 2)) {
        const surfaces = represented.surfaces.filter(
          (row) => row.provenance.workerId === worker.id,
        );
        const deferred = represented.deferred.filter(
          (row) => row.provenance.workerId === worker.id,
        );
        assert.ok(surfaces.length > 0);
        assert.ok(deferred.length > 0);
        for (const surface of surfaces)
          assert.match(surface.id, /-attempt-\d+-surface-\d+$/);
        for (const row of deferred)
          assert.ok(
            row.surfaceIds.every((id) =>
              surfaces.some((surface) => surface.id === id),
            ),
          );
      }
      if (interruptReducer === "buffered")
        await store.updateWorker({
          ...reducer,
          status: "failed",
          error: "Synthetic interruption before commit.",
        });
      const stopped = await store.get(run.scanId, threadId);
      for (const worker of workers.slice(0, 2))
        assert.equal(
          stopped.persistedWorkers.find((row) => row.id === worker.id)
            .mergeState,
          interruptReducer,
        );
      assert.equal(
        stopped.persistedWorkers.find((row) => row.id === workers[2].id)
          .mergeState,
        "buffered",
      );
      assert.equal(
        stopped.persistedWorkers.find((row) => row.id === id)
          .resultManifestPath,
        undefined,
      );
      await runWorkbench([
        "fail-scan",
        "--scan-id",
        run.scanId,
        "--message",
        "Synthetic interruption before commit.",
      ]);
      const coveragePath = path.join(run.scanDir, "coverage.json");
      const recovered = JSON.parse(await readFile(coveragePath, "utf8"));
      for (const field of ["surfaces", "deferred"]) {
        const rows = recovered[field].filter(
          (row) => row.id !== "scan-stopped",
        );
        const keptProjection =
          parentTiming === "newer" ? [] : represented[field];
        assert.equal(
          rows.length,
          keptProjection.length +
            (parentTiming === "newer" ? workers.length : 1),
        );
        for (const projected of keptProjection)
          assert.ok(rows.some((row) => isDeepStrictEqual(row, projected)));
        if (parentTiming === "newer") {
          for (const worker of workers.slice(0, 2)) {
            const source = JSON.parse(
              await readFile(
                path.join(worker.artifactDir, "result.json"),
                "utf8",
              ),
            ).coverage[field][0];
            const retained = rows.find((row) => row.id === source.id);
            assert.ok(
              retained,
              "superseded projection must not hide a raw record",
            );
            assert.deepEqual(retained.provenance, source.provenance);
          }
        }
        const unrepresented = JSON.parse(
          await readFile(
            path.join(workers[2].artifactDir, "result.json"),
            "utf8",
          ),
        ).coverage[field][0];
        const retained = rows.find((row) => row.id === unrepresented.id);
        assert.ok(
          retained,
          "unrepresented buffered work keeps its saved identity",
        );
        assert.deepEqual(retained.provenance, unrepresented.provenance);
        if (field === "deferred")
          assert.deepEqual(retained.surfaceIds, unrepresented.surfaceIds);
      }
      const frozen = await readFile(coveragePath, "utf8");
      const replay = await runWorkbench([
        "recover-scan-results",
        "--scan-id",
        run.scanId,
      ]);
      assert.equal(replay.scan.resultsRecoveryNeeded, false);
      assert.equal(await readFile(coveragePath, "utf8"), frozen);
      for (const [file, bytes] of rawSources)
        assert.equal(await readFile(file, "utf8"), bytes);
      return { scanDir: run.scanDir, threadId };
    }
    // Legacy accepted reducers omitted coverage entirely.
    await writeFile(
      resultManifestPath,
      JSON.stringify({ scanId: run.scanId, findings: [] }),
    );
    rawSources.set(
      resultManifestPath,
      await readFile(resultManifestPath, "utf8"),
    );
    await store.commitDedup({
      id,
      scanId: run.scanId,
      newFindings: 0,
      resultManifestPath,
    });
    run = await store.get(run.scanId, threadId);
  }
  if (workflowVersion) {
    run = await store.get(run.scanId, threadId);
    assert.equal(run.workflowVersion, workflowVersion);
    const claim = await store.claimCoordinator({
      scanId: run.scanId,
      threadId,
    });
    assert.equal(claim.acquired, true);
    run = claim.run;
    assert.equal(run.workflowVersion, workflowVersion);
  }
  let discoveryCalls = 0;
  let interruptedDiscovery;
  const executor = {
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
        if (index === 0 && discoveryCalls === 1) {
          if (receiptRetry) {
            await writeReceiptAttempt(request.artifactContext.root);
          } else if (namedRetry) {
            await writeDiscovery(request.artifactContext.root, index, true);
          }
          if (streamRetry) {
            await writeDiscovery(request.artifactContext.root, index);
            interruptedDiscovery = {
              thread,
              root: request.artifactContext.root,
              result: await readFile(
                path.join(request.artifactContext.root, "result.json"),
                "utf8",
              ),
            };
            throw new Error(
              "Synthetic stream interruption after recorded result.",
            );
          }
          return {
            threadId: thread,
            finalResponse: "Continue the unfinished audit.",
          };
        }
        if (streamRetry && index === 0 && discoveryCalls === 2) {
          assert.equal(request.resumeThreadId, interruptedDiscovery.thread);
          assert.equal(request.artifactContext.root, interruptedDiscovery.root);
          assert.equal(
            await readFile(
              path.join(request.artifactContext.root, "result.json"),
              "utf8",
            ),
            interruptedDiscovery.result,
            "same-thread retry preserves the original result bytes",
          );
        } else await writeDiscovery(request.artifactContext.root, index);
      } else {
        await recordCodexSecurityDeepReduction(
          {
            ...request.artifactContext,
            repoRoot: targetPath,
            scanId: run.scanId,
          },
          { scanId: run.scanId, findings: [] },
        );
      }
      return { threadId: thread, finalResponse: "Audit finished." };
    },
  };
  let expectedCoverage;
  const coordinator = new DeepScanCoordinator({
    run,
    store,
    executor,
    pluginRoot,
    retryDelaysMs: [1],
    onComplete: async (draft, signal) => {
      if (missingProjection || descriptiveVariants) {
        expectedCoverage = structuredClone(draft.coverage);
        draft = structuredClone(draft);
        if (descriptiveVariants) {
          for (const field of [
            "surfaces",
            "deferred",
            "explicitExclusions",
            "openQuestions",
          ])
            draft.coverage[field].splice(1, 1);
        } else {
          if (missingProjection !== "deferred")
            draft.coverage.surfaces.splice(0, duplicateRows ? 2 : 1);
          if (missingProjection !== "surfaces") draft.coverage.deferred.shift();
        }
      }
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        draft,
        runWorkbench,
        signal,
        draft.coverage.resolvedDeferred,
      );
    },
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 30_000);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(
    terminal.noNewStreak,
    statuses.length,
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
    const result = JSON.parse(
      await readFile(worker.resultManifestPath, "utf8"),
    );
    const persisted =
      workflowVersion === "deep-security-scan/v2" &&
      !rawSources.has(worker.resultManifestPath);
    assert.equal(Object.hasOwn(result, "sourceCoverage"), persisted);
    if (persisted) assert.ok(result.sourceCoverage.reviews.length > 0);
    if (!rawSources.has(worker.resultManifestPath)) {
      const checkpoints = [];
      for (const name of await readdir(
        path.join(worker.artifactDir, "checkpoints"),
      )) {
        const checkpoint = JSON.parse(
          await readFile(
            path.join(worker.artifactDir, "checkpoints", name),
            "utf8",
          ),
        );
        assert.equal(Object.hasOwn(checkpoint, "sourceCoverage"), persisted);
        checkpoints.push(checkpoint);
      }
      if (persisted) {
        assert.ok(
          checkpoints.some((checkpoint) =>
            isDeepStrictEqual(checkpoint.sourceCoverage, result.sourceCoverage),
          ),
          "final coverage must have an immutable checkpoint",
        );
      }
    }
  }
  const parentCoverage = JSON.parse(
    await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
  );
  if (sameAttemptChange) {
    const worker = accepted.persistedWorkers.find(
      (worker) => worker.kind === "discovery",
    );
    const resultPath = worker.resultManifestPath;
    const updated = JSON.parse(await readFile(resultPath, "utf8"));
    updated.coverage.surfaces[0].label = "Updated source review";
    updated.coverage.surfaces[0].provenance.description =
      "Updated surface context.";
    updated.coverage.deferred[0].reason = "Updated source review remains.";
    if (directFile) await writeFile(resultPath, JSON.stringify(updated));
    else {
      await recordCodexSecurityWorkerScanDraft(
        {
          root: worker.artifactDir,
          repoRoot: targetPath,
          layout: "worker",
          scanId: run.scanId,
        },
        updated,
      );
      for (const name of await readdir(
        path.join(worker.artifactDir, "checkpoints"),
      )) {
        const file = path.join(worker.artifactDir, "checkpoints", name);
        if (!rawSources.has(file))
          rawSources.set(file, await readFile(file, "utf8"));
      }
    }
    rawSources.set(resultPath, await readFile(resultPath, "utf8"));
    const after = await store.get(run.scanId, threadId);
    assert.equal(
      after.persistedWorkers.find((row) => row.id === worker.id).attempt,
      worker.attempt,
    );
  }
  if (stopAfterDraft) {
    await runWorkbench([
      "fail-scan",
      "--scan-id",
      run.scanId,
      "--message",
      "Synthetic stop after parent draft.",
    ]);
    const recovered = await runWorkbench([
      "recover-scan-results",
      "--scan-id",
      run.scanId,
    ]);
    assert.equal(recovered.scan.resultsRecoveryNeeded, false);
  } else {
    await runWorkbench(["complete-scan", "--scan-id", run.scanId]);
    const completed = await getCodexSecurityCompletedScan(
      await createScanArtifactContext(run.scanId, runWorkbench),
      { scanId: run.scanId },
    );
    assert.deepEqual(
      completed.coverage,
      JSON.parse(
        await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
      ),
    );
  }
  const finalCoverage = JSON.parse(
    await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
  );
  if (descriptiveVariants) {
    for (const field of [
      "surfaces",
      "deferred",
      "explicitExclusions",
      "openQuestions",
    ]) {
      const rows = finalCoverage[field].filter(
        (row) => row.id !== "scan-stopped",
      );
      const expected = expectedCoverage[field];
      assert.equal(rows.length, expected.length, field);
      for (const row of expected) {
        const actual = rows.find((actual) => {
          if (field !== "explicitExclusions" || row.id !== undefined)
            return isDeepStrictEqual(actual, row);
          const { id, ...content } = actual;
          return (
            isDeepStrictEqual(content, row) &&
            (id === undefined || /^saved-/.test(id))
          );
        });
        assert.ok(actual, field);
      }
    }
  }
  if (
    (directFile || omitCoverageIds) &&
    !descriptiveVariants &&
    !sameAttemptChange
  ) {
    const expected = expectedCoverage ?? parentCoverage;
    const rows = (items) =>
      missingProjection
        ? [...items].sort((left, right) => left.id.localeCompare(right.id))
        : items;
    assert.deepEqual(rows(finalCoverage.surfaces), rows(expected.surfaces));
    assert.deepEqual(
      rows(finalCoverage.deferred.filter((row) => row.id !== "scan-stopped")),
      rows(expected.deferred),
    );
  }
  if (sameAttemptChange) {
    for (const surface of parentCoverage.surfaces)
      assert.ok(
        finalCoverage.surfaces.some((row) => isDeepStrictEqual(row, surface)),
      );
    for (const deferred of parentCoverage.deferred)
      assert.ok(
        finalCoverage.deferred.some((row) => isDeepStrictEqual(row, deferred)),
      );
    const changed = finalCoverage.surfaces.filter(
      (row) => row.label === "Updated source review",
    );
    assert.equal(changed.length, 1);
    assert.notEqual(changed[0].id, parentCoverage.surfaces[0].id);
    assert.equal(
      changed[0].provenance.attempt,
      parentCoverage.surfaces[0].provenance.attempt,
    );
    assert.equal(changed[0].provenance.description, "Updated surface context.");
    const pending = finalCoverage.deferred.filter(
      (row) => row.reason === "Updated source review remains.",
    );
    assert.equal(pending.length, 1);
    assert.deepEqual(pending[0].surfaceIds, [changed[0].id]);
  }
  if (changedRetry) {
    for (const field of ["surfaces", "deferred"])
      assert.equal(parentCoverage[field][0].provenance.attempt, 2);
  }
  if (omitCoverageIds) {
    for (const field of ["surfaces", "deferred"]) {
      const retainedArchive =
        directFile && namedRetry && changedRetry
          ? parentCoverage[field].filter((row) =>
              field === "surfaces"
                ? row.label === "Earlier independent route"
                : row.reason === "An earlier independent observation.",
            )
          : [];
      if (directFile && namedRetry && changedRetry) {
        assert.equal(
          retainedArchive.length,
          1,
          "the independent archived observation remains",
        );
        const row = retainedArchive[0];
        assert.equal(row.provenance.attempt, 1);
        const worker = accepted.persistedWorkers.find(
          (worker) => worker.id === row.provenance.workerId,
        );
        const savedPath = path.join(
          path.dirname(worker.artifactDir),
          "attempts",
          "attempt-01",
          "result.json",
        );
        const saved = JSON.parse(rawSources.get(savedPath));
        assert.ok(
          saved.coverage[field].some(
            (source) =>
              source.id === row.provenance.sourceId &&
              (field === "surfaces"
                ? source.label === row.label
                : source.reason === row.reason),
          ),
          "archived sourceId describes the immutable saved observation",
        );
      }
      const currentRows = parentCoverage[field].filter(
        (row) => !retainedArchive.includes(row),
      );
      const ids = currentRows.flatMap((row) =>
        typeof row.provenance.sourceId === "string"
          ? [row.provenance.sourceId]
          : [],
      );
      assert.equal(
        ids.length,
        directFile
          ? competingIds
            ? currentRows.length / 2
            : 0
          : currentRows.length,
        "sourceId must describe an identity persisted in the worker source",
      );
      if (directFile && competingIds)
        assert.deepEqual(
          new Set(ids),
          new Set([field === "surfaces" ? "owned-surface" : "owned-deferred"]),
        );
    }
  }
  for (const [file, bytes] of rawSources)
    assert.equal(await readFile(file, "utf8"), bytes);
  if (closeGeneric) {
    const coverage = JSON.parse(
      await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
    );
    const surfaces = coverage.surfaces.filter(
      (row) => row.label === "Archive route",
    );
    assert.equal(
      surfaces.length,
      1,
      "generic closure replaces the retained host surface",
    );
    assert.equal(surfaces[0].disposition, "no_issue_found");
    assert.equal(
      coverage.deferred.some(
        (row) => row.reason === "Finish the source review.",
      ),
      false,
    );
  }
  if (streamRetry) {
    const first = accepted.persistedWorkers.find(
      (worker) => worker.kind === "discovery",
    );
    assert.equal(
      first.attempt,
      2,
      "host accepted the resumed execution attempt",
    );
    const coverage = JSON.parse(
      await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
    );
    const rows = coverage.surfaces.filter(
      (row) => row.provenance?.workerId === first.id,
    );
    assert.equal(rows.length, 1);
    assert.equal(
      rows[0].provenance.attempt,
      1,
      "recorded coverage belongs to original execution attempt",
    );
    assert.match(rows[0].id, new RegExp(`^${first.id}-attempt-1-surface-`));
    for (const field of ["explicitExclusions", "deferred", "openQuestions"])
      for (const row of coverage[field] ?? [])
        if (row.provenance?.workerId === first.id)
          assert.equal(row.provenance.attempt, 1);
    assert.deepEqual(
      coverage.reviews
        .filter((review) => review.workerId === first.id)
        .map((review) => review.attempt)
        .sort(),
      [1, 2],
    );
    assert.equal(
      await readFile(path.join(run.scanDir, rows[0].receiptRefs[0]), "utf8"),
      "Synthetic review evidence.\n",
    );
  }
  if (receiptRetry) {
    const coverage = JSON.parse(
      await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
    );
    const current = coverage.surfaces.filter(
      (surface) => surface.label === "Current review",
    );
    assert.equal(current.length, 1);
    assert.match(current[0].receiptRefs[0], /\/output\/artifacts\/review\.md$/);
    assert.equal(
      await readFile(path.join(run.scanDir, current[0].receiptRefs[0]), "utf8"),
      "Synthetic review evidence.\n",
    );
    const prior = coverage.surfaces.filter(
      (surface) => surface.label === "Prior review",
    );
    assert.equal(prior.length, 1);
    assert.equal(prior[0].disposition, "no_issue_found");
    assert.equal(prior[0].provenance.attempt, 1);
    assert.equal(current[0].provenance.attempt, 2);
    assert.deepEqual(
      coverage.reviews.map((review) => review.attempt).sort(),
      [1, 2],
    );
    assert.match(
      prior[0].receiptRefs[0],
      /\/attempts\/attempt-01\/artifacts\/prior\.txt$/,
    );
    assert.equal(
      await readFile(path.join(run.scanDir, prior[0].receiptRefs[0]), "utf8"),
      "Archived receipt.\n",
    );
  }
  return { scanDir: run.scanDir, threadId, terminal };
}

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
