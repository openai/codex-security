import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { dirname, join } from "node:path";

import { deepDedupPrompt, deepDiscoveryPrompt, deepTailPrompt } from "./prompt.mjs";
import { runClaudeSession } from "./runner.mjs";
import {
  IncompleteScanError,
  SecurityError,
  ensureDirectory,
  isFile,
  readJson,
  stateDirectory,
} from "./util.mjs";
import { runWorkbench } from "./workbench.mjs";

const WORKFLOW_VERSION = "deep-security-scan/v1";

/**
 * Runs a deep scan: repeated independent discovery until the search saturates,
 * then one centralized tail session.
 *
 * The fan-out lives here rather than in the model's hands on purpose. The
 * workbench enforces a strict state machine — a dedup may only claim an ordered
 * prefix of buffered discovery results, `saturated` may only be declared once
 * the no-new streak is reached, `capped` only at the dispatch ceiling — and a
 * deterministic coordinator can honor that exactly, resume from a crash, and
 * respect --workers. A model asked to orchestrate its own fan-out cannot
 * promise any of those.
 */
export async function runDeepScan(options) {
  const { scanId, scanDir, target, workbenchOptions } = options;
  const observer = options.observer ?? {};
  const threadId = randomUUID();

  await writeDeepScanConfig(options.deep);

  const paths = deepPaths(scanDir);
  await ensureDirectory(paths.workersDir);
  await ensureDirectory(paths.dedupDir);
  await ensureDirectory(paths.canonical.findingsDir);
  // The workbench rejects a canonical artifact path whose parent does not
  // exist, so every destination directory is created before orchestration.
  for (const [label, path] of Object.entries(paths.canonical)) {
    if (label !== "findingsDir") await ensureDirectory(dirname(path));
  }

  let state = deepState(
    await deepWorkbench(workbenchOptions, [
      "begin-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId,
      "--available-parallelism",
      String(Math.max(1, availableParallelism())),
      "--workflow-version",
      WORKFLOW_VERSION,
    ]),
  );
  observer.onDeepScanStarted?.({ config: state.config });

  const buffered = [];
  const workerRecords = new Map();
  let round = 0;
  let terminalReason = null;

  try {
    while (terminalReason === null) {
      const dispatchBudget = state.config.maxDiscoveryRuns - state.dispatchedCount;
      const saturated = state.noNewStreak >= state.config.stopAfterNoNew;
      if (saturated) terminalReason = "saturated";
      else if (dispatchBudget <= 0) terminalReason = "capped";
      if (terminalReason !== null) break;

      round += 1;
      const batchSize = Math.min(state.config.workers, dispatchBudget);

      observer.onDeepRoundStarted?.({ round, workers: batchSize, noNewStreak: state.noNewStreak });

      const launched = await Promise.all(
        Array.from({ length: batchSize }, (_unused, index) =>
          runDiscoveryWorker({
            ...options,
            paths,
            round,
            workerIndex: index + 1,
            threadId,
          }),
        ),
      );
      for (const record of launched) {
        workerRecords.set(record.workerId, record);
        if (record.ok) buffered.push(record);
      }
      if (buffered.length === 0) {
        throw new IncompleteScanError(
          `Every discovery worker in pass ${round} failed. Last error: ${
            launched.find((record) => !record.ok)?.error ?? "unknown"
          }`,
        );
      }

      state = deepState(await getDeepScan(workbenchOptions, scanId, threadId));

      // The workbench requires two buffered passes for the very first reduction
      // and one thereafter. With --workers 1 that means dispatching another pass
      // rather than quietly running two workers the operator did not ask for.
      const minimumInputs = state.canonicalArtifacts.candidatesPath === null ? 2 : 1;
      if (
        buffered.length < minimumInputs &&
        state.config.maxDiscoveryRuns - state.dispatchedCount > 0
      ) {
        continue;
      }

      const reductionInputs = orderByCompletion(buffered.splice(0, buffered.length), state);
      const reduction = await runReduction({
        ...options,
        paths,
        round,
        inputs: reductionInputs,
        priorCanonicalCandidatesPath: state.canonicalArtifacts.candidatesPath ?? undefined,
      });
      observer.onDeepRoundFinished?.({
        round,
        merged: reductionInputs.length,
        newFindings: reduction.newFindingsCount,
        canonicalCandidates: reduction.canonicalCandidateCount,
      });
      state = deepState(await getDeepScan(workbenchOptions, scanId, threadId));
    }

    if (buffered.length > 0) {
      // Neither terminal reason may be declared while a discovery result is
      // still buffered, so the tail is always flushed first.
      const reductionInputs = orderByCompletion(buffered.splice(0, buffered.length), state);
      await runReduction({
        ...options,
        paths,
        round: round + 1,
        inputs: reductionInputs,
        priorCanonicalCandidatesPath: state.canonicalArtifacts.candidatesPath ?? undefined,
      });
      state = deepState(await getDeepScan(workbenchOptions, scanId, threadId));
      // That flush can reset the no-new streak, which would make an earlier
      // `saturated` decision one the workbench now rejects. Re-decide from the
      // state that actually exists.
      terminalReason =
        state.noNewStreak >= state.config.stopAfterNoNew ? "saturated" : "capped";
      if (
        terminalReason === "capped" &&
        state.dispatchedCount < state.config.maxDiscoveryRuns
      ) {
        throw new IncompleteScanError(
          "Repeated discovery stopped before either terminal condition was reached.",
        );
      }
    }

    if (state.canonicalArtifacts.candidatesPath === null) {
      throw new IncompleteScanError(
        "Repeated discovery ended without producing a canonical candidate set.",
      );
    }

    const manifest = buildTerminalManifest({
      state,
      scanId,
      terminalReason,
      round,
      workerRecords,
      paths,
    });
    await writeFile(paths.manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });

    await deepWorkbench(workbenchOptions, [
      "finish-deep-scan",
      "--scan-id",
      scanId,
      "--terminal-reason",
      terminalReason,
      "--manifest-path",
      paths.manifestPath,
    ]);
    observer.onDeepScanFinished?.({
      terminalReason,
      discoveryPasses: state.dispatchedCount,
      manifestPath: paths.manifestPath,
    });
  } catch (error) {
    await deepWorkbench({ ...workbenchOptions, signal: undefined }, [
      "fail-deep-scan",
      "--scan-id",
      scanId,
      "--message",
      String(error?.message ?? error).slice(0, 2400),
    ]).catch(() => {});
    throw error;
  }

  observer.onDeepTailStarted?.();
  return await runClaudeSession({
    cwd: options.cwd,
    environment: options.environment,
    model: options.model,
    effort: options.effort,
    settings: options.settings,
    addDirs: options.addDirs,
    signal: options.signal,
    observer,
    sessionName: options.sessionName,
    prompt: deepTailPrompt({
      manifestPath: paths.manifestPath,
      target,
      hasKnowledgeBase: options.hasKnowledgeBase,
      falsePositiveFeedbackPath: options.falsePositiveFeedbackPath,
    }),
  });
}

/**
 * Sorts reduction inputs into the order the workbench buffered them.
 *
 * A dedup may only claim an ordered prefix of buffered discovery results *in
 * completion order*, and workers run concurrently — the one dispatched first
 * routinely finishes second. Launch order is therefore not the same list, so
 * the sequence the workbench assigned at `succeeded` is the only correct key.
 * Anything the workbench does not know about sorts last, so a missing sequence
 * degrades to a stable order instead of a silent misclaim.
 */
export function orderByCompletion(records, state) {
  const sequenceById = new Map(
    (state.workers ?? [])
      .filter((worker) => typeof worker?.completionSequence === "number")
      .map((worker) => [worker.id, worker.completionSequence]),
  );
  return [...records].sort(
    (left, right) =>
      (sequenceById.get(left.workerId) ?? Number.MAX_SAFE_INTEGER) -
      (sequenceById.get(right.workerId) ?? Number.MAX_SAFE_INTEGER),
  );
}

function deepPaths(scanDir) {
  const artifacts = join(scanDir, "artifacts");
  const discovery = join(artifacts, "02_discovery");
  const deep = join(discovery, "deep");
  return {
    deep,
    workersDir: join(deep, "workers"),
    dedupDir: join(deep, "dedup"),
    manifestPath: join(deep, "discovery_manifest.json"),
    canonical: {
      inventory: join(discovery, "candidate_inventory.jsonl"),
      findingReport: join(discovery, "finding_discovery_report.md"),
      candidates: join(artifacts, "04_reconciliation", "deduped_candidates.jsonl"),
      dedupeReport: join(artifacts, "04_reconciliation", "dedupe_report.md"),
      seedResearch: join(artifacts, "01_context", "seed_research.md"),
      workLedger: join(discovery, "work_ledger.jsonl"),
      rawCandidates: join(discovery, "raw_candidates.jsonl"),
      coverageLedger: join(artifacts, "03_coverage", "repository_coverage_ledger.md"),
      findingsDir: join(artifacts, "05_findings"),
    },
  };
}

/**
 * Deep-scan sizing lives in a per-user TOML the Python resolver owns, so CLI
 * flags are written there before orchestration starts rather than threaded
 * through a second, divergent code path.
 */
async function writeDeepScanConfig(deep) {
  // The Python resolver looks for this file under the state directory, which the
  // workbench environment exports as CODEX_HOME.
  const configDir = join(stateDirectory(), "codex-security");
  await ensureDirectory(configDir);
  const lines = ["# Written by claude-security. Values come from the scan's CLI flags.", "[deep_scan]"];
  if (deep?.workers !== undefined) lines.push(`workers = ${deep.workers}`);
  if (deep?.subagents !== undefined) lines.push(`subagents = ${deep.subagents}`);
  if (deep?.stopAfterNoNew !== undefined) lines.push(`stop_after_no_new = ${deep.stopAfterNoNew}`);
  if (deep?.maxDiscoveryRuns !== undefined) {
    lines.push(`max_discovery_runs = ${deep.maxDiscoveryRuns}`);
  }
  await writeFile(join(configDir, "config.toml"), `${lines.join("\n")}\n`, { mode: 0o600 });
}

async function deepWorkbench(workbenchOptions, args) {
  return await runWorkbench(
    { ...workbenchOptions, failureMessage: "Deep scan orchestration failed" },
    args,
  );
}

async function getDeepScan(workbenchOptions, scanId, threadId) {
  return await deepWorkbench(workbenchOptions, [
    "get-deep-scan",
    "--scan-id",
    scanId,
    "--thread-id",
    threadId,
  ]);
}

function deepState(result) {
  const state = result?.["deepScan"];
  if (!state || typeof state !== "object") {
    throw new SecurityError("The workbench returned an invalid deep-scan state.");
  }
  return state;
}

async function runDiscoveryWorker(options) {
  const { paths, workbenchOptions, scanId } = options;
  const workerId = randomUUID();
  const artifactDir = join(paths.workersDir, workerId);
  await ensureDirectory(artifactDir);
  const promptPath = join(artifactDir, "prompt.md");
  const resultManifestPath = join(artifactDir, "result.json");

  const prompt = deepDiscoveryPrompt({
    workerId,
    workerIndex: options.workerIndex,
    round: options.round,
    artifactDir,
    resultManifestPath,
    userContext: options.userContext,
  });
  await writeFile(promptPath, `${prompt}\n`, { mode: 0o600 });

  const identity = [
    "--scan-id",
    scanId,
    "--worker-id",
    workerId,
    "--kind",
    "discovery",
    "--prompt-path",
    promptPath,
    "--artifact-dir",
    artifactDir,
  ];

  await deepWorkbench(workbenchOptions, [
    "upsert-deep-scan-worker",
    ...identity,
    "--status",
    "queued",
  ]);
  await deepWorkbench(workbenchOptions, [
    "upsert-deep-scan-worker",
    ...identity,
    "--status",
    "running",
    "--attempt",
    "1",
  ]);

  try {
    const session = await runClaudeSession({
      cwd: options.cwd,
      environment: options.environment,
      model: options.model,
      effort: options.effort,
      settings: options.settings,
      addDirs: options.addDirs,
      signal: options.signal,
      sessionName: `claude-security discovery ${options.round}.${options.workerIndex}`,
      prompt,
      observer: {
        onToolUse: () => options.observer?.onDeepWorkerActivity?.({ workerId }),
      },
    });
    if (session.isError) throw new Error(`session ended as ${session.subtype ?? "error"}`);
    if (!(await isFile(resultManifestPath))) {
      throw new Error(`worker did not write ${resultManifestPath}`);
    }
    const manifest = await readJson(resultManifestPath);
    await deepWorkbench(workbenchOptions, [
      "upsert-deep-scan-worker",
      ...identity,
      "--status",
      "succeeded",
      "--attempt",
      "1",
      "--result-manifest-path",
      resultManifestPath,
      ...(session.sessionId === null ? [] : ["--sdk-thread-id", session.sessionId]),
    ]);
    return {
      ok: true,
      workerId,
      round: options.round,
      artifactDir,
      resultManifestPath,
      threatModelPath: manifest["threatModelPath"] ?? join(artifactDir, "threat_model.md"),
      rawCandidatesPath: manifest["rawCandidatesPath"] ?? join(artifactDir, "raw_candidates.jsonl"),
      inScopeFilesPath: manifest["inScopeFilesPath"] ?? join(artifactDir, "in_scope_files.txt"),
      reportPath: manifest["reportPath"] ?? join(artifactDir, "finding_discovery_report.md"),
      candidateCount: Number(manifest["candidateCount"] ?? 0),
    };
  } catch (error) {
    const message = String(error?.message ?? error).slice(0, 2400);
    await deepWorkbench({ ...workbenchOptions, signal: undefined }, [
      "upsert-deep-scan-worker",
      ...identity,
      "--status",
      "failed",
      "--attempt",
      "1",
      "--error-message",
      message,
    ]).catch(() => {});
    options.observer?.onWarning?.(`Discovery worker failed: ${message}`);
    return { ok: false, workerId, error: message };
  }
}

async function runReduction(options) {
  const { paths, workbenchOptions, scanId, inputs } = options;
  const workerId = randomUUID();
  const artifactDir = join(paths.dedupDir, workerId);
  await ensureDirectory(artifactDir);
  const promptPath = join(artifactDir, "prompt.md");
  const resultManifestPath = join(artifactDir, "result.json");

  const prompt = deepDedupPrompt({
    inputs,
    canonical: paths.canonical,
    resultManifestPath,
    priorCanonicalCandidatesPath: options.priorCanonicalCandidatesPath,
  });
  await writeFile(promptPath, `${prompt}\n`, { mode: 0o600 });

  await deepWorkbench(workbenchOptions, [
    "claim-deep-scan-dedup",
    "--scan-id",
    scanId,
    "--worker-id",
    workerId,
    "--prompt-path",
    promptPath,
    "--artifact-dir",
    artifactDir,
    ...inputs.flatMap((input) => ["--input-worker-id", input.workerId]),
  ]);

  const session = await runClaudeSession({
    cwd: options.cwd,
    environment: options.environment,
    model: options.model,
    effort: options.effort,
    settings: options.settings,
    addDirs: options.addDirs,
    signal: options.signal,
    sessionName: `claude-security reduce ${options.round}`,
    prompt,
    observer: { onToolUse: () => options.observer?.onDeepWorkerActivity?.({ workerId }) },
  });
  if (session.isError) {
    throw new IncompleteScanError(
      `The deep-scan reduction for pass ${options.round} ended as ${session.subtype ?? "error"}.`,
    );
  }

  const missing = [];
  for (const [label, path] of Object.entries(paths.canonical)) {
    if (label === "findingsDir") continue;
    if (!(await isFile(path))) missing.push(path);
  }
  if (!(await isFile(resultManifestPath))) missing.push(resultManifestPath);
  if (missing.length > 0) {
    throw new IncompleteScanError(
      `The deep-scan reduction for pass ${options.round} did not write: ${missing.join(", ")}`,
    );
  }

  const manifest = await readJson(resultManifestPath);
  const newFindingsCount = Number(manifest["newFindingsCount"]);
  if (!Number.isInteger(newFindingsCount) || newFindingsCount < 0) {
    throw new IncompleteScanError(
      `The deep-scan reduction reported an invalid newFindingsCount: ${manifest["newFindingsCount"]}`,
    );
  }

  await deepWorkbench(workbenchOptions, [
    "commit-deep-scan-dedup",
    "--scan-id",
    scanId,
    "--worker-id",
    workerId,
    "--canonical-inventory-path",
    paths.canonical.inventory,
    "--canonical-finding-report-path",
    paths.canonical.findingReport,
    "--canonical-candidates-path",
    paths.canonical.candidates,
    "--dedupe-report-path",
    paths.canonical.dedupeReport,
    "--seed-research-path",
    paths.canonical.seedResearch,
    "--work-ledger-path",
    paths.canonical.workLedger,
    "--raw-candidates-path",
    paths.canonical.rawCandidates,
    "--coverage-ledger-path",
    paths.canonical.coverageLedger,
    "--findings-dir",
    paths.canonical.findingsDir,
    "--result-manifest-path",
    resultManifestPath,
    "--new-findings-count",
    String(newFindingsCount),
  ]);

  return {
    newFindingsCount,
    canonicalCandidateCount: Number(manifest["canonicalCandidateCount"] ?? 0),
  };
}

function buildTerminalManifest({ state, scanId, terminalReason, round, workerRecords, paths }) {
  const records = [...workerRecords.values()];
  return {
    documentType: "claude-security.deep-discovery-manifest",
    schemaVersion: "1.0",
    workflowVersion: WORKFLOW_VERSION,
    scanId,
    terminalReason,
    config: state.config,
    discoveryPasses: state.dispatchedCount,
    reductionRounds: round,
    noNewStreak: state.noNewStreak,
    canonicalArtifacts: {
      candidateInventoryPath: paths.canonical.inventory,
      findingDiscoveryReportPath: paths.canonical.findingReport,
      dedupedCandidatesPath: paths.canonical.candidates,
      dedupeReportPath: paths.canonical.dedupeReport,
      seedResearchPath: paths.canonical.seedResearch,
      workLedgerPath: paths.canonical.workLedger,
      rawCandidatesPath: paths.canonical.rawCandidates,
      coverageLedgerPath: paths.canonical.coverageLedger,
      findingsDir: paths.canonical.findingsDir,
    },
    workerThreatModelPaths: records
      .filter((record) => record.ok)
      .sort((left, right) => left.round - right.round)
      .map((record) => record.threatModelPath),
    mergedWorkerIds: records.filter((record) => record.ok).map((record) => record.workerId),
    failedWorkerIds: records.filter((record) => !record.ok).map((record) => record.workerId),
    omittedWorkerIds: [],
  };
}
