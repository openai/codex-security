import { Codex } from "@openai/codex-sdk";
import { readCodexTurn } from "../src/scan-events.js";
import { loadDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import { randomUUID } from "node:crypto";
import {
  cp,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import * as timers from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, expect, spyOn, test } from "bun:test";
import type { ScanOptions } from "../src/api.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import { estimateScanCost, type ScanCost } from "../src/cost.js";
import type { JsonObject as WorkbenchJsonObject } from "../src/config.js";
import {
  runDeepScans,
  ScanCostTrackingError,
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
  type DeepScanComposition,
} from "../src/deep-scan.js";
import { loadContract } from "../src/contract.js";
import { ScanResult } from "../src/result.js";
import { abortable } from "../src/targets.js";
import {
  ScanPermissionError,
  ScanTransportClosedError,
} from "../src/scan-execution.js";
import { semanticScanDraft, type SemanticScan } from "../src/scan-semantics.js";
import type {
  ScanManifest,
  FindingsDocument,
  CoverageDocument,
} from "../src/models.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const example = join(pluginRoot, "examples/completed-scan");
const roots: string[] = [];
let exampleManifest: ScanManifest;
let exampleFindings: FindingsDocument;
let exampleCoverage: CoverageDocument;
let retryDelay:
  ReturnType<typeof spyOn<typeof timers, "setTimeout">> | undefined;

beforeAll(async () => {
  [exampleManifest, exampleFindings, exampleCoverage] = await Promise.all(
    ["scan-manifest.json", "findings.json", "coverage.json"].map(async (file) =>
      JSON.parse(await readFile(join(example, file), "utf8")),
    ),
  );
});

afterEach(async () => {
  retryDelay?.mockRestore();
  retryDelay = undefined;
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

function result(
  scanId: string,
  scanDir: string,
  identity?: string,
): ScanResult {
  const manifest = structuredClone(exampleManifest);
  manifest.scan.id = scanId;
  const findings = structuredClone(exampleFindings);
  findings.scanId = scanId;
  if (identity === undefined) findings.findings = [];
  else findings.findings[0]!.identity = { anchor: identity };
  const coverage = structuredClone(exampleCoverage);
  coverage.scanId = scanId;
  coverage.surfaces = [];
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    threadId: `thread-${scanId}`,
    turnResult: {},
  });
}

async function codexStreamError(item: string): Promise<Error> {
  const thread = new Codex({
    codexPathOverride: process.execPath,
  }).startThread();
  const executable = thread as unknown as {
    _exec: { run(): AsyncGenerator<string> };
  };
  executable._exec.run = async function* () {
    yield item;
  };
  try {
    await readCodexTurn({
      thread,
      events: (await thread.runStreamed("Synthetic stream failure.")).events,
    });
  } catch (error) {
    if (error instanceof Error) return error;
    throw error;
  }
  throw new Error("The synthetic stream did not fail.");
}

interface SavedRecord {
  completedAt?: string;
  scanId: string;
  scanDir: string;
  parentScanId: string;
  parentScanRole?: "deep_pass" | null;
  targetPath: string;
  progress: { status: string };
  continuationThreadId?: string;
  cost?: ScanCost | null;
}

async function harness(
  settings: Partial<DeepScanComposition["settings"]> = {},
) {
  const root = await mkdtemp(join(tmpdir(), "deep-scan-composition-"));
  roots.push(root);
  const scanDir = join(root, "parent");
  const repository = join(root, "repository");
  await mkdir(scanDir, { mode: 0o700 });
  await mkdir(repository);
  const controller = new AbortController();
  const scanId = randomUUID();
  const records = new Map<string, SavedRecord>();
  const projectedResults = new Map<string, ScanResult>();
  const calls: ScanOptions[] = [];
  const published: SemanticScan[] = [];
  const checkpoints: DeepScanCheckpoint[] = [];
  const mergeInputs: number[] = [];
  let closed = 0;
  let active = 0;
  let maximumActive = 0;
  let run = async (options: ScanOptions): Promise<ScanResult> =>
    result(options.resumeScanId ?? randomUUID(), options.outputDir!);
  const input: DeepScanComposition = {
    scanId,
    scanDir,
    repository,
    pluginRoot,
    startedAt: new Date().toISOString(),
    settings: {
      workers: 1,
      subagents: 3,
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 3,
      maxDiscoveryRuns: 8,
      maxTimeHours: 1,
      ...settings,
    },
    scanOptions: {},
    signal: controller.signal,
    createClient: () => ({
      async run(_repository, options = {}) {
        calls.push(options);
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        const id = options.resumeScanId ?? randomUUID();
        records.set(id, {
          ...records.get(id),
          scanId: id,
          scanDir: options.outputDir!,
          parentScanId: scanId,
          parentScanRole: "deep_pass",
          targetPath: repository,
          progress: { status: "running" },
        });
        await mkdir(options.outputDir!, { recursive: true, mode: 0o700 });
        await options.onRegisteredScan?.({
          scanId: id,
          scanDir: options.outputDir!,
          threadId: records.get(id)!.continuationThreadId ?? null,
        });
        try {
          const completed = await run({ ...options, resumeScanId: id });
          records.get(id)!.progress.status = "complete";
          records.get(id)!.completedAt = new Date().toISOString();
          projectedResults.set(completed.manifest.scan.id, completed);
          return completed;
        } finally {
          active -= 1;
        }
      },
      async close() {
        closed += 1;
      },
    }),
    async projectChild(childId, childDir) {
      const completed =
        projectedResults.get(childId) ??
        (await loadContract(childDir, { pluginRoot, expectedScanId: childId }));
      const sourceFindings = structuredClone(completed.findings.findings);
      const draft = semanticScanDraft(
        scanId,
        completed.manifest.scan,
        sourceFindings,
        completed.coverage,
      );
      for (const [index, finding] of draft.findings.entries()) {
        finding.provenance.sourceFindingIds = [`${childId}:${index}`];
      }
      return { scanId: childId, scanDir: childDir, draft, sourceFindings };
    },
    async workbench(args, contents) {
      if (args[0] === "save-scan-artifact") {
        const state = JSON.parse(contents!) as DeepScanCheckpoint;
        if (args[4] === DEEP_SCAN_CHECKPOINT) checkpoints.push(state);
        const path = join(scanDir, args[4]!);
        await mkdir(dirname(path), { recursive: true });
        const temporary = `${path}.${randomUUID()}.tmp`;
        await writeFile(temporary, contents!);
        await rename(temporary, path);
        return {};
      }
      if (args[0] === "update-progress") return {};
      if (args[0] === "list-scans")
        return {
          scans: [...records.values()],
        } as unknown as WorkbenchJsonObject;
      if (args[0] === "get-scan")
        return {
          scan: records.get(args[2]!) ?? { progress: { status: "running" } },
        } as unknown as WorkbenchJsonObject;
      if (args[0] === "fail-scan") {
        if (args[4]!.length > 2400)
          throw new Error("Text value must be no longer than 2400 characters.");
        const record = records.get(args[2]!)!;
        if (record.progress.status === "complete")
          throw new Error("A completed scan cannot be marked failed.");
        record.progress.status = "failed";
        record.completedAt = new Date().toISOString();
        const costIndex = args.indexOf("--cost-json");
        record.cost = costIndex < 0 ? null : JSON.parse(args[costIndex + 1]!);
        return {};
      }
      throw new Error(`Unexpected workbench operation ${args[0]}`);
    },
    async merge(prompt) {
      const payload = JSON.parse(prompt.split("\n").at(-1)!);
      mergeInputs.push(payload.findings.after.length);
      return { matches: [], uncertain: [], related: [], request: null };
    },
    writer: {
      async restoreMany(artifacts) {
        for (const artifact of artifacts) {
          await mkdir(dirname(join(scanDir, artifact.path)), {
            recursive: true,
          });
          await writeFile(join(scanDir, artifact.path), artifact.contents);
        }
      },
      async restore(path, contents) {
        await mkdir(dirname(join(scanDir, path)), { recursive: true });
        await writeFile(join(scanDir, path), contents);
      },
    },
    async publish(draft) {
      published.push(structuredClone(draft));
    },
    onCost() {},
  };
  return {
    input,
    records,
    calls,
    published,
    checkpoints,
    mergeInputs,
    controller,
    setRun(value: typeof run) {
      run = value;
    },
    metrics: () => ({ closed, maximumActive }),
    checkpoint: async () => (await loadDeepScanCheckpoint(scanDir))!,
    async seed(state: DeepScanCheckpoint) {
      const path = join(scanDir, DEEP_SCAN_CHECKPOINT);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify(state));
    },
  };
}

test("only the parent owns its resume ID, workflow and follow-up across child passes", async () => {
  const h = await harness({ workers: 1, maxDiscoveryRuns: 2 });
  h.input.scanOptions.workflowId = "synthetic-parent-workflow";
  h.input.scanOptions.resumeScanId = h.input.scanId;
  h.input.scanOptions.postScanPrompt = "Review the completed aggregate.";
  h.input.scanOptions.postScanPromptFile = "follow-up.md";
  const transport = new ScanTransportClosedError("synthetic disconnected host");
  h.setRun(async () => {
    throw transport;
  });
  await expect(runDeepScans(h.input)).rejects.toBe(transport);
  h.setRun(async (options) =>
    result(options.resumeScanId!, options.outputDir!),
  );
  await runDeepScans(h.input);
  expect(h.calls).toHaveLength(3);
  expect(h.calls[0]!.resumeScanId).toBeUndefined();
  expect(h.calls[1]!.resumeScanId).toBe([...h.records.keys()][0]);
  expect(h.calls[2]!.resumeScanId).toBeUndefined();
  for (const [index, call] of h.calls.entries()) {
    expect(call.workflowId).toBeUndefined();
    expect(call.postScanPrompt).toBeUndefined();
    expect(call.postScanPromptFile).toBeUndefined();
    expect(call.outputDir).toBe(
      join(
        h.input.scanDir,
        `artifacts/deep-scan/passes/pass-${index === 2 ? 2 : 1}`,
      ),
    );
  }
});

test.each([
  "projection",
  "completion persistence",
  "publication",
  "intermediate publication",
] as const)(
  "retries completed-child %s on resume without rerunning its scan",
  async (phase) => {
    retryDelay = spyOn(timers, "setTimeout").mockImplementation(
      async <T>(_delay?: number, value?: T): Promise<T> => value as T,
    );
    const maxDiscoveryRuns = phase === "intermediate publication" ? 2 : 1;
    const h = await harness({ maxDiscoveryRuns });
    const project = h.input.projectChild;
    const publish = h.input.publish;
    const workbench = h.input.workbench;
    const failure = new Error(`Synthetic ${phase} failure.`);
    if (phase === "projection")
      h.input.projectChild = async () => {
        throw failure;
      };
    else if (phase === "completion persistence")
      h.input.workbench = async (args, contents) => {
        if (
          args[0] === "save-scan-artifact" &&
          args[4] === DEEP_SCAN_CHECKPOINT &&
          [...h.records.values()].some(
            (record) => record.progress.status === "complete",
          )
        )
          throw failure;
        return workbench(args, contents);
      };
    else
      h.input.publish = async () => {
        throw failure;
      };

    await expect(runDeepScans(h.input)).rejects.toThrow(
      phase.includes("publication")
        ? "resume to retry publication"
        : failure.message,
    );
    expect(h.calls).toHaveLength(1);
    expect(
      [...h.records.values()].map((record) => record.progress.status),
    ).toEqual(["complete"]);
    expect((await h.checkpoint()).terminalReason).not.toBe("failed");
    h.input.projectChild = project;
    h.input.publish = publish;
    h.input.workbench = workbench;
    await expect(runDeepScans(h.input)).resolves.toMatchObject({
      terminalReason: "capped",
    });
    expect(h.calls).toHaveLength(maxDiscoveryRuns);
    expect(h.published.at(-1)).toBeDefined();
  },
);

test("does not retry a child after its requested cost limit is exceeded", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({ maxDiscoveryRuns: 2 });
  const cost = estimateScanCost("gpt-6-astra", {
    input_tokens: 100,
    output_tokens: 10,
  })!;
  const failure = new ScanCostLimitExceededError(0, cost, h.input.scanDir);
  h.setRun(async () => {
    throw failure;
  });
  await expect(runDeepScans(h.input)).rejects.toBe(failure);
  expect(h.calls).toHaveLength(1);
  expect((await h.checkpoint()).terminalReason).toBe("capped");
});

test.each(["budget", "accounting"] as const)(
  "does not retry a reducer after a terminal %s failure",
  async (kind) => {
    const h = await harness({ maxDiscoveryRuns: 2 });
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const failure =
      kind === "budget"
        ? new ScanCostLimitExceededError(0, cost, h.input.scanDir)
        : new ScanCostTrackingError(
            "Required reducer usage is missing.",
            h.input.scanDir,
          );
    h.setRun(async (options) =>
      result(options.resumeScanId!, options.outputDir!, "synthetic-finding"),
    );
    let attempts = 0;
    h.input.merge = async () => {
      attempts++;
      throw failure;
    };
    await expect(runDeepScans(h.input)).rejects.toBe(failure);
    expect(attempts).toBe(1);
    expect(h.calls).toHaveLength(2);
    const checkpoint = await h.checkpoint();
    expect(checkpoint.terminalReason).toBe(
      kind === "budget" ? "capped" : "failed",
    );
    expect(checkpoint.mergeFailures ?? 0).toBe(0);
  },
);

test("retains recovered paid usage when retiring a pass after its deadline", async () => {
  const h = await harness({ maxDiscoveryRuns: 1 });
  h.input.scanOptions.requireCost = true;
  const childId = randomUUID();
  const directory = "artifacts/deep-scan/passes/pass-1";
  const recoveredCost = estimateScanCost("gpt-6-astra", {
    input_tokens: 100,
    output_tokens: 10,
  })!;
  h.records.set(childId, {
    scanId: childId,
    scanDir: join(h.input.scanDir, directory),
    parentScanId: h.input.scanId,
    parentScanRole: "deep_pass",
    targetPath: h.input.repository,
    progress: { status: "running" },
    continuationThreadId: "synthetic-paid-thread",
  });
  await h.seed({
    version: 3,
    startedAt: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    passes: [{ directory, scanId: childId }],
    mergedScanIds: [],
    aggregate: null,
    noNewStreak: 0,
    consecutiveErrors: 0,
  });
  h.input.historicalCost = async () => recoveredCost;
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    if (args[0] === "fail-scan") {
      // Match the persisted receipt behavior of workbench fail-scan.
      const costIndex = args.indexOf("--cost-json");
      h.records.get(args[2]!)!.cost =
        costIndex < 0 ? null : JSON.parse(args[costIndex + 1]!);
    }
    return workbench(args, contents);
  };
  const publish = h.input.publish;
  h.input.publish = async () => {
    throw new Error("Synthetic publication interruption.");
  };
  await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
  expect(h.records.get(childId)).toMatchObject({
    progress: { status: "failed" },
    cost: recoveredCost,
  });
  h.input.publish = publish;
  await expect(runDeepScans(h.input)).resolves.toMatchObject({
    terminalReason: "capped",
  });
  expect(h.calls).toEqual([]);
  expect(h.published).toHaveLength(1);
});

test("publishes unresolved pass coverage before a later batch loses transport", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({ workers: 2, maxDiscoveryRuns: 4 });
  const transport = new ScanTransportClosedError(
    "Synthetic interrupted batch.",
  );
  h.setRun(async (options) => {
    if (options.outputDir!.endsWith("pass-1"))
      throw new Error("Synthetic exhausted discovery pass.");
    if (options.outputDir!.endsWith("pass-3")) throw transport;
    return result(options.resumeScanId!, options.outputDir!);
  });
  await expect(runDeepScans(h.input)).rejects.toBe(transport);
  expect(h.published).toHaveLength(1);
  expect(h.published[0]!.coverage.completeness).toBe("partial");
  expect(h.published[0]!.coverage.deferred).toContainEqual({
    reason: "artifacts/deep-scan/passes/pass-1",
  });
  const checkpoint = await h.checkpoint();
  expect(checkpoint.terminalReason).toBeUndefined();
  expect(checkpoint.aggregate!.coverage).toEqual(h.published[0]!.coverage);
});

test("keeps an optional cleanup observer failure out of scan execution", async () => {
  const h = await harness({ maxDiscoveryRuns: 1 });
  h.input.onCleanupError = () => {
    throw new Error("Synthetic observer failure.");
  };
  const createClient = h.input.createClient;
  h.input.createClient = () => ({
    ...createClient(),
    close: async () => {
      throw new Error("Synthetic cleanup failure.");
    },
  });
  await expect(runDeepScans(h.input)).resolves.toMatchObject({
    terminalReason: "capped",
  });
  expect(h.calls).toHaveLength(1);
  expect(h.published.at(-1)).toBeDefined();
});

test.each(
  ["child", "merge"].flatMap((source) =>
    ["optional", "required", "limited"].map((requirement) => ({
      source,
      requirement,
    })),
  ),
)(
  "isolates optional historical cost failures while enforcing requested accounting: %j",
  async ({ source, requirement }) => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    if (requirement === "required") h.input.scanOptions.requireCost = true;
    if (requirement === "limited") h.input.scanOptions.maxCostUsd = 1;
    const failure = async () => {
      throw new Error("Synthetic accounting history failure.");
    };
    if (source === "merge") h.input.onCostsRecovered = failure;
    else {
      const scanId = randomUUID();
      const directory = "artifacts/deep-scan/passes/pass-1";
      h.records.set(scanId, {
        scanId,
        scanDir: join(h.input.scanDir, directory),
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        targetPath: h.input.repository,
        progress: { status: "running" },
        continuationThreadId: "synthetic-thread",
      });
      await h.seed({
        version: 3,
        startedAt: h.input.startedAt,
        passes: [{ directory, scanId }],
        mergedScanIds: [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors: 0,
      });
      h.input.historicalCost = failure;
    }
    if (requirement === "optional") {
      await expect(runDeepScans(h.input)).resolves.toMatchObject({
        terminalReason: "capped",
      });
      expect(h.calls).toHaveLength(1);
    } else {
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanCostTrackingError,
      );
      expect(h.calls).toHaveLength(0);
    }
  },
);

test("replays an unregistered failure after an earlier unobserved completion", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({
    maxDiscoveryRuns: 3,
    stopAfterConsecutiveErrors: 2,
  });
  const directory = "artifacts/deep-scan/passes/pass-1";
  const scanDir = join(h.input.scanDir, directory);
  await mkdir(dirname(scanDir), { recursive: true, mode: 0o700 });
  await cp(example, scanDir, { recursive: true });
  await chmod(scanDir, 0o700);
  const scanId = exampleManifest.scan.id;
  h.records.set(scanId, {
    scanId,
    scanDir,
    parentScanId: h.input.scanId,
    parentScanRole: "deep_pass",
    targetPath: h.input.repository,
    progress: { status: "complete" },
    completedAt: "2026-01-01T00:00:01Z",
  });
  await h.seed({
    version: 3,
    startedAt: h.input.startedAt,
    passes: [
      { directory, scanId },
      {
        directory: "artifacts/deep-scan/passes/pass-2",
        failed: true,
        failedBeforeRegistration: "2026-01-01T00:00:01.500Z",
      },
    ],
    mergedScanIds: [],
    aggregate: null,
    noNewStreak: 0,
    consecutiveErrors: 1,
  });
  h.input.createClient = () => ({
    run: async () => {
      throw new Error("Synthetic registration failure.");
    },
    close: async () => {},
  });
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "consecutive error limit",
  );
  const checkpoint = await h.checkpoint();
  expect(checkpoint.consecutiveErrors).toBe(2);
  expect(checkpoint.passes[2]!.failedBeforeRegistration).toEqual(
    expect.any(String),
  );
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "saved Deep Scan is failed",
  );
  expect((await h.checkpoint()).consecutiveErrors).toBe(2);
});

test("a sibling failure aborts an in-flight projection", async () => {
  const h = await harness({ workers: 2 });
  const failure = new ScanPermissionError("synthetic permission failure");
  let started!: () => void;
  const projecting = new Promise<void>((resolve) => {
    started = resolve;
  });
  let projectionSignal: AbortSignal | undefined;
  h.input.projectChild = async (_id, _directory, signal) => {
    projectionSignal = signal;
    started();
    return new Promise<never>((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      });
    });
  };
  let pass = 0;
  h.setRun(async (options) => {
    if (++pass === 2) {
      await projecting;
      throw failure;
    }
    return result(options.resumeScanId!, options.outputDir!);
  });
  let stopped!: () => void;
  const stopping = new Promise<void>((resolve) => {
    stopped = resolve;
  });
  const workbench = h.input.workbench;
  h.input.workbench = async (args, input) => {
    if (args[0] === "fail-scan") stopped();
    return workbench(args, input);
  };
  const run = runDeepScans(h.input);
  const settled = run.catch((error: unknown) => error);
  try {
    await stopping;
    expect(projectionSignal!.aborted).toBe(true);
    expect(await settled).toBe(failure);
  } finally {
    h.controller.abort(failure);
    await settled;
  }
  expect(projectionSignal!.reason).toBe(failure);
});

test.each(["before recovery", "during recovery"])(
  "a deadline reached %s stops saved passes without executing them",
  async (when) => {
    const h = await harness({ workers: 1, maxDiscoveryRuns: 1 });
    const transport = new ScanTransportClosedError(
      "synthetic disconnected host",
    );
    h.setRun(async () => {
      throw transport;
    });
    await expect(runDeepScans(h.input)).rejects.toBe(transport);
    const checkpoint = await h.checkpoint();
    const now = Date.now();
    checkpoint.startedAt = new Date(
      when === "before recovery" ? now - 2 * 3_600_000 : now,
    ).toISOString();
    await h.seed(checkpoint);
    expect([...h.records.values()][0]!.progress.status).toBe("running");
    const clock = spyOn(Date, "now").mockReturnValue(now);
    const workbench = h.input.workbench;
    let stopped = 0;
    h.input.workbench = async (args, input) => {
      if (args[0] === "list-scans" && when === "during recovery")
        clock.mockReturnValue(now + 2 * 3_600_000);
      if (args[0] === "fail-scan") stopped++;
      return workbench(args, input);
    };
    try {
      const state = await runDeepScans(h.input);
      expect(state.terminalReason).toBe("capped");
      expect([...h.records.values()][0]!.progress.status).toBe("failed");
      expect(h.calls).toHaveLength(1);
      expect(stopped).toBe(1);
      expect(h.published.at(-1)!.coverage!.completeness).toBe("partial");
    } finally {
      clock.mockRestore();
    }
  },
);

test.each(["child", "merge"] as const)(
  "retries %s cost recovery after transport reconnects without terminalizing discovery",
  async (source) => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    h.input.scanOptions.requireCost = true;
    const childId = randomUUID();
    const directory = "artifacts/deep-scan/passes/pass-1";
    const receipt = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    if (source === "child")
      h.records.set(childId, {
        scanId: childId,
        scanDir: join(h.input.scanDir, directory),
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        targetPath: h.input.repository,
        progress: { status: "running" },
        continuationThreadId: "synthetic-paid-thread",
      });
    await h.seed({
      version: 3,
      startedAt: new Date(Date.now() - 2 * 3_600_000).toISOString(),
      passes: source === "child" ? [{ directory, scanId: childId }] : [],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
    });
    const transport = new ScanTransportClosedError(
      "Synthetic cost history transport loss.",
    );
    const fail = async () => {
      throw transport;
    };
    if (source === "child") h.input.historicalCost = fail;
    else h.input.onCostsRecovered = fail;
    await expect(runDeepScans(h.input)).rejects.toBe(transport);
    expect((await h.checkpoint()).terminalReason).toBeUndefined();
    expect(h.published).toEqual([]);
    h.input.historicalCost = async () => receipt;
    h.input.onCostsRecovered = async () => {};
    await expect(runDeepScans(h.input)).resolves.toMatchObject({
      terminalReason: "capped",
    });
    expect(h.calls).toEqual([]);
  },
);

test("counts live completion before a delayed projection and subsequent failures", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({
    workers: 3,
    maxDiscoveryRuns: 3,
    stopAfterConsecutiveErrors: 2,
  });
  const projecting = Promise.withResolvers<void>();
  const firstFailure = Promise.withResolvers<void>();
  const successSaved = Promise.withResolvers<void>();
  const project = h.input.projectChild;
  h.input.projectChild = async (...args) => {
    projecting.resolve();
    await firstFailure.promise;
    return project(...args);
  };
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    const output = await workbench(args, contents);
    if (args[0] === "fail-scan") {
      firstFailure.resolve();
      if (
        [...h.records.values()].some(
          (record) => record.progress.status === "complete",
        )
      )
        successSaved.resolve();
    }
    return output;
  };
  h.setRun(async (options) => {
    if (options.outputDir!.endsWith("pass-1"))
      return result(options.resumeScanId!, options.outputDir!);
    await projecting.promise;
    if (options.outputDir!.endsWith("pass-3")) await successSaved.promise;
    throw new Error("Synthetic exhausted discovery failure.");
  });
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "consecutive error limit",
  );
  expect(await h.checkpoint()).toMatchObject({
    terminalReason: "failed",
    consecutiveErrors: 2,
  });
  expect(h.calls).toHaveLength(3);
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "saved Deep Scan is failed",
  );
  expect(h.calls).toHaveLength(3);
});

test.each(["storage", "transport"] as const)(
  "retries deadline retirement after a %s failure before terminalizing discovery",
  async (kind) => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    const childId = randomUUID();
    const directory = "artifacts/deep-scan/passes/pass-1";
    h.records.set(childId, {
      scanId: childId,
      scanDir: join(h.input.scanDir, directory),
      parentScanId: h.input.scanId,
      parentScanRole: "deep_pass",
      targetPath: h.input.repository,
      progress: { status: "running" },
      continuationThreadId: "synthetic-saved-thread",
    });
    await h.seed({
      version: 3,
      startedAt: new Date(Date.now() - 2 * 3_600_000).toISOString(),
      passes: [{ directory, scanId: childId }],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
    });
    const failure =
      kind === "transport"
        ? new ScanTransportClosedError("Synthetic retirement transport loss.")
        : new Error("Synthetic retirement persistence failure.");
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (args[0] === "fail-scan") throw failure;
      return workbench(args, contents);
    };
    if (kind === "transport")
      await expect(runDeepScans(h.input)).rejects.toBe(failure);
    else await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
    expect((await h.checkpoint()).terminalReason).toBeUndefined();
    expect(h.records.get(childId)!.progress.status).toBe("running");
    expect(h.published).toEqual([]);
    h.input.workbench = workbench;
    await expect(runDeepScans(h.input)).resolves.toMatchObject({
      terminalReason: "capped",
    });
    expect(h.records.get(childId)!.progress.status).toBe("failed");
    expect(h.calls).toEqual([]);
  },
);

test.each([
  ["2026-01-01T00:00:00.000900Z", "2026-01-01T00:00:00.000100Z"],
  ["2026-01-01T00:00:00.000100Z", "2026-01-01T00:00:00.000Z"],
  ["2026-01-01T00:00:00.000100Z", "2026-01-01T00:00:00Z"],
])(
  "replays submillisecond completion %s after failure %s",
  async (successTime, failureTime) => {
    const h = await harness({
      maxDiscoveryRuns: 2,
      stopAfterConsecutiveErrors: 1,
    });
    const successId = exampleManifest.scan.id;
    const failureId = randomUUID();
    const directory = "artifacts/deep-scan/passes/pass-1";
    const scanDir = join(h.input.scanDir, directory);
    await mkdir(dirname(scanDir), { recursive: true, mode: 0o700 });
    await cp(example, scanDir, { recursive: true });
    await chmod(scanDir, 0o700);
    for (const [scanId, status, completedAt, scanDirectory] of [
      [successId, "complete", successTime, scanDir],
      [
        failureId,
        "failed",
        failureTime,
        join(h.input.scanDir, "artifacts/deep-scan/passes/pass-2"),
      ],
    ] as const)
      h.records.set(scanId, {
        scanId,
        scanDir: scanDirectory,
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        targetPath: h.input.repository,
        progress: { status },
        completedAt,
      });
    await h.seed({
      version: 3,
      startedAt: h.input.startedAt,
      passes: [
        { directory, scanId: successId, completed: true },
        { directory: "artifacts/deep-scan/passes/pass-2", scanId: failureId },
      ],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
    });
    for (let resume = 0; resume < 2; resume++) {
      expect(await runDeepScans(h.input)).toMatchObject({
        terminalReason: "capped",
        consecutiveErrors: 0,
      });
    }
    expect(h.calls).toEqual([]);
  },
);

test.each(
  (["budget", "cancel", "permission", "policy", "accounting"] as const).flatMap(
    (stop) =>
      (["storage", "transport"] as const).map(
        (failure) => [stop, failure] as const,
      ),
  ),
)(
  "retries concurrent retirement after %s abort and %s failure",
  async (stopKind, failureKind) => {
    const h = await harness({ workers: 2, maxDiscoveryRuns: 4 });
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const stop =
      stopKind === "budget"
        ? new ScanCostLimitExceededError(0, cost, h.input.scanDir)
        : stopKind === "permission"
          ? new ScanPermissionError("Synthetic permission failure.")
          : stopKind === "accounting"
            ? new ScanCostTrackingError(
                "Synthetic missing usage.",
                h.input.scanDir,
              )
            : stopKind === "policy"
              ? new Error("Request rejected: cyber_policy.")
              : new Error("Synthetic cancellation.");
    const terminalReason =
      stopKind === "budget"
        ? "capped"
        : stopKind === "cancel"
          ? "canceled"
          : "failed";
    const failure =
      failureKind === "transport"
        ? new ScanTransportClosedError("Synthetic retirement transport loss.")
        : new Error("Synthetic retirement persistence failure.");
    let started = 0;
    let release!: () => void;
    const bothStarted = new Promise<void>((resolve) => {
      release = resolve;
    });
    h.setRun(async (options) => {
      if (++started === 2) release();
      await bothStarted;
      options.onCost?.(cost);
      if (stopKind === "cancel") h.controller.abort(stop);
      throw stop;
    });
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (
        args[0] === "fail-scan" &&
        h.records.get(args[2]!)?.scanDir.endsWith("pass-2")
      )
        throw failure;
      return workbench(args, contents);
    };
    if (failureKind === "transport")
      await expect(runDeepScans(h.input)).rejects.toBe(failure);
    else await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
    expect((await h.checkpoint()).terminalReason).toBeUndefined();
    const interruptedChild = [...h.records.values()].find((record) =>
      record.scanDir.endsWith("pass-2"),
    )!;
    expect(interruptedChild.progress.status).toBe("running");
    expect(h.published).toEqual([]);

    expect(await h.checkpoint()).toMatchObject({
      pendingStop: { reason: terminalReason, message: stop.message },
    });
    h.input.signal = new AbortController().signal;
    if (failureKind === "transport")
      await expect(runDeepScans(h.input)).rejects.toBe(failure);
    else await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
    expect(h.calls).toHaveLength(2);
    expect((await h.checkpoint()).pendingStop).toBeDefined();
    h.input.workbench = workbench;
    h.setRun(async () => {
      throw new Error("A stopped scan must not execute discovery.");
    });
    h.input.onCost = () => {
      expect(
        [...h.records.values()].every(
          (record) => record.progress.status !== "running",
        ),
      ).toBe(true);
    };
    h.input.onCostsRecovered = async () => {
      expect(
        [...h.records.values()].every(
          (record) => record.progress.status !== "running",
        ),
      ).toBe(true);
    };
    if (terminalReason === "capped")
      await expect(runDeepScans(h.input)).resolves.toMatchObject({
        terminalReason,
      });
    else
      await expect(runDeepScans(h.input)).rejects.toThrow(
        `saved Deep Scan is ${terminalReason}`,
      );
    expect(h.records.get(interruptedChild.scanId)!.progress.status).toBe(
      "failed",
    );
    expect(h.records.get(interruptedChild.scanId)!.cost).toEqual(cost);
    expect((await h.checkpoint()).terminalReason).toBe(terminalReason);
    expect((await h.checkpoint())["pendingStop"]).toBeUndefined();
    expect(h.calls).toHaveLength(2);
  },
);

test.each(["permission", "policy", "accounting", "budget"] as const)(
  "retains a terminal %s decision after a later host disconnect",
  async (kind) => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const failure =
      kind === "permission"
        ? new ScanPermissionError("Synthetic required permission failure.")
        : kind === "accounting"
          ? new ScanCostTrackingError(
              "Required usage unavailable.",
              h.input.scanDir,
            )
          : kind === "budget"
            ? new ScanCostLimitExceededError(0, cost, h.input.scanDir)
            : await codexStreamError(
                JSON.stringify({
                  type: "turn.failed",
                  error: { message: "Request rejected: cyber_policy." },
                }),
              );
    h.setRun(async () => {
      throw failure;
    });
    const createClient = h.input.createClient;
    h.input.createClient = () => {
      const client = createClient();
      return {
        ...client,
        async close() {
          await client.close();
          h.controller.abort(
            new ScanTransportClosedError("Synthetic host disconnect."),
          );
        },
      };
    };
    await expect(runDeepScans(h.input)).rejects.toBe(failure);
    expect((await h.checkpoint()).terminalReason).toBe(
      kind === "budget" ? "capped" : "failed",
    );
    expect([...h.records.values()][0]!.progress.status).toBe("failed");
    expect(h.mergeInputs).toEqual([]);

    h.input.signal = new AbortController().signal;
    if (kind === "budget")
      await expect(runDeepScans(h.input)).resolves.toMatchObject({
        terminalReason: "capped",
      });
    else
      await expect(runDeepScans(h.input)).rejects.toThrow(
        "saved Deep Scan is failed",
      );
    expect(h.calls).toHaveLength(1);
  },
);

test.each(["accounting", "budget", "cancel"] as const)(
  "does not retire a completed child after a final %s stop",
  async (kind) => {
    const h = await harness({ maxDiscoveryRuns: 4 });
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const stop =
      kind === "budget"
        ? new ScanCostLimitExceededError(0, cost, h.input.scanDir)
        : kind === "accounting"
          ? new ScanCostTrackingError(
              "Synthetic required usage failure.",
              h.input.scanDir,
            )
          : new Error("Synthetic cancellation after child completion.");
    const project = h.input.projectChild;
    h.input.projectChild = async (...args) => {
      const draft = await project(...args);
      if (kind === "cancel") h.controller.abort(stop);
      return draft;
    };
    if (kind !== "cancel")
      h.input.onCost = () => {
        if (
          [...h.records.values()].some(
            (record) => record.progress.status === "complete",
          )
        )
          throw stop;
      };
    const retired: string[] = [];
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (args[0] === "fail-scan") retired.push(args[2]!);
      return workbench(args, contents);
    };
    await expect(runDeepScans(h.input)).rejects.toBe(stop);
    expect(retired).toEqual([]);
    expect(
      [...h.records.values()].map((record) => record.progress.status),
    ).toEqual(["complete"]);
    expect(h.calls).toHaveLength(1);
    expect((await h.checkpoint()).terminalReason).toBe(
      kind === "budget" ? "capped" : kind === "cancel" ? "canceled" : "failed",
    );
  },
);

test("retries the final retirement checkpoint without rerunning children", async () => {
  const h = await harness({ maxDiscoveryRuns: 4 });
  const stop = new Error("Synthetic cancellation.");
  h.setRun(async () => {
    h.controller.abort(stop);
    throw stop;
  });
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    if (
      args[0] === "save-scan-artifact" &&
      JSON.parse(contents!).terminalReason === "canceled"
    )
      throw new Error("Synthetic terminal checkpoint write failure.");
    return workbench(args, contents);
  };
  await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
  expect((await h.checkpoint()).pendingStop?.reason).toBe("canceled");
  expect(
    [...h.records.values()].map((record) => record.progress.status),
  ).toEqual(["failed"]);
  h.input.signal = new AbortController().signal;
  h.input.workbench = workbench;
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "saved Deep Scan is canceled",
  );
  expect(h.calls).toHaveLength(1);
  expect((await h.checkpoint()).pendingStop).toBeUndefined();
});

test("keeps deadline retirement capped when transport closes after the deadline", async () => {
  const h = await harness({ maxDiscoveryRuns: 1 });
  const childId = randomUUID();
  const directory = "artifacts/deep-scan/passes/pass-1";
  h.records.set(childId, {
    scanId: childId,
    scanDir: join(h.input.scanDir, directory),
    parentScanId: h.input.scanId,
    parentScanRole: "deep_pass",
    targetPath: h.input.repository,
    progress: { status: "running" },
    continuationThreadId: "synthetic-saved-thread",
  });
  await h.seed({
    version: 3,
    startedAt: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    passes: [{ directory, scanId: childId }],
    mergedScanIds: [],
    aggregate: null,
    noNewStreak: 0,
    consecutiveErrors: 0,
  });
  const transport = new ScanTransportClosedError(
    "Synthetic late transport closure.",
  );
  const createClient = h.input.createClient;
  h.input.createClient = () => {
    h.controller.abort(transport);
    return createClient();
  };
  await expect(runDeepScans(h.input)).rejects.toBe(transport);
  expect((await h.checkpoint()).terminalReason).toBe("capped");
  h.input.signal = new AbortController().signal;
  await expect(runDeepScans(h.input)).resolves.toMatchObject({
    terminalReason: "capped",
  });
  expect(h.calls).toEqual([]);
  expect(h.records.get(childId)!.progress.status).toBe("failed");
});

test.each(
  (["budget", "accounting"] as const).flatMap((kind) =>
    [false, true].map((interruptRetirement) => ({ kind, interruptRetirement })),
  ),
)(
  "retires restored children after recovery stops: %j",
  async ({ kind, interruptRetirement }) => {
    const h = await harness({ workers: 2, maxDiscoveryRuns: 2 });
    h.input.scanOptions.requireCost = true;
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const stop =
      kind === "budget"
        ? new ScanCostLimitExceededError(0, cost, h.input.scanDir)
        : new ScanCostTrackingError(
            "Synthetic recovery accounting failure.",
            h.input.scanDir,
          );
    const passes = [1, 2].map((index) => ({
      directory: `artifacts/deep-scan/passes/pass-${index}`,
      scanId: randomUUID(),
    }));
    for (const [index, pass] of passes.entries()) {
      h.records.set(pass.scanId, {
        scanId: pass.scanId,
        scanDir: join(h.input.scanDir, pass.directory),
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        targetPath: h.input.repository,
        progress: { status: "running" },
        continuationThreadId: `synthetic-recovery-thread-${index}`,
      });
    }
    await h.seed({
      version: 3,
      startedAt: h.input.startedAt,
      passes,
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
    });
    h.input.historicalCost = async (thread) => {
      if (kind === "accounting" && thread.endsWith("-1")) throw stop;
      return cost;
    };
    h.input.onCost = (_key, receipt) => {
      if (kind === "budget" && receipt !== null) throw stop;
    };
    const workbench = h.input.workbench;
    let interrupted = false;
    h.input.workbench = async (args, contents) => {
      if (args[0] === "fail-scan") {
        expect((await h.checkpoint()).pendingStop).toBeDefined();
        if (interruptRetirement && !interrupted) {
          interrupted = true;
          throw new Error("Synthetic retirement storage failure.");
        }
      }
      return workbench(args, contents);
    };
    const terminalReason = kind === "budget" ? "capped" : "failed";
    if (interruptRetirement) {
      await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
      expect((await h.checkpoint()).pendingStop?.reason).toBe(terminalReason);
      expect((await h.checkpoint()).terminalReason).toBeUndefined();
      h.input.onCost = () => {
        expect(
          [...h.records.values()].every(
            (record) => record.progress.status === "failed",
          ),
        ).toBe(true);
      };
      h.input.historicalCost = async () => {
        throw new Error(
          "Stopped children must be retired before cost recovery.",
        );
      };
      if (kind === "budget")
        await expect(runDeepScans(h.input)).resolves.toMatchObject({
          terminalReason,
        });
      else
        await expect(runDeepScans(h.input)).rejects.toThrow(
          "saved Deep Scan is failed",
        );
    } else {
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        kind === "budget" ? ScanCostLimitExceededError : ScanCostTrackingError,
      );
    }
    expect(h.calls).toEqual([]);
    expect(
      [...h.records.values()].map((record) => record.progress.status),
    ).toEqual(["failed", "failed"]);
    expect(h.records.get(passes[0]!.scanId)!.cost).toEqual(cost);
    expect(h.records.get(passes[1]!.scanId)!.cost).toEqual(
      kind === "budget" ? cost : null,
    );
    expect((await h.checkpoint()).terminalReason).toBe(terminalReason);
    expect((await h.checkpoint()).pendingStop).toBeUndefined();
  },
);

test.each(["canceled", "failed"] as const)(
  "preserves an authoritative workbench %s stop without rewriting frozen artifacts",
  async (status) => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    const schedule = globalThis.setInterval;
    let poll: (() => void) | undefined;
    const timer = spyOn(globalThis, "setInterval").mockImplementation(((
      ...args: Parameters<typeof schedule>
    ) => {
      const [callback, milliseconds, ...parameters] = args;
      if (milliseconds === 1_000) poll = () => callback(...parameters);
      return schedule(...args);
    }) as typeof schedule);
    let parentStopped = false;
    let writesAfterStop = 0;
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (parentStopped) {
        if (args[0] === "get-scan") return { scan: { progress: { status } } };
        if (args[0] === "save-scan-artifact" || args[0] === "fail-scan") {
          writesAfterStop++;
          throw new Error("A stopped parent cannot accept scan artifacts.");
        }
      }
      return workbench(args, contents);
    };
    h.setRun(async (options) => {
      parentStopped = true;
      // Workbench cancellation already stops registered children before polling.
      for (const record of h.records.values()) record.progress.status = status;
      expect(poll).toBeDefined();
      poll!();
      return await abortable(
        () => new Promise<ScanResult>(() => {}),
        options.signal!,
      );
    });
    try {
      await expect(runDeepScans(h.input)).rejects.toThrow(
        "The saved parent scan stopped.",
      );
      expect(writesAfterStop).toBe(0);
      expect(h.calls).toHaveLength(1);
      expect(h.metrics().closed).toBe(1);
      expect(h.published).toEqual([]);
    } finally {
      timer.mockRestore();
    }
  },
);

test.each([
  "permission",
  "policy",
  "accounting",
  "cancel",
  "transient",
  "exhausted",
])(
  "a capped discovery retains the subsequent %s reducer outcome",
  async (kind) => {
    const h = await harness({ maxDiscoveryRuns: 2 });
    h.setRun(async (options) =>
      result(options.resumeScanId!, options.outputDir!, "saved-finding"),
    );
    const merge = h.input.merge;
    const transport = new ScanTransportClosedError(
      "Synthetic interrupted merge.",
    );
    h.input.merge = async () => {
      throw transport;
    };
    await expect(runDeepScans(h.input)).rejects.toBe(transport);
    const checkpoint = await h.checkpoint();
    await h.seed({ ...checkpoint, terminalReason: "capped" });
    const failure =
      kind === "permission"
        ? new ScanPermissionError("Synthetic reducer permission failure.")
        : kind === "policy"
          ? new Error("cyber_policy")
          : kind === "accounting"
            ? new ScanCostTrackingError(
                "Synthetic missing required reducer receipt.",
                h.input.scanDir,
              )
            : new Error(`Synthetic ${kind} reducer stop.`);
    let attempts = 0;
    h.input.merge = async (...args) => {
      attempts++;
      if (kind === "transient" && attempts > 1) return merge(...args);
      if (kind === "cancel") h.controller.abort(failure);
      throw failure;
    };
    if (kind === "transient") {
      await expect(runDeepScans(h.input)).resolves.toMatchObject({
        terminalReason: "capped",
      });
      expect(attempts).toBe(2);
      expect(h.published.at(-1)!.findings).toHaveLength(2);
    } else {
      await expect(runDeepScans(h.input)).rejects.toBe(failure);
      const reason = kind === "cancel" ? "canceled" : "failed";
      expect((await h.checkpoint()).terminalReason).toBe(reason);
      h.input.signal = new AbortController().signal;
      await expect(runDeepScans(h.input)).rejects.toThrow(
        `saved Deep Scan is ${reason}`,
      );
      expect(attempts).toBe(kind === "exhausted" ? 3 : 1);
    }
    expect(h.calls).toHaveLength(2);
    expect([...h.records.values()].map((row) => row.progress.status)).toEqual([
      "complete",
      "complete",
    ]);
  },
);

test("a deadline retains child completion committed before its response", async () => {
  const h = await harness({ maxDiscoveryRuns: 1 });
  h.setRun(async (options) =>
    result(options.resumeScanId!, options.outputDir!, "committed-finding"),
  );
  const now = Date.parse(h.input.startedAt);
  const clock = spyOn(Date, "now").mockReturnValue(now);
  const schedule = globalThis.setTimeout;
  let expire: (() => void) | undefined;
  const timer = spyOn(globalThis, "setTimeout").mockImplementation(((
    ...args: Parameters<typeof schedule>
  ) => {
    const [callback, milliseconds, ...parameters] = args;
    if (milliseconds === 3_600_000) expire = () => callback(...parameters);
    return schedule(...args);
  }) as typeof schedule);
  const createClient = h.input.createClient;
  h.input.createClient = () => {
    const client = createClient();
    return {
      ...client,
      async run(...args) {
        await client.run(...args);
        clock.mockReturnValue(now + 3_600_000);
        expect(expire).toBeDefined();
        expire!();
        throw args[1]!.signal!.reason;
      },
    };
  };
  const retired: string[] = [];
  const workbench = h.input.workbench;
  h.input.workbench = async (args, input) => {
    if (args[0] === "fail-scan") retired.push(args[2]!);
    return workbench(args, input);
  };
  try {
    await expect(runDeepScans(h.input)).resolves.toMatchObject({
      terminalReason: "capped",
    });
    expect(h.calls).toHaveLength(1);
    expect(retired).toEqual([]);
    expect(h.published.at(-1)!.findings).toHaveLength(1);
    expect([...h.records.values()].map((row) => row.progress.status)).toEqual([
      "complete",
    ]);
  } finally {
    clock.mockRestore();
    timer.mockRestore();
  }
});

test("recovers committed child completion after a plain response failure", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({
    maxDiscoveryRuns: 1,
    stopAfterConsecutiveErrors: 1,
  });
  h.setRun(async (options) =>
    result(options.resumeScanId!, options.outputDir!, "committed-finding"),
  );
  const createClient = h.input.createClient;
  let requests = 0;
  h.input.createClient = () => {
    const client = createClient();
    return {
      ...client,
      async run(...args) {
        requests++;
        const id = args[1]?.resumeScanId;
        if (id && h.records.get(id)?.progress.status === "complete")
          throw new Error("Completed scans cannot resume.");
        await client.run(...args);
        throw new Error("Synthetic completion response failure.");
      },
    };
  };
  await expect(runDeepScans(h.input)).resolves.toMatchObject({
    terminalReason: "capped",
    consecutiveErrors: 0,
  });
  expect(requests).toBe(1);
  expect(h.calls).toHaveLength(1);
  expect(h.published.at(-1)!.findings).toHaveLength(1);
  expect([...h.records.values()].map((row) => row.progress.status)).toEqual([
    "complete",
  ]);
  await runDeepScans(h.input);
  expect(requests).toBe(1);
});

test("keeps failed retry retirement pending when its sibling later reaches the deadline", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({ workers: 2, maxDiscoveryRuns: 2 });
  const now = Date.parse(h.input.startedAt);
  const clock = spyOn(Date, "now").mockReturnValue(now);
  const schedule = globalThis.setTimeout;
  let expire: (() => void) | undefined;
  const timer = spyOn(globalThis, "setTimeout").mockImplementation(((
    ...args: Parameters<typeof schedule>
  ) => {
    const [callback, milliseconds, ...parameters] = args;
    if (milliseconds === 3_600_000) expire = () => callback(...parameters);
    return schedule(...args);
  }) as typeof schedule);
  const retiredAttempt = Promise.withResolvers<void>();
  const createClient = h.input.createClient;
  h.input.createClient = () => {
    const client = createClient();
    let first = false;
    return {
      async run(...args) {
        first = args[1]!.outputDir!.endsWith("pass-1");
        return client.run(...args);
      },
      async close() {
        await client.close();
        if (first) retiredAttempt.resolve();
      },
    };
  };
  h.setRun(async (options) => {
    if (options.outputDir!.endsWith("pass-1"))
      throw new Error("Synthetic exhausted child.");
    await retiredAttempt.promise;
    clock.mockReturnValue(now + 3_600_000);
    expire!();
    throw options.signal!.reason;
  });
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    if (
      args[0] === "fail-scan" &&
      h.records.get(args[2]!)!.scanDir.endsWith("pass-1")
    )
      throw new Error("Synthetic retirement storage failure.");
    return workbench(args, contents);
  };
  try {
    await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
    expect((await h.checkpoint()).pendingStop?.reason).toBe("capped");
    expect((await h.checkpoint()).terminalReason).toBeUndefined();
    expect([...h.records.values()].map((row) => row.progress.status)).toEqual([
      "running",
      "failed",
    ]);
    const calls = h.calls.length;
    h.input.workbench = workbench;
    await expect(runDeepScans(h.input)).resolves.toMatchObject({
      terminalReason: "capped",
    });
    expect([...h.records.values()].map((row) => row.progress.status)).toEqual([
      "failed",
      "failed",
    ]);
    expect((await h.checkpoint()).pendingStop).toBeUndefined();
    expect(h.calls).toHaveLength(calls);
  } finally {
    clock.mockRestore();
    timer.mockRestore();
  }
});

test.each([false, true])(
  "persists cancellation during publication after discovery saturates (throws: %p)",
  async (throws) => {
    const h = await harness({ stopAfterNoNew: 1 });
    const failure = new Error("Synthetic final publication cancellation.");
    const publish = h.input.publish;
    h.input.publish = async (draft) => {
      if ((await h.checkpoint()).terminalReason === "saturated") {
        h.controller.abort(failure);
        if (throws) throw failure;
      }
      return publish(draft);
    };
    await expect(runDeepScans(h.input)).rejects.toBe(failure);
    expect((await h.checkpoint()).terminalReason).toBe("canceled");
    const calls = h.calls.length;
    h.input.signal = new AbortController().signal;
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "saved Deep Scan is canceled",
    );
    expect(h.calls).toHaveLength(calls);
  },
);

test("a saved capped result rejects when recovered accounting aborts its budget", async () => {
  const h = await harness({ maxDiscoveryRuns: 1 });
  await runDeepScans(h.input);
  const calls = h.calls.length;
  const cost = estimateScanCost("gpt-6-astra", {
    input_tokens: 100,
    output_tokens: 10,
  })!;
  const failure = new ScanCostLimitExceededError(0, cost, h.input.scanDir);
  h.input.onCost = () => h.controller.abort(failure);
  await expect(runDeepScans(h.input)).rejects.toBe(failure);
  expect((await h.checkpoint()).terminalReason).toBe("capped");
  expect(h.calls).toHaveLength(calls);
});

test("retirement transport closes sibling execution before client cleanup completes", async () => {
  retryDelay = spyOn(timers, "setTimeout").mockImplementation(
    async <T>(_delay?: number, value?: T): Promise<T> => value as T,
  );
  const h = await harness({ workers: 2, maxDiscoveryRuns: 2 });
  const transport = new ScanTransportClosedError(
    "Synthetic retirement transport loss.",
  );
  const firstClosed = Promise.withResolvers<void>();
  const createClient = h.input.createClient;
  h.input.createClient = () => {
    const client = createClient();
    let first = false;
    return {
      async run(...args) {
        first = args[1]!.outputDir!.endsWith("pass-1");
        return client.run(...args);
      },
      async close() {
        await client.close();
        if (first) firstClosed.resolve();
      },
    };
  };
  let siblingAbortedBeforeCleanup: boolean | undefined;
  h.setRun(async (options) => {
    if (options.outputDir!.endsWith("pass-1"))
      throw new Error("Synthetic child execution failure.");
    await firstClosed.promise;
    siblingAbortedBeforeCleanup = options.signal!.aborted;
    if (!options.signal!.aborted) h.controller.abort(transport);
    options.signal!.throwIfAborted();
    throw new Error("Expected child cancellation.");
  });
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    if (
      args[0] === "fail-scan" &&
      h.records.get(args[2]!)!.scanDir.endsWith("pass-1")
    )
      throw transport;
    return workbench(args, contents);
  };
  await expect(runDeepScans(h.input)).rejects.toBe(transport);
  expect(siblingAbortedBeforeCleanup).toBe(true);
  expect(h.metrics().closed).toBe(2);
  expect((await h.checkpoint()).terminalReason).toBeUndefined();
  expect([...h.records.values()].map((row) => row.progress.status)).toEqual([
    "running",
    "running",
  ]);
});

test.each(
  ([null, undefined, "deep_pass"] as const).flatMap((parentScanRole) =>
    [false, true].flatMap((registered) =>
      [false, true].map((pendingStop) => ({
        parentScanRole,
        registered,
        pendingStop,
      })),
    ),
  ),
)(
  "admits only assigned Deep children in saved reservations: %j",
  async ({ parentScanRole, registered, pendingStop }) => {
    const h = await harness({ workers: 1, maxDiscoveryRuns: 1 });
    await runDeepScans(h.input);
    const child = [...h.records.values()][0]!;
    if (parentScanRole === undefined) delete child.parentScanRole;
    else child.parentScanRole = parentScanRole;
    if (pendingStop) child.progress.status = "running";
    const childBefore = structuredClone(child);
    const ordinary = {
      scanId: randomUUID(),
      scanDir: join(h.input.scanDir, "ordinary-rerun"),
      parentScanId: h.input.scanId,
      parentScanRole: null,
      targetPath: h.input.repository,
      progress: { status: "running" },
    };
    h.records.set(ordinary.scanId, ordinary);
    const ordinaryBefore = structuredClone(ordinary);
    const previous = await h.checkpoint();
    await h.seed({
      version: 3,
      startedAt: h.input.startedAt,
      passes: [
        {
          directory: previous.passes[0]!.directory,
          ...(registered ? { scanId: child.scanId } : {}),
        },
      ],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
      ...(pendingStop
        ? {
            pendingStop: {
              reason: "failed" as const,
              message: "Synthetic saved stop.",
              costs: {},
            },
          }
        : {}),
    });
    h.calls.length = 0;
    h.published.length = 0;
    const projected: string[] = [];
    const accounted: string[] = [];
    const project = h.input.projectChild;
    h.input.projectChild = async (...args) => {
      projected.push(args[0]);
      return project(...args);
    };
    h.input.onCost = (key) => {
      accounted.push(key);
    };
    if (parentScanRole !== "deep_pass") {
      await expect(runDeepScans(h.input)).rejects.toThrow(
        "not an assigned Deep Scan pass",
      );
      expect(child).toEqual(childBefore);
      expect(projected).toEqual([]);
      expect(accounted).toEqual([]);
      expect(h.published).toEqual([]);
      const retained = await h.checkpoint();
      expect(retained.mergedScanIds).toEqual([]);
      expect(retained.passes[0]!.scanId).toBe(
        registered ? child.scanId : undefined,
      );
      expect(retained.pendingStop?.reason).toBe("failed");
    } else if (pendingStop) {
      await expect(runDeepScans(h.input)).rejects.toThrow(
        "saved Deep Scan is failed",
      );
      expect(child.progress.status).toBe("failed");
      expect(child.parentScanRole).toBe("deep_pass");
      expect((await h.checkpoint()).pendingStop).toBeUndefined();
    } else {
      const resumed = await runDeepScans(h.input);
      expect(resumed.mergedScanIds).toEqual([child.scanId]);
      expect(projected).toEqual([child.scanId]);
      expect(h.published.at(-1)).toBeDefined();
      expect(child).toEqual(childBefore);
    }
    expect(h.calls).toEqual([]);
    expect(ordinary).toEqual(ordinaryBefore);
  },
);
