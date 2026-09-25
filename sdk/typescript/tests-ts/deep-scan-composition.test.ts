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
import { afterEach, beforeAll, describe, expect, spyOn, test } from "bun:test";
import type { ScanOptions } from "../src/api.js";
import { estimateScanCost, type ScanCost } from "../src/cost.js";
import type { JsonObject as WorkbenchJsonObject } from "../src/config.js";
import {
  runDeepScans,
  ScanCostTrackingError,
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
  type DeepScanComposition,
} from "../src/deep-scan.js";
import { ScanResult } from "../src/result.js";
import { abortable } from "../src/targets.js";
import {
  ScanPermissionError,
  ScanTransportClosedError,
} from "../src/scan-execution.js";
import {
  scanFindingIdentity,
  type JsonObject,
  type SemanticScan,
} from "../src/scan-semantics.js";
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

interface SavedRecord {
  scanId: string;
  scanDir: string;
  parentScanId: string;
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
          scanId: id,
          scanDir: options.outputDir!,
          parentScanId: scanId,
          targetPath: repository,
          progress: { status: "running" },
        });
        await mkdir(options.outputDir!, { recursive: true, mode: 0o700 });
        await options.onRegisteredScan?.({
          scanId: id,
          scanDir: options.outputDir!,
        });
        try {
          const completed = await run({ ...options, resumeScanId: id });
          records.get(id)!.progress.status = "complete";
          return completed;
        } finally {
          active -= 1;
        }
      },
      async close() {
        closed += 1;
      },
    }),
    async workbench(args, contents) {
      if (args[0] === "save-scan-artifact") {
        const state = JSON.parse(contents!) as DeepScanCheckpoint;
        checkpoints.push(state);
        const path = join(scanDir, DEEP_SCAN_CHECKPOINT);
        await mkdir(dirname(path), { recursive: true });
        const temporary = `${path}.${randomUUID()}.tmp`;
        await writeFile(temporary, contents!);
        await rename(temporary, path);
        return {};
      }
      if (args[0] === "list-scans")
        return {
          scans: [...records.values()],
        } as unknown as WorkbenchJsonObject;
      if (args[0] === "get-scan")
        return { scan: { progress: { status: "running" } } };
      if (args[0] === "fail-scan") {
        if (args[4]!.length > 2400)
          throw new Error("Text value must be no longer than 2400 characters.");
        records.get(args[2]!)!.progress.status = "failed";
        return {};
      }
      throw new Error(`Unexpected workbench operation ${args[0]}`);
    },
    async merge(prompt) {
      const path = join(scanDir, "artifacts/deep-scan/merge-inputs.json");
      expect(prompt).toContain(JSON.stringify(path));
      const payload = JSON.parse(await readFile(path, "utf8")) as {
        scans: SemanticScan[];
        previous: SemanticScan | null;
      };
      mergeInputs.push(payload.scans.length);
      const findings = structuredClone(payload.previous?.findings ?? []);
      for (const source of payload.scans.flatMap((scan) => scan.findings)) {
        const existing = findings.find(
          (finding) =>
            scanFindingIdentity(finding) === scanFindingIdentity(source),
        );
        if (!existing) findings.push(source);
        else
          (existing["provenance"] as JsonObject)["sourceFindingIds"] = [
            ...((existing["provenance"] as JsonObject)[
              "sourceFindingIds"
            ] as string[]),
            ...((source["provenance"] as JsonObject)[
              "sourceFindingIds"
            ] as string[]),
          ];
      }
      return { scanId, findings };
    },
    writer: {
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
    checkpoint: async () =>
      JSON.parse(
        await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
      ) as DeepScanCheckpoint,
    async seed(state: DeepScanCheckpoint) {
      const path = join(scanDir, DEEP_SCAN_CHECKPOINT);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify(state));
    },
  };
}

describe("ordinary scan composition", () => {
  test("serializes concurrent child checkpoint writes", async () => {
    const h = await harness({ workers: 2, stopAfterNoNew: 2 });
    const registrationsReady = Promise.withResolvers<void>();
    const releaseWrite = Promise.withResolvers<void>();
    let registrations = 0;
    const createClient = h.input.createClient;
    h.input.createClient = () => {
      const client = createClient();
      return {
        ...client,
        run(repository, options = {}) {
          return client.run(repository, {
            ...options,
            async onRegisteredScan(registration) {
              const pending = options.onRegisteredScan?.(registration);
              if (++registrations === 2) registrationsReady.resolve();
              return pending;
            },
          });
        },
      };
    };
    const workbench = h.input.workbench;
    let writing = 0;
    let maximumWriting = 0;
    h.input.workbench = async (args, contents) => {
      if (args[0] !== "save-scan-artifact") return workbench(args, contents);
      writing += 1;
      maximumWriting = Math.max(maximumWriting, writing);
      try {
        const state = JSON.parse(contents!) as DeepScanCheckpoint;
        if (state.passes.some((pass) => pass.scanId))
          await releaseWrite.promise;
        return await workbench(args, contents);
      } finally {
        writing -= 1;
      }
    };
    const execution = runDeepScans(h.input);
    try {
      await Promise.race([registrationsReady.promise, execution]);
    } finally {
      releaseWrite.resolve();
    }
    await execution;
    expect(maximumWriting).toBe(1);
    const state = await h.checkpoint();
    expect(state.mergedScanIds).toHaveLength(2);
    expect(state.terminalReason).toBe("saturated");
  });

  test("preserves a checkpoint write failure and still saves terminal state", async () => {
    const h = await harness({ stopAfterNoNew: 1 });
    const workbench = h.input.workbench;
    const failure = new Error("Synthetic checkpoint write failure.");
    let rejected = false;
    h.input.workbench = async (args, contents) => {
      if (
        args[0] === "save-scan-artifact" &&
        JSON.parse(contents!).mergedScanIds.length > 0 &&
        !rejected
      ) {
        rejected = true;
        throw failure;
      }
      return workbench(args, contents);
    };
    await expect(runDeepScans(h.input)).rejects.toBe(failure);
    expect((await h.checkpoint()).terminalReason).toBe("failed");
  });

  test("runs fixed bounded batches and counts every successfully merged clean input", async () => {
    const h = await harness({ workers: 2, stopAfterNoNew: 4 });
    await runDeepScans(h.input);
    const state = await h.checkpoint();
    expect(h.calls).toHaveLength(4);
    expect(h.metrics()).toEqual({ closed: 4, maximumActive: 2 });
    expect(h.mergeInputs).toEqual([2, 2]);
    expect(state.noNewStreak).toBe(4);
    expect(state.terminalReason).toBe("saturated");
    expect(new Set(h.published.map((draft) => draft.scanId))).toEqual(
      new Set([h.input.scanId]),
    );
    expect(h.published.at(-1)).toEqual(state.aggregate!);
    expect(h.published.at(-1)!.findings).toEqual([]);
    expect(
      h.calls.every(
        (options) =>
          options.mode === "standard" &&
          options.parentScanId === h.input.scanId &&
          options.deepScanPass === true,
      ),
    ).toBe(true);
  });

  test("resets no-new streak on a novel stable identity", async () => {
    const h = await harness({ stopAfterNoNew: 2 });
    let pass = 0;
    h.setRun(async (options) =>
      result(
        options.resumeScanId!,
        options.outputDir!,
        ++pass >= 2 ? "supported-issue" : undefined,
      ),
    );
    await runDeepScans(h.input);
    const state = await h.checkpoint();
    expect(h.calls).toHaveLength(4);
    expect(state.noNewStreak).toBe(2);
    expect(state.terminalReason).toBe("saturated");
    expect(h.published.at(-1)!.findings).toHaveLength(1);
    expect(
      (h.published.at(-1)!.findings[0]!["provenance"] as JsonObject)[
        "sourceFindings"
      ],
    ).toHaveLength(3);
    const admissions = h.checkpoints.filter(
      (checkpoint, index, all) =>
        checkpoint.mergedScanIds.length >
        (all[index - 1]?.mergedScanIds.length ?? 0),
    );
    expect(admissions.map((checkpoint) => checkpoint.noNewStreak)).toEqual([
      1, 0, 1, 2,
    ]);
  });

  test.each([
    [0, 0, "merge"],
    [0, 1, "merge"],
    [0, 3, "merge"],
    [2, 0, "merge"],
    [2, 1, "merge"],
    [3, 0, "merge"],
    [2, 1, "permission"],
    [2, 1, "refusal"],
    [0, 1, "rate limit"],
    [1, 0, "discovery"],
    [1, 0, "failed discovery"],
    [0, 0, "cost"],
  ] as const)(
    "resumes a sealed child with %i saved and %i new merge failures (%s)",
    async (priorFailures, failures, kind) => {
      const h = await harness({ stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
      const permissionFailure = kind === "permission";
      const fatalMergeFailure = permissionFailure || kind === "refusal";
      const discoveryLimit =
        kind === "discovery" || kind === "failed discovery";
      const consecutiveErrors = discoveryLimit ? 3 : 2;
      const childDirectory = "artifacts/deep-scan/passes/pass-1";
      const scanDir = join(h.input.scanDir, childDirectory);
      await mkdir(dirname(scanDir), { recursive: true, mode: 0o700 });
      await cp(example, scanDir, { recursive: true });
      if (process.platform !== "win32") await chmod(scanDir, 0o700);
      const scanId = exampleManifest.scan.id;
      h.records.set(scanId, {
        scanId,
        scanDir,
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status: "complete" },
        ...(kind === "cost" ? { cost: null } : {}),
      });
      const bytes = await readFile(join(scanDir, "findings.json"));
      await h.seed({
        version: 2,
        startedAt: h.input.startedAt,
        passes: [{ directory: childDirectory }],
        mergedScanIds: [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors,
        ...(priorFailures === 0 ? {} : { mergeFailures: priorFailures }),
        ...(kind === "failed discovery"
          ? { terminalReason: "failed" as const }
          : {}),
      });
      const merge = h.input.merge;
      const failure = permissionFailure
        ? new ScanPermissionError("Merge permissions rejected.")
        : new Error(
            kind === "refusal"
              ? "Request blocked by cyberPolicy."
              : kind === "rate limit"
                ? "429: request blocked by cyberPolicy."
                : "Merge failed.",
          );
      let attempts = 0;
      h.input.merge = async (...args) => {
        if (++attempts <= failures) throw failure;
        return merge(...args);
      };
      if (kind === "cost") {
        h.input.scanOptions.requireCost = true;
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
        expect(h.calls).toEqual([]);
        expect(attempts).toBe(0);
        expect(h.published).toEqual([]);
        expect(await readFile(join(scanDir, "findings.json"))).toEqual(bytes);
        return;
      }
      if (
        discoveryLimit ||
        fatalMergeFailure ||
        priorFailures + failures >= 3
      ) {
        const execution = runDeepScans(h.input);
        if (fatalMergeFailure) await expect(execution).rejects.toBe(failure);
        else
          await expect(execution).rejects.toThrow(
            discoveryLimit
              ? "consecutive error limit"
              : priorFailures === 3
                ? "consecutive merge error limit"
                : failure.message,
          );
        expect(attempts).toBe(
          discoveryLimit ? 0 : fatalMergeFailure ? 1 : 3 - priorFailures,
        );
        expect(h.calls).toEqual([]);
        expect(h.published).toEqual([]);
        expect(await h.checkpoint()).toMatchObject({
          consecutiveErrors,
          mergeFailures:
            discoveryLimit || fatalMergeFailure ? priorFailures : 3,
          noNewStreak: 0,
          mergedScanIds: [],
          terminalReason: "failed",
        });
        expect(await readFile(join(scanDir, "findings.json"))).toEqual(bytes);
        return;
      }
      await runDeepScans(h.input);
      const state = await h.checkpoint();
      expect(h.calls).toEqual([]);
      expect(h.mergeInputs).toEqual([1]);
      expect(state.mergedScanIds).toEqual([scanId]);
      expect(state.consecutiveErrors).toBe(consecutiveErrors);
      expect(state.mergeFailures).toBe(0);
      expect(attempts).toBe(failures + 1);
      expect(state.terminalReason).toBe("capped");
      expect(h.published.at(-1)!.findings).toHaveLength(1);
      expect(await readFile(join(scanDir, "findings.json"))).toEqual(bytes);
      await runDeepScans(h.input);
      expect(h.calls).toEqual([]);
      expect(h.mergeInputs).toEqual([1]);
      expect((await h.checkpoint()).mergedScanIds).toEqual([scanId]);
      expect((await h.checkpoint()).noNewStreak).toBe(state.noNewStreak);
      expect(await readFile(join(scanDir, "findings.json"))).toEqual(bytes);
    },
  );

  test("stops at the saved merge error limit before scheduling discovery", async () => {
    const h = await harness();
    await h.seed({
      version: 2,
      startedAt: h.input.startedAt,
      passes: [],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
      mergeFailures: 3,
    });
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "consecutive merge error limit",
    );
    expect(h.calls).toEqual([]);
    expect(h.mergeInputs).toEqual([]);
    expect((await h.checkpoint()).mergeFailures).toBe(3);
  });

  test("retries an invalid merge with the missing field diagnostic", async () => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    h.setRun(async (options) =>
      result(options.resumeScanId!, options.outputDir!, "supported-issue"),
    );
    const merge = h.input.merge;
    const prompts: string[] = [];
    h.input.merge = async (prompt, signal) => {
      prompts.push(prompt);
      const output = await merge(prompt, signal);
      if (prompts.length !== 1) return output;
      const invalid = structuredClone(output) as { findings: JsonObject[] };
      delete (invalid.findings[0]!["confidence"] as JsonObject)["rationale"];
      return invalid;
    };

    await runDeepScans(h.input);

    expect(prompts).toHaveLength(2);
    expect(prompts[1]).toContain("rationale");
    expect((await h.checkpoint()).mergeFailures).toBe(0);
    expect(h.published.at(-1)!.findings).toHaveLength(1);
  });

  test("continues the already reserved final pass before applying the run cap", async () => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    const id = randomUUID();
    const directory = "artifacts/deep-scan/passes/pass-1";
    h.records.set(id, {
      scanId: id,
      scanDir: join(h.input.scanDir, directory),
      parentScanId: h.input.scanId,
      targetPath: h.input.repository,
      progress: { status: "running" },
    });
    await h.seed({
      version: 2,
      startedAt: h.input.startedAt,
      passes: [{ directory, scanId: id }],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
    });
    await runDeepScans(h.input);
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0]!.resumeScanId).toBe(id);
    expect((await h.checkpoint()).mergedScanIds).toEqual([id]);
    expect((await h.checkpoint()).terminalReason).toBe("capped");
  });

  test("continues saved legacy counters and coverage using only new ordinary scans", async () => {
    const h = await harness({ maxDiscoveryRuns: 3, stopAfterNoNew: 4 });
    const coverage = {
      completeness: "partial",
      surfaces: [],
      deferred: [
        { id: "legacy-unresolved", reason: "Saved unresolved validation." },
      ],
    };
    await h.seed({
      version: 2,
      startedAt: h.input.startedAt,
      passes: [],
      mergedScanIds: [],
      aggregate: { scanId: h.input.scanId, findings: [], coverage },
      legacy: { discoveryRuns: 2, coverage },
      noNewStreak: 3,
      consecutiveErrors: 0,
    });
    await runDeepScans(h.input);
    const state = await h.checkpoint();
    expect(h.calls).toHaveLength(1);
    expect(state.passes).toHaveLength(1);
    expect(state.noNewStreak).toBe(4);
    expect(state.terminalReason).toBe("saturated");
    expect(state.aggregate!.coverage["deferred"]).toEqual(coverage.deferred);
    expect(state.aggregate!.coverage["completeness"]).toBe("partial");

    const ready = await harness();
    await ready.seed({
      ...state,
      passes: [],
      mergedScanIds: [],
      aggregate: {
        ...state.aggregate!,
        scanId: ready.input.scanId,
      },
    });
    await runDeepScans(ready.input);
    expect(ready.calls).toEqual([]);
    expect(ready.mergeInputs).toEqual([]);
    expect(ready.published.at(-1)!.coverage["deferred"]).toEqual(
      coverage.deferred,
    );
  });

  test("recovers legacy paid usage once and requires it before spending under a saved limit", async () => {
    const h = await harness({ maxDiscoveryRuns: 1 });
    const coverage = { completeness: "partial", surfaces: [] };
    const state: DeepScanCheckpoint = {
      version: 2,
      startedAt: h.input.startedAt,
      passes: [],
      mergedScanIds: [],
      aggregate: { scanId: h.input.scanId, findings: [], coverage },
      legacy: {
        discoveryRuns: 1,
        coverage,
        originThreadId: "original-session",
      },
      noNewStreak: 0,
      consecutiveErrors: 0,
    };
    await h.seed(state);
    h.input.scanOptions.requireCost = true;
    h.input.historicalCost = async () => null;
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "original Deep Scan session logs",
    );
    expect(h.calls).toEqual([]);
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 10000,
      output_tokens: 2000,
    })!;
    let recoveries = 0;
    h.input.historicalCost = async (threadId) => {
      expect(threadId).toBe("original-session");
      recoveries++;
      return cost;
    };
    const costs = new Map();
    h.input.onCost = (id, receipt) => {
      costs.set(id, receipt);
    };
    await runDeepScans(h.input);
    await runDeepScans(h.input);
    expect(recoveries).toBe(1);
    expect(costs.get("legacy")).toEqual(cost);
    expect((await h.checkpoint()).legacy!.cost).toEqual(cost);
    expect(h.calls).toEqual([]);
  });

  test.each([
    "Transient scan interruption",
    "429: request flagged for possible cybersecurity risk.",
    "Rate-limited: request refused under safety policy.",
  ])(
    "retries the same ordinary scan after %s without counting another logical input",
    async (message) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ stopAfterNoNew: 1 });
      let attempts = 0;
      h.setRun(async (options) => {
        if (++attempts === 1) throw new Error(message);
        return result(options.resumeScanId!, options.outputDir!);
      });
      await runDeepScans(h.input);
      const state = await h.checkpoint();
      expect(h.calls).toHaveLength(2);
      expect(h.calls[0]!.outputDir).toBe(h.calls[1]!.outputDir);
      expect(h.calls[1]!.resumeScanId).toBe(state.passes[0]!.scanId);
      expect(state.passes).toHaveLength(1);
      expect(state.noNewStreak).toBe(1);
      expect(state.mergedScanIds).toHaveLength(1);
      expect(h.mergeInputs).toEqual([1]);
    },
  );

  test.each([
    ["short", "Discovery failed."],
    ["long", "x".repeat(2401)],
  ])(
    "failed scans with %s errors do not count toward clean saturation",
    async (_label, message) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
      h.setRun(async (options) => {
        if (h.calls.length > 4)
          return result(options.resumeScanId!, options.outputDir!);
        throw new Error(message);
      });
      await expect(runDeepScans(h.input)).rejects.toThrow(
        "every discovery run failed",
      );
      const state = await h.checkpoint();
      expect(h.calls).toHaveLength(4);
      expect(state.passes).toHaveLength(1);
      expect(state.mergedScanIds).toEqual([]);
      expect(state.noNewStreak).toBe(0);
      expect(state.terminalReason).toBe("failed");
      expect(state.consecutiveErrors).toBe(1);
      expect(h.mergeInputs).toEqual([]);
      expect(h.published).toEqual([]);
    },
  );

  test.each([
    [0, "every discovery run failed"],
    [2, "consecutive error limit"],
    [2, "expired deadline"],
  ] as const)(
    "resumes a persisted child failure after %i prior errors (%s)",
    async (priorErrors, message) => {
      const h = await harness({ maxDiscoveryRuns: 1 });
      const scanId = randomUUID();
      const pass = { directory: "artifacts/deep-scan/passes/pass-1", scanId };
      h.records.set(scanId, {
        scanId,
        scanDir: join(h.input.scanDir, pass.directory),
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status: "failed" },
      });
      await h.seed({
        version: 2,
        startedAt:
          message === "expired deadline"
            ? new Date(Date.parse(h.input.startedAt) - 3_600_001).toISOString()
            : h.input.startedAt,
        passes: [pass],
        mergedScanIds: [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors: priorErrors,
      });
      if (message === "expired deadline") {
        await runDeepScans(h.input);
        expect(await h.checkpoint()).toMatchObject({
          terminalReason: "capped",
          consecutiveErrors: priorErrors,
          passes: [pass],
        });
        expect(h.calls).toEqual([]);
        return;
      }
      const workbench = h.input.workbench;
      h.input.workbench = async (args, input) => {
        const result = await workbench(args, input);
        if (
          args[0] === "save-scan-artifact" &&
          JSON.parse(input!).passes[0]?.failed
        )
          throw new ScanTransportClosedError("Transport closed.");
        return result;
      };
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      expect((await h.checkpoint()).terminalReason).toBeUndefined();
      h.input.workbench = workbench;

      await expect(runDeepScans(h.input)).rejects.toThrow(message);
      expect(await h.checkpoint()).toMatchObject({
        passes: [{ ...pass, failed: true }],
        consecutiveErrors: priorErrors + 1,
        noNewStreak: 0,
        mergedScanIds: [],
        terminalReason: "failed",
      });
      expect(h.calls).toEqual([]);
      expect(h.mergeInputs).toEqual([]);
      expect(h.published).toEqual([]);
    },
  );

  test("keeps the consecutive error limit when a sibling finishes after it", async () => {
    retryDelay = spyOn(timers, "setTimeout").mockImplementation(
      async <T>(_delay?: number, value?: T): Promise<T> => value as T,
    );
    const h = await harness({ workers: 2, stopAfterConsecutiveErrors: 1 });
    let releaseSibling!: () => void;
    const thresholdReached = new Promise<void>((resolve) => {
      releaseSibling = resolve;
    });
    const workbench = h.input.workbench;
    h.input.workbench = async (args, input) => {
      const result = await workbench(args, input);
      if (
        args[0] === "save-scan-artifact" &&
        JSON.parse(input!).consecutiveErrors === 1
      )
        releaseSibling();
      return result;
    };
    let siblingSignal: AbortSignal | undefined;
    h.setRun(async (options) => {
      if (options.outputDir!.endsWith("pass-1"))
        throw new Error("Discovery failed.");
      siblingSignal = options.signal;
      await thresholdReached;
      return result(options.resumeScanId!, options.outputDir!);
    });
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "consecutive error limit",
    );
    expect(siblingSignal?.aborted).toBe(true);
    expect(h.calls).toHaveLength(5);
    expect(h.metrics().closed).toBe(2);
    expect(h.mergeInputs).toEqual([]);
    expect(h.published).toEqual([]);
    expect(await h.checkpoint()).toMatchObject({
      terminalReason: "failed",
      consecutiveErrors: 1,
      noNewStreak: 0,
      mergedScanIds: [],
    });
  });

  test.each([false, true])(
    "counts exhausted unregistered passes toward the run cap (restart: %p)",
    async (restart) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ maxDiscoveryRuns: 1 });
      const attempts: ScanOptions[] = [];
      let closed = 0;
      h.input.createClient = () => ({
        async run(_repository, options = {}) {
          attempts.push(options);
          throw new Error("Scan registration failed.");
        },
        async close() {
          closed++;
        },
      });
      if (restart) {
        const workbench = h.input.workbench;
        h.input.workbench = async (args, input) => {
          const result = await workbench(args, input);
          if (
            args[0] === "save-scan-artifact" &&
            JSON.parse(input!).passes[0]?.failed
          )
            h.controller.abort(
              new ScanTransportClosedError("Transport closed."),
            );
          return result;
        };
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanTransportClosedError,
        );
        expect((await h.checkpoint()).terminalReason).toBeUndefined();
        h.input.workbench = workbench;
        h.input.signal = new AbortController().signal;
      }
      await expect(runDeepScans(h.input)).rejects.toThrow(
        "every discovery run failed",
      );
      expect(attempts).toHaveLength(4);
      expect(new Set(attempts.map((attempt) => attempt.outputDir)).size).toBe(
        1,
      );
      expect(closed).toBe(1);
      expect(h.records.size).toBe(0);
      expect(await h.checkpoint()).toMatchObject({
        startedAt: h.input.startedAt,
        passes: [
          { directory: "artifacts/deep-scan/passes/pass-1", failed: true },
        ],
        consecutiveErrors: 1,
        noNewStreak: 0,
        terminalReason: "failed",
      });
    },
  );

  test.each([
    [false, false, true],
    [false, true, true],
    [true, false, true],
    [true, true, true],
    [false, true, false],
    [true, true, false],
  ])(
    "accounts for failed pass cost (resumed: %p, required: %p, executed: %p)",
    async (resumed, requireCost, executed) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ stopAfterNoNew: 1, maxDiscoveryRuns: 2 });
      h.input.scanOptions.requireCost = requireCost;
      const failedDirectory = "artifacts/deep-scan/passes/pass-1";
      const costs = new Map<string, Readonly<ScanCost> | null>();
      h.input.onCost = (key, cost) => {
        costs.set(key, cost);
      };
      if (resumed) {
        const scanId = randomUUID();
        h.records.set(scanId, {
          scanId,
          scanDir: join(h.input.scanDir, failedDirectory),
          parentScanId: h.input.scanId,
          targetPath: h.input.repository,
          progress: { status: "failed" },
          ...(executed ? { continuationThreadId: `thread-${scanId}` } : {}),
        });
        await h.seed({
          version: 2,
          startedAt: h.input.startedAt,
          passes: [{ directory: failedDirectory, scanId }],
          mergedScanIds: [],
          aggregate: null,
          noNewStreak: 0,
          consecutiveErrors: 0,
        });
      }
      h.setRun(async (options) => {
        const scanId = options.resumeScanId!;
        if (options.outputDir!.endsWith("pass-1")) {
          if (executed)
            h.records.get(scanId)!.continuationThreadId = `thread-${scanId}`;
          throw new Error("Discovery failed.");
        }
        const completed = new ScanResult({
          ...result(scanId, options.outputDir!),
          turnResult: {
            model: "gpt-6-astra",
            usage: { input_tokens: 10000, output_tokens: 2000 },
          },
        });
        h.records.get(scanId)!.cost = completed.cost;
        return completed;
      });
      const stopped = executed && requireCost;
      if (stopped)
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
      else {
        await runDeepScans(h.input);
        expect((await h.checkpoint()).terminalReason).toBe("saturated");
        expect(h.published.at(-1)!.coverage["completeness"]).toBe("partial");
      }
      expect(h.calls).toHaveLength((resumed ? 0 : 4) + (stopped ? 0 : 1));
      expect(h.mergeInputs).toEqual(stopped ? [] : [1]);
      expect(costs.has(failedDirectory)).toBe(executed);
      if (executed) expect(costs.get(failedDirectory)).toBeNull();
      expect([...costs.values()].some((cost) => cost !== null)).toBe(!stopped);
    },
  );

  test.each([false, true])(
    "replaces partial child cost with unavailable completed cost (required: %p)",
    async (requireCost) => {
      const h = await harness({ stopAfterNoNew: 1, maxDiscoveryRuns: 2 });
      h.input.scanOptions.requireCost = requireCost;
      const partial = estimateScanCost("gpt-6-astra", {
        input_tokens: 10000,
        output_tokens: 2000,
      })!;
      const costs: Array<Readonly<ScanCost> | null> = [];
      h.input.onCost = (_key, cost) => costs.push(cost);
      h.setRun(async (options) => {
        options.onCost?.(partial);
        return result(options.resumeScanId!, options.outputDir!);
      });
      if (requireCost) {
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
        expect(h.mergeInputs).toEqual([]);
        expect(h.published).toEqual([]);
        expect(await h.checkpoint()).toMatchObject({
          terminalReason: "failed",
          consecutiveErrors: 0,
          noNewStreak: 0,
          mergedScanIds: [],
        });
      } else {
        await runDeepScans(h.input);
        expect(h.mergeInputs).toEqual([1]);
        expect((await h.checkpoint()).terminalReason).toBe("saturated");
      }
      expect(h.calls).toHaveLength(1);
      expect(costs[0]).toEqual(partial);
      expect(costs.at(-1)).toBeNull();
    },
  );

  test.each([
    "metering",
    "permission before registration",
    "permission after registration",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
    "Request blocked by cyberPolicy.",
    "Request blocked by a cybersecurity_policy_violation.",
    "Request blocked by a safety policy violation.",
    "Request refused under cybersecurity policy.",
    "Cybersecurity policy has refused the request.",
  ])(
    "required child %s failure stops sibling discovery without retries or merging",
    async (kind) => {
      const h = await harness({ workers: 2, maxDiscoveryRuns: 4 });
      h.input.scanOptions.requireCost = kind === "metering";
      const beforeRegistration = kind === "permission before registration";
      const failure =
        kind === "metering"
          ? new ScanCostTrackingError(
              "Required usage unavailable.",
              h.input.scanDir,
            )
          : kind.startsWith("permission")
            ? new ScanPermissionError("Read-only permissions rejected.")
            : new Error(kind);
      let secondStarted!: () => void;
      const started = new Promise<void>((resolve) => {
        secondStarted = resolve;
      });
      const retries: string[] = [];
      h.input.onRetry = (message) => {
        retries.push(message);
        h.controller.abort(new Error("A fatal child failure was retried."));
      };
      if (beforeRegistration) {
        const createClient = h.input.createClient;
        h.input.createClient = () => {
          const client = createClient();
          return {
            ...client,
            async run(repository, options = {}) {
              if (options.outputDir!.endsWith("pass-1")) {
                await abortable(() => started, options.signal);
                throw failure;
              }
              return await client.run(repository, options);
            },
          };
        };
      }
      h.setRun(async (options) => {
        if (options.outputDir!.endsWith("pass-1")) {
          await abortable(() => started, options.signal);
          throw failure;
        }
        secondStarted();
        options.signal!.throwIfAborted();
        return await new Promise<ScanResult>((_resolve, reject) => {
          options.signal!.addEventListener(
            "abort",
            () => reject(options.signal!.reason),
            { once: true },
          );
        });
      });
      await expect(runDeepScans(h.input)).rejects.toBe(failure);
      expect(h.calls).toHaveLength(beforeRegistration ? 1 : 2);
      expect(h.metrics().closed).toBe(2);
      expect(retries).toEqual([]);
      expect(h.mergeInputs).toEqual([]);
      expect(
        [...h.records.values()].map((record) => record.progress.status),
      ).toEqual(beforeRegistration ? ["failed"] : ["failed", "failed"]);
      const state = await h.checkpoint();
      expect(state).toMatchObject({
        terminalReason: "failed",
        consecutiveErrors: 0,
        noNewStreak: 0,
        mergedScanIds: [],
      });
      if (beforeRegistration) expect(state.passes[0]!.scanId).toBeUndefined();
    },
  );

  test.each(["accepted", "fatal"])(
    "preserves the %s child outcome when cleanup fails",
    async (outcome) => {
      const h = await harness({ stopAfterNoNew: 1 });
      const cleanupFailure = Object.assign(new Error("Cleanup denied."), {
        code: "EPERM",
      });
      const cleanupErrors: unknown[] = [];
      h.input.onCleanupError = (error) => cleanupErrors.push(error);
      const createClient = h.input.createClient;
      h.input.createClient = () => {
        const client = createClient();
        return {
          ...client,
          async close() {
            await client.close();
            throw cleanupFailure;
          },
        };
      };
      if (outcome === "fatal") {
        const failure = new ScanPermissionError(
          "Read-only permissions rejected.",
        );
        h.setRun(async () => {
          throw failure;
        });
        await expect(runDeepScans(h.input)).rejects.toBe(failure);
        expect(h.mergeInputs).toEqual([]);
        expect((await h.checkpoint()).terminalReason).toBe("failed");
      } else {
        const state = await runDeepScans(h.input);
        expect(state.terminalReason).toBe("saturated");
        expect(state.mergedScanIds).toHaveLength(1);
        expect(h.published.at(-1)).toEqual(state.aggregate!);
      }
      expect(h.calls).toHaveLength(1);
      expect(h.metrics().closed).toBe(1);
      expect(cleanupErrors).toEqual([cleanupFailure]);
    },
  );

  test("surfaces failed child persistence instead of restarting its retries", async () => {
    retryDelay = spyOn(timers, "setTimeout").mockImplementation(
      async <T>(_delay?: number, value?: T): Promise<T> => value as T,
    );
    const h = await harness({ stopAfterNoNew: 1, maxDiscoveryRuns: 1 });
    h.setRun(async (options) => {
      if (h.calls.length > 4)
        return result(options.resumeScanId!, options.outputDir!);
      throw new Error("Discovery failed.");
    });
    const workbench = h.input.workbench;
    h.input.workbench = async (args, input) => {
      if (args[0] === "fail-scan")
        throw new Error("Saved scan is unavailable.");
      return await workbench(args, input);
    };
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "Saved scan is unavailable.",
    );
    expect(h.calls).toHaveLength(4);
    expect(h.metrics().closed).toBe(1);
    expect((await h.checkpoint()).terminalReason).toBe("failed");
  });

  test("caps discovery when its deadline interrupts a child", async () => {
    const h = await harness({ maxDiscoveryRuns: 1 });
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
    h.setRun(async (options) => {
      clock.mockReturnValue(now + 3_600_000);
      expect(expire).toBeDefined();
      expire!();
      throw options.signal!.reason;
    });
    try {
      await runDeepScans(h.input);
      expect(h.calls).toHaveLength(1);
      expect(await h.checkpoint()).toMatchObject({
        terminalReason: "capped",
        consecutiveErrors: 0,
      });
      expect([...h.records.values()][0]!.progress.status).toBe("failed");
      expect(h.metrics().closed).toBe(1);
    } finally {
      timer.mockRestore();
      clock.mockRestore();
    }
  });

  test("reports the original deadline when the final merge reaches saturation late", async () => {
    const h = await harness({ stopAfterNoNew: 1 });
    const merge = h.input.merge;
    const clock = spyOn(Date, "now");
    h.input.merge = async (...args) => {
      const merged = await merge(...args);
      clock.mockReturnValue(Date.parse(h.input.startedAt) + 3_600_001);
      return merged;
    };
    try {
      await runDeepScans(h.input);
      expect(await h.checkpoint()).toMatchObject({
        startedAt: h.input.startedAt,
        noNewStreak: 1,
        terminalReason: "capped",
      });
      expect(h.calls).toHaveLength(1);
      expect(h.mergeInputs).toEqual([1]);
      expect(h.published.at(-1)!.findings).toEqual([]);
    } finally {
      clock.mockRestore();
    }
  });

  test("cancellation preserves accepted progress and closes owned clients", async () => {
    const h = await harness({ stopAfterNoNew: 4 });
    let passes = 0;
    h.setRun(async (options) => {
      if (++passes === 2) {
        h.controller.abort(new Error("Canceled by the user."));
        throw h.controller.signal.reason;
      }
      return result(
        options.resumeScanId!,
        options.outputDir!,
        "supported-issue",
      );
    });
    await expect(runDeepScans(h.input)).rejects.toThrow("Canceled by the user");
    const state = await h.checkpoint();
    expect(state.terminalReason).toBe("canceled");
    expect(state.mergedScanIds).toHaveLength(1);
    expect(state.aggregate!.findings).toHaveLength(1);
    expect(
      (state.aggregate!.findings[0]!["provenance"] as JsonObject)[
        "sourceFindings"
      ],
    ).toHaveLength(1);
    expect(h.published.at(-1)).toEqual(state.aggregate!);
    expect(h.published.at(-1)!.coverage["completeness"]).toBe("partial");
    expect(h.published.at(-1)!.coverage["deferred"]).toHaveLength(1);
    expect(h.metrics().closed).toBe(2);
  });

  test.each(["transport interruption", "explicit cancellation"] as const)(
    "preserves saved discovery state across %s with the correct child lifecycle",
    async (stop) => {
      const h = await harness({ stopAfterNoNew: 3 });
      const now = Date.parse("2026-01-02T12:00:00Z");
      h.input.startedAt = new Date(now).toISOString();
      const startedAt = new Date(now - 1_800_000).toISOString();
      const scanId = randomUUID();
      const directory = "artifacts/deep-scan/passes/pass-1";
      const scanDir = join(h.input.scanDir, directory);
      const childCheckpoint = join(scanDir, "checkpoint.json");
      const childBytes = Buffer.from('{"completed":"inventory"}\n');
      await mkdir(scanDir, { recursive: true, mode: 0o700 });
      await writeFile(childCheckpoint, childBytes);
      h.records.set(scanId, {
        scanId,
        scanDir,
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status: "running" },
      });
      const coverage = { completeness: "partial", surfaces: [] };
      const checkpoint: DeepScanCheckpoint = {
        version: 2,
        startedAt,
        passes: [{ directory, scanId }],
        mergedScanIds: [],
        aggregate: { scanId: h.input.scanId, findings: [], coverage },
        legacy: { discoveryRuns: 2, coverage },
        noNewStreak: 2,
        consecutiveErrors: 1,
        mergeFailures: 1,
      };
      await h.seed(checkpoint);
      const checkpointPath = join(h.input.scanDir, DEEP_SCAN_CHECKPOINT);
      const checkpointBytes = await readFile(checkpointPath);
      const reason =
        stop === "transport interruption"
          ? new ScanTransportClosedError("Native transport disconnected.")
          : new Error("Canceled by the user.".padEnd(2401, "."));
      h.setRun(async () => {
        h.controller.abort(reason);
        throw reason;
      });
      const clock = spyOn(Date, "now").mockReturnValue(now);
      try {
        await expect(runDeepScans(h.input)).rejects.toThrow(reason.message);
        expect(h.calls).toHaveLength(1);
        expect(h.calls[0]).toMatchObject({
          resumeScanId: scanId,
          outputDir: scanDir,
        });
        expect(h.metrics()).toEqual({ closed: 1, maximumActive: 1 });
        expect(await readFile(childCheckpoint)).toEqual(childBytes);
        expect(await h.checkpoint()).toMatchObject({
          startedAt,
          passes: checkpoint.passes,
          mergedScanIds: [],
          noNewStreak: 2,
          consecutiveErrors: 1,
          mergeFailures: 1,
        });
        if (stop === "explicit cancellation") {
          expect((await h.checkpoint()).terminalReason).toBe("canceled");
          expect(h.records.get(scanId)!.progress.status).toBe("failed");
          return;
        }

        expect(await readFile(checkpointPath)).toEqual(checkpointBytes);
        expect((await h.checkpoint()).terminalReason).toBeUndefined();
        expect(h.records.get(scanId)!.progress.status).toBe("running");
        expect(h.published).toEqual([]);
        h.input.signal = new AbortController().signal;
        h.setRun(async (options) => {
          clock.mockReturnValue(Date.parse(startedAt) + 3_600_001);
          return result(options.resumeScanId!, options.outputDir!);
        });
        await runDeepScans(h.input);
        expect(h.calls).toHaveLength(2);
        expect(h.calls[1]).toMatchObject({
          resumeScanId: scanId,
          outputDir: scanDir,
        });
        expect(h.records.size).toBe(1);
        expect(h.records.get(scanId)!.progress.status).toBe("complete");
        expect(await h.checkpoint()).toMatchObject({
          startedAt,
          passes: checkpoint.passes,
          mergedScanIds: [scanId],
          noNewStreak: 3,
          consecutiveErrors: 0,
          mergeFailures: 0,
          terminalReason: "capped",
        });
        expect(h.mergeInputs).toEqual([1]);
        expect(h.metrics()).toEqual({ closed: 2, maximumActive: 1 });
        expect(await readFile(childCheckpoint)).toEqual(childBytes);
      } finally {
        clock.mockRestore();
      }
    },
  );
});
