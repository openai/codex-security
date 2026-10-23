import * as childProcess from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, spyOn, test } from "bun:test";
import { Codex } from "@openai/codex-sdk";
import type { ScanOptions } from "../src/api.js";
import { estimateScanCost } from "../src/cost.js";
import { tokenUsage, type ScanTokenUsage } from "../src/cost-model.js";
import { OutputDirectoryError } from "../src/errors.js";
import {
  DEEP_SCAN_CHECKPOINT,
  DeepScanPublicationError,
  DeepScanRecoveryError,
  DeepScanInputRecoveryError,
  runDeepScans,
  ScanCostTrackingError,
  type DeepScanComposition,
} from "../src/deep-scan.js";
import {
  loadDeepScanCheckpoint,
  newDeepScanCheckpoint,
} from "../src/deep-scan-checkpoint.js";
import { ScanResult } from "../src/result.js";
import { prepareScanArtifactRestorer } from "../src/runtime.js";
import { createPermissionCheckedCodex } from "../src/permission-profile.js";
import { readCodexTurn } from "../src/scan-events.js";
import {
  ScanPermissionError,
  ScanTransportClosedError,
} from "../src/scan-execution.js";
import type { ScanMergeInput } from "../src/scan-merge.js";
import type { SemanticScan } from "../src/semantic-models.js";
import type { SavedScanRecord } from "../src/workbench-types.js";
import { semanticCoverage, semanticFinding } from "./helpers/semantic-scan.js";
import { fixtureSpawn } from "./support/codex-process.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture(
  settings: Partial<DeepScanComposition["settings"]> = {},
) {
  const scanDir = await mkdtemp(join(tmpdir(), "composition-"));
  roots.push(scanDir);
  const scanId = randomUUID();
  const repository = join(scanDir, "repository");
  const records = new Map<string, SavedScanRecord>();
  const projected = new Map<string, ScanMergeInput>();
  const calls: ScanOptions[] = [];
  const publications: SemanticScan[] = [];
  const operations: string[] = [];
  const costs = new Map();
  const controller = new AbortController();
  let merges = 0;
  let closes = 0;
  let registrationThreadId: string | null = "session";
  let execute: (options: ScanOptions) => Promise<void> = async () => {};
  const write = async (path: string, contents: Uint8Array | string) => {
    await mkdir(dirname(join(scanDir, path)), { recursive: true, mode: 0o700 });
    await writeFile(join(scanDir, path), contents);
  };
  const input: DeepScanComposition = {
    scanId,
    scanDir,
    repository,
    pluginRoot,
    startedAt: new Date().toISOString(),
    signal: controller.signal,
    settings: {
      workers: 2,
      subagents: 0,
      maxDiscoveryRuns: 2,
      maxTimeHours: 1,
      stopAfterNoNew: 4,
      stopAfterConsecutiveErrors: 2,
      ...settings,
    },
    scanOptions: {},
    createClient: () => ({
      async run(_repository, options = {}) {
        calls.push(options);
        const childId = options.resumeScanId ?? randomUUID();
        records.set(childId, {
          scanId: childId,
          scanDir: options.outputDir!,
          targetPath: repository,
          parentScanId: scanId,
          parentScanRole: "deep_pass",
          continuationThreadId: registrationThreadId,
          progress: { status: "running" },
        });
        await options.onRegisteredScan?.({
          scanId: childId,
          threadId: registrationThreadId,
          scanDir: options.outputDir!,
        });
        let usage = tokenUsage({ input_tokens: 10, output_tokens: 3 })!;
        await execute({
          ...options,
          onUsage: (snapshot) => {
            usage = { ...snapshot };
            options.onUsage?.(snapshot);
          },
        });
        const finding = semanticFinding({
          provenance: {
            source: "local_plugin",
            sourceFindingIds: [`${childId}:0`],
          },
        });
        projected.set(childId, {
          scanId: childId,
          scanDir: options.outputDir!,
          sourceFindings: [finding],
          draft: { scanId, findings: [finding], coverage: semanticCoverage() },
        });
        const cost = estimateScanCost("gpt-6-astra", usage);
        records.get(childId)!.progress.status = "complete";
        records.get(childId)!.cost = cost;
        records.get(childId)!.completedAt = new Date().toISOString();
        return {
          manifest: { scan: { id: childId } },
          scanDir: options.outputDir!,
          turnResult: { usage },
          cost,
        } as ScanResult;
      },
      async close() {
        closes++;
      },
    }),
    async workbench(args, contents) {
      operations.push(args[0]!);
      if (args[0] === "save-scan-artifact") {
        await write(args[4]!, contents!);
        return {};
      }
      if (args[0] === "list-scans")
        return { scans: [...records.values()] } as never;
      if (args[0] === "update-progress") return {};
      if (args[0] === "get-scan")
        return { scan: records.get(args[2]!) } as never;
      if (args[0] === "fail-scan") {
        records.get(args[2]!)!.progress.status = "failed";
        records.get(args[2]!)!.completedAt = new Date().toISOString();
        return {};
      }
      throw new Error(`Unexpected operation ${args[0]}`);
    },
    async projectChild(id) {
      return projected.get(id)!;
    },
    async merge(prompt) {
      merges++;
      const catalogue = JSON.parse(prompt.split("\n").at(-1)!);
      expect(catalogue.findings.before.length).toBeGreaterThan(0);
      expect(catalogue.findings.after.length).toBeGreaterThan(0);
      return { matches: [], uncertain: [], related: [], request: null };
    },
    writer: {
      restore: write,
      async restoreMany(artifacts) {
        for (const artifact of artifacts)
          await write(artifact.path, artifact.contents);
      },
    },
    async publish(draft) {
      publications.push(draft);
    },
    onCost(key, cost) {
      costs.set(key, cost);
    },
  };
  return {
    input,
    calls,
    records,
    projected,
    publications,
    operations,
    costs,
    controller,
    write,
    setExecute(fn: typeof execute) {
      execute = fn;
    },
    setRegistrationThreadId(id: string | null) {
      registrationThreadId = id;
    },
    metrics: () => ({ merges, closes }),
  };
}

async function unstartedRetirementFixture() {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  h.input.scanOptions.requireCost = true;
  h.input.unstartedCost = estimateScanCost("gpt-6-astra", {
    input_tokens: 0,
    output_tokens: 0,
  });
  h.setRegistrationThreadId(null);
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    const result = await workbench(args, contents);
    const costIndex = args.indexOf("--cost-json");
    if (args[0] === "fail-scan" && costIndex !== -1)
      h.records.get(args[2]!)!.cost = JSON.parse(args[costIndex + 1]!);
    return result;
  };
  return h;
}

async function saveUnstartedPass(
  h: Awaited<ReturnType<typeof unstartedRetirementFixture>>,
  expired = true,
) {
  const directory = "artifacts/deep-scan/passes/pass-1";
  const childId = randomUUID();
  h.records.set(childId, {
    scanId: childId,
    scanDir: join(h.input.scanDir, directory),
    targetPath: h.input.repository,
    parentScanId: h.input.scanId,
    parentScanRole: "deep_pass",
    continuationThreadId: null,
    progress: { status: "running" },
  });
  await h.write(
    DEEP_SCAN_CHECKPOINT,
    JSON.stringify({
      ...newDeepScanCheckpoint(
        expired
          ? new Date(Date.now() - 2 * 3600000).toISOString()
          : h.input.startedAt,
      ),
      passes: [{ directory, scanId: childId, executionNotStarted: true }],
    }),
  );
  return { directory, childId };
}

test.each(["deadline", "user abort", "parent stop"] as const)(
  "unstarted discovery retirement preserves %s and later recovery",
  async (scenario) => {
    const h = await unstartedRetirementFixture();
    h.input.settings.maxTimeHours = 1 / 3600;
    const now = Date.now();
    h.input.startedAt = new Date(now).toISOString();
    const clock = spyOn(Date, "now").mockReturnValue(now);
    const rejection = new DeepScanInputRecoveryError(
      "Synthetic changed instructions",
      h.input.scanDir,
      true,
    );
    h.setExecute(async () => {
      throw rejection;
    });
    const cancellation = new Error("Synthetic explicit caller cancellation");
    let expire: (() => void) | undefined;
    let poll: (() => void) | undefined;
    const setTimeout = globalThis.setTimeout;
    const setInterval = globalThis.setInterval;
    const timeout = spyOn(globalThis, "setTimeout").mockImplementation(((
      ...parameters: Parameters<typeof setTimeout>
    ) => {
      const [callback, delay, ...args] = parameters;
      if (scenario === "deadline" && delay === 1000) {
        expire = () => callback(...args);
        return setTimeout(() => {}, 60000);
      }
      return setTimeout(...parameters);
    }) as typeof setTimeout);
    const interval = spyOn(globalThis, "setInterval").mockImplementation(((
      ...parameters: Parameters<typeof setInterval>
    ) => {
      const [callback, delay, ...args] = parameters;
      if (scenario === "parent stop" && delay === 1000) {
        poll = () => callback(...args);
        return setInterval(() => {}, 60000);
      }
      return setInterval(...parameters);
    }) as typeof setInterval);
    const workbench = h.input.workbench;
    let triggered = false;
    h.input.workbench = async (args, contents) => {
      if (
        scenario === "parent stop" &&
        args[0] === "get-scan" &&
        args[2] === h.input.scanId
      )
        return { scan: { progress: { status: "failed" } } } as never;
      const result = await workbench(args, contents);
      if (
        !triggered &&
        args[0] === "save-scan-artifact" &&
        args[4] === DEEP_SCAN_CHECKPOINT &&
        JSON.parse(contents!).passes[0]?.executionNotStarted === true
      ) {
        triggered = true;
        if (scenario === "deadline") {
          expect(expire).toBeDefined();
          clock.mockReturnValue(now + 1001);
          expire!();
        } else if (scenario === "user abort") h.controller.abort(cancellation);
        else {
          expect(poll).toBeDefined();
          poll!();
          await Promise.resolve();
          await Promise.resolve();
        }
      }
      return result;
    };
    try {
      const error = await runDeepScans(h.input).catch(
        (error: unknown) => error,
      );
      expect(triggered).toBe(true);
      const state = (await loadDeepScanCheckpoint(h.input.scanDir))!;
      const child = [...h.records.values()][0]!;
      expect(state.terminalReason).toBeUndefined();
      expect(state.costUnavailable).toBeUndefined();
      expect(h.calls).toHaveLength(1);
      if (scenario === "parent stop") {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe("The saved parent scan stopped.");
        expect(child.progress.status).toBe("running");
        expect(child.cost).toBeUndefined();
        expect(h.operations).not.toContain("fail-scan");
      } else {
        expect(error).toBe(rejection);
        expect(state.pendingStop?.reason).toBe(
          scenario === "deadline" ? "capped" : "canceled",
        );
        expect(child.progress.status).toBe("failed");
        expect(child.cost).toEqual(h.input.unstartedCost);
        if (scenario === "deadline") {
          const resumed = await runDeepScans(h.input);
          expect(resumed.terminalReason).toBe("capped");
          expect(resumed.pendingStop).toBeUndefined();
          expect(resumed.passes[0]!.executionNotStarted).toBeUndefined();
          expect(resumed.costUnavailable).toBeUndefined();
        } else {
          await expect(runDeepScans(h.input)).rejects.toThrow(
            "saved Deep Scan is canceled",
          );
          const resumed = (await loadDeepScanCheckpoint(h.input.scanDir))!;
          expect(resumed.terminalReason).toBe("canceled");
          expect(resumed.pendingStop).toBeUndefined();
        }
        expect(h.calls).toHaveLength(1);
      }
    } finally {
      timeout.mockRestore();
      interval.mockRestore();
      clock.mockRestore();
    }
  },
);

test("expired discovery retires a saved unstarted child without execution", async () => {
  const h = await unstartedRetirementFixture();
  const { childId, directory } = await saveUnstartedPass(h);
  const state = await runDeepScans(h.input);
  expect(state.terminalReason).toBe("capped");
  expect(state.costUnavailable).toBeUndefined();
  expect(state.pendingStop).toBeUndefined();
  expect(h.calls).toHaveLength(0);
  expect(h.records.get(childId)!.progress.status).toBe("failed");
  expect(h.records.get(childId)!.cost).toEqual(h.input.unstartedCost);
  expect(h.costs.get(directory)).toEqual(h.input.unstartedCost);
  const resumed = await runDeepScans(h.input);
  expect(resumed.terminalReason).toBe("capped");
  expect(resumed.passes[0]!.executionNotStarted).toBeUndefined();
  expect(resumed.costUnavailable).toBeUndefined();
  expect(h.calls).toHaveLength(0);
});

test.each(["before retirement", "after retirement"] as const)(
  "unstarted retirement recovers transport loss %s",
  async (phase) => {
    const h = await unstartedRetirementFixture();
    const { childId } = await saveUnstartedPass(h);
    const workbench = h.input.workbench;
    const loss = new ScanTransportClosedError(
      "Synthetic retirement response loss",
    );
    let lost = false;
    h.input.workbench = async (args, contents) => {
      if (!lost && args[0] === "fail-scan") {
        lost = true;
        if (phase === "after retirement") await workbench(args, contents);
        throw loss;
      }
      return workbench(args, contents);
    };
    await expect(runDeepScans(h.input)).rejects.toBe(loss);
    const interrupted = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect(interrupted.pendingStop?.reason).toBe("capped");
    expect(interrupted.terminalReason).toBeUndefined();
    expect(interrupted.passes[0]!.executionNotStarted).toBe(true);
    expect(h.records.get(childId)!.progress.status).toBe(
      phase === "after retirement" ? "failed" : "running",
    );
    expect(h.records.get(childId)!.cost).toEqual(
      phase === "after retirement" ? h.input.unstartedCost : undefined,
    );
    const resumed = await runDeepScans(h.input);
    expect(resumed.terminalReason).toBe("capped");
    expect(resumed.pendingStop).toBeUndefined();
    expect(resumed.costUnavailable).toBeUndefined();
    expect(resumed.passes[0]!.executionNotStarted).toBeUndefined();
    expect(h.records.get(childId)!.cost).toEqual(h.input.unstartedCost);
    expect(h.calls).toHaveLength(0);
  },
);

test("consumed unstarted proof cannot price a later attempted turn with no receipt", async () => {
  const h = await unstartedRetirementFixture();
  const { childId } = await saveUnstartedPass(h, false);
  let attempted = 0;
  const loss = new ScanTransportClosedError(
    "Synthetic attempted turn response loss",
  );
  h.setExecute(async () => {
    attempted++;
    expect(
      (await loadDeepScanCheckpoint(h.input.scanDir))!.passes[0]!
        .executionNotStarted,
    ).toBeUndefined();
    throw loss;
  });
  await expect(runDeepScans(h.input)).rejects.toBe(loss);
  expect(attempted).toBe(1);
  expect(h.records.get(childId)!.cost).toBeUndefined();
  expect(h.records.get(childId)!.progress.status).toBe("running");
  expect(h.operations).not.toContain("fail-scan");
  await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
    ScanCostTrackingError,
  );
  expect(attempted).toBe(1);
  expect(h.records.get(childId)!.cost).toBeUndefined();
  expect((await loadDeepScanCheckpoint(h.input.scanDir))!.costUnavailable).toBe(
    true,
  );
});

test.each(["live", "pending stop"] as const)(
  "unstarted retirement preserves an existing %s cost receipt",
  async (source) => {
    const h = await unstartedRetirementFixture();
    const { childId, directory } = await saveUnstartedPass(h);
    const liveCost = estimateScanCost("gpt-6-astra", {
      input_tokens: 10,
      output_tokens: 3,
    })!;
    const suppliedCost = estimateScanCost("gpt-6-astra", {
      input_tokens: 20,
      output_tokens: 6,
    })!;
    h.records.get(childId)!.cost = liveCost;
    if (source === "pending stop") {
      const checkpoint = (await loadDeepScanCheckpoint(h.input.scanDir))!;
      checkpoint.pendingStop = {
        reason: "capped",
        message: "Synthetic saved deadline",
        costs: { [directory]: suppliedCost },
      };
      await h.write(DEEP_SCAN_CHECKPOINT, JSON.stringify(checkpoint));
    }
    const state = await runDeepScans(h.input);
    const expected = source === "live" ? liveCost : suppliedCost;
    expect(state.terminalReason).toBe("capped");
    expect(state.costUnavailable).toBeUndefined();
    expect(h.records.get(childId)!.cost).toEqual(expected);
    expect(h.costs.get(directory)).toEqual(expected);
    expect(h.calls).toHaveLength(0);
  },
);

test("unstarted retirement does not invent a price for an unknown model", async () => {
  const h = await unstartedRetirementFixture();
  h.input.unstartedCost = null;
  const { childId, directory } = await saveUnstartedPass(h);
  await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
    ScanCostTrackingError,
  );
  expect(h.records.get(childId)!.cost).toBeUndefined();
  expect(h.calls).toHaveLength(0);
  expect(h.costs.get(directory)).toBeNull();
});

test("unstarted discovery rejects repeatedly and restores the same required-cost pass", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  h.input.scanOptions.requireCost = true;
  h.setRegistrationThreadId(null);
  const rejection = new DeepScanInputRecoveryError(
    "Synthetic changed instructions",
    h.input.scanDir,
    true,
  );
  h.setExecute(async () => {
    throw rejection;
  });
  const createClient = h.input.createClient;
  h.input.createClient = () => {
    const client = createClient();
    return {
      close: () => client.close(),
      async run(repository, options) {
        expect(
          (await loadDeepScanCheckpoint(h.input.scanDir))!.passes[0]!
            .executionNotStarted,
        ).toBeUndefined();
        return client.run(repository, options);
      },
    };
  };
  let childId: string | undefined;
  for (let attempt = 0; attempt < 2; attempt++) {
    await expect(runDeepScans(h.input)).rejects.toBe(rejection);
    const state = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    childId ??= state.passes[0]!.scanId;
    expect(state.passes).toEqual([
      {
        directory: "artifacts/deep-scan/passes/pass-1",
        scanId: childId,
        executionNotStarted: true,
      },
    ]);
    expect(state.costUnavailable).toBeUndefined();
    expect(state.terminalReason).toBeUndefined();
    expect(h.records.get(childId!)!.progress.status).toBe("running");
  }
  h.setExecute(async () => {
    h.records.get(childId!)!.continuationThreadId = "restored-session";
  });
  const restored = await runDeepScans(h.input);
  expect(restored.passes).toEqual([
    { directory: "artifacts/deep-scan/passes/pass-1", scanId: childId },
  ]);
  expect(restored.costUnavailable).toBeUndefined();
  expect(restored.terminalReason).toBe("capped");
  expect(h.records.size).toBe(1);
  expect(h.records.get(childId!)!.progress.status).toBe("complete");
  expect(h.calls.map((options) => options.resumeScanId)).toEqual([
    undefined,
    childId,
    childId,
  ]);
  expect(h.operations).not.toContain("fail-scan");
});

test.each(["consume", "record"] as const)(
  "unstarted discovery checkpoint %s failure preserves conservative recovery",
  async (phase) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
    h.input.scanOptions.requireCost = true;
    h.setRegistrationThreadId(null);
    h.setExecute(async () => {
      throw new DeepScanInputRecoveryError(
        "Synthetic invalid input",
        h.input.scanDir,
        true,
      );
    });
    if (phase === "consume")
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        DeepScanInputRecoveryError,
      );
    const beforeCalls = h.calls.length;
    const workbench = h.input.workbench;
    const failure = new Error(`Synthetic ${phase} checkpoint write failure`);
    h.input.workbench = async (args, contents) => {
      if (
        args[0] === "save-scan-artifact" &&
        args[4] === DEEP_SCAN_CHECKPOINT
      ) {
        const pass = JSON.parse(contents!).passes[0];
        if (
          pass?.scanId &&
          (pass.executionNotStarted === true) === (phase === "record")
        )
          throw failure;
      }
      return workbench(args, contents);
    };
    const error = await runDeepScans(h.input).catch((error: unknown) => error);
    expect(error).toBeInstanceOf(DeepScanRecoveryError);
    expect(error).not.toBeInstanceOf(DeepScanInputRecoveryError);
    expect((error as Error).message).toContain(failure.message);
    let cause = error;
    while (cause instanceof Error && cause.cause !== undefined)
      cause = cause.cause;
    expect(cause).toBe(failure);
    expect(h.calls.length - beforeCalls).toBe(phase === "consume" ? 0 : 1);
    const state = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect(state.passes[0]!.executionNotStarted).toBe(
      phase === "consume" ? true : undefined,
    );
    expect(state.costUnavailable).toBeUndefined();
    expect(state.terminalReason).toBeUndefined();
    expect([...h.records.values()][0]!.progress.status).toBe("running");
    expect(h.operations).not.toContain("fail-scan");
    if (phase === "record") {
      h.input.workbench = workbench;
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanCostTrackingError,
      );
      expect(h.calls).toHaveLength(1);
      expect(
        (await loadDeepScanCheckpoint(h.input.scanDir))!.costUnavailable,
      ).toBe(true);
    }
  },
);

test.each(["unmarked", "prior thread", "prior unknown cost"] as const)(
  "unstarted discovery proof does not excuse %s accounting",
  async (scenario) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
    h.input.scanOptions.requireCost = true;
    const childId = randomUUID();
    const directory = "artifacts/deep-scan/passes/pass-1";
    h.records.set(childId, {
      scanId: childId,
      scanDir: join(h.input.scanDir, directory),
      targetPath: h.input.repository,
      parentScanId: h.input.scanId,
      parentScanRole: "deep_pass",
      progress: { status: "running" },
      continuationThreadId:
        scenario === "prior thread" ? "prior-session" : null,
    });
    await h.write(
      DEEP_SCAN_CHECKPOINT,
      JSON.stringify({
        ...newDeepScanCheckpoint(h.input.startedAt),
        passes: [
          {
            directory,
            scanId: childId,
            ...(scenario === "unmarked" ? {} : { executionNotStarted: true }),
          },
        ],
        ...(scenario === "prior unknown cost" ? { costUnavailable: true } : {}),
      }),
    );
    h.input.historicalCost = async () => null;
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      ScanCostTrackingError,
    );
    expect(h.calls).toHaveLength(0);
    const state = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect(state.passes[0]!.executionNotStarted).toBe(
      scenario === "prior unknown cost" ? true : undefined,
    );
    if (scenario !== "prior thread") expect(state.costUnavailable).toBe(true);
  },
);

test("an attempted discovery never gains unstarted execution proof", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  h.input.scanOptions.requireCost = true;
  h.setRegistrationThreadId(null);
  h.setExecute(async () => {
    throw new DeepScanInputRecoveryError(
      "Synthetic later input rejection",
      h.input.scanDir,
      false,
    );
  });
  await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
    DeepScanInputRecoveryError,
  );
  expect(
    (await loadDeepScanCheckpoint(h.input.scanDir))!.passes[0]!
      .executionNotStarted,
  ).toBeUndefined();
  await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
    ScanCostTrackingError,
  );
  expect(h.calls).toHaveLength(1);
});

test.each([
  [undefined, true, undefined],
  [false, true, false],
  [true, true, true],
  [undefined, false, true],
] as const)(
  "unstarted reducer restores only new execution state (prior: %p, unstarted: %p)",
  async (prior, neverStarted, expected) => {
    const h = await fixture();
    await h.write(
      DEEP_SCAN_CHECKPOINT,
      JSON.stringify({
        ...newDeepScanCheckpoint(h.input.startedAt),
        mergeStarted: prior,
      }),
    );
    h.input.merge = async () => {
      throw new DeepScanInputRecoveryError(
        "Synthetic reducer input rejection",
        h.input.scanDir,
        neverStarted,
      );
    };
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      DeepScanInputRecoveryError,
    );
    const state = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect<unknown>(state.mergeStarted).toBe(expected);
    expect(state.mergeFailures).toBeUndefined();
    expect(state.terminalReason).toBeUndefined();
    expect(h.calls).toHaveLength(2);
    expect(
      [...h.records.values()].every(
        (record) => record.progress.status === "complete",
      ),
    ).toBe(true);
  },
);

test("unstarted reducer rollback write failure retains prior execution uncertainty", async () => {
  const h = await fixture();
  let rejected = false;
  h.input.merge = async () => {
    rejected = true;
    throw new DeepScanInputRecoveryError(
      "Synthetic reducer input rejection",
      h.input.scanDir,
      true,
    );
  };
  const workbench = h.input.workbench;
  const failure = new Error(
    "Synthetic reducer rollback checkpoint write failure",
  );
  h.input.workbench = async (args, contents) => {
    if (
      rejected &&
      args[0] === "save-scan-artifact" &&
      args[4] === DEEP_SCAN_CHECKPOINT &&
      JSON.parse(contents!).mergeStarted !== true
    )
      throw failure;
    return workbench(args, contents);
  };
  const error = await runDeepScans(h.input).catch((error: unknown) => error);
  expect(error).toBeInstanceOf(DeepScanRecoveryError);
  expect(error).not.toBeInstanceOf(DeepScanInputRecoveryError);
  expect((error as Error).message).toContain(failure.message);
  let cause = error;
  while (cause instanceof Error && cause.cause !== undefined)
    cause = cause.cause;
  expect(cause).toBe(failure);
  const state = (await loadDeepScanCheckpoint(h.input.scanDir))!;
  expect(state.mergeStarted).toBe(true);
  expect(state.terminalReason).toBeUndefined();
  expect(h.calls).toHaveLength(2);
  expect(h.operations).not.toContain("fail-scan");
});

test("discovery usage retains pass keys across saved unpriced receipts", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 2 });
  const observed: Array<[string, Readonly<ScanTokenUsage>]> = [];
  h.input.onUsage = (key, usage) => observed.push([key, usage]);
  h.setExecute(async (options) => {
    options.onUsage?.(tokenUsage({ input_tokens: 7, output_tokens: 1 })!);
    options.onUsage?.(tokenUsage({ input_tokens: 11, output_tokens: 2 })!);
  });
  await runDeepScans(h.input);
  const keys = [...new Set(observed.map(([key]) => key))];
  expect(keys).toHaveLength(2);
  expect(observed.map(([, usage]) => usage.input_tokens)).toEqual([
    7, 11, 11, 7, 11, 11,
  ]);
  for (const record of h.records.values()) {
    Object.assign(record, {
      cost: null,
      usage: {
        coverage: "complete",
        inputTokens: 17,
        cachedInputTokens: 3,
        cacheWriteInputTokens: 0,
        outputTokens: 2,
        reasoningOutputTokens: 1,
      },
    });
  }
  observed.length = 0;
  const refreshed: string[] = [];
  h.input.historicalCost = async (_thread, directory) => {
    refreshed.push(directory!);
    return null;
  };
  await runDeepScans(h.input);
  expect(refreshed.sort()).toEqual(
    [...h.records.values()].map((record) => record.scanDir).sort(),
  );
  expect(h.calls).toHaveLength(2);
  expect(observed.map(([key]) => key).sort()).toEqual(keys.sort());
  expect(observed.map(([, usage]) => usage.input_tokens)).toEqual([17, 17]);
  for (const record of h.records.values())
    record.cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 17,
      output_tokens: 2,
    });
  h.input.scanOptions.maxCostUsd = 100;
  h.input.historicalCost = async (_thread, _directory, optionalUsageOnly) => {
    expect(optionalUsageOnly).toBe(true);
    throw new Error("Synthetic saved usage read failure");
  };
  await runDeepScans(h.input);
  expect(h.controller.signal.aborted).toBe(false);
});

test.each(["Original discovery assumptions.", undefined])(
  "freezes discovery context across interrupted and new passes: %p",
  async (scanPrompt) => {
    const h = await fixture({
      workers: 1,
      maxDiscoveryRuns: 2,
      stopAfterNoNew: 3,
    });
    h.input.scanOptions.scanPrompt = scanPrompt;
    const interruption = new ScanTransportClosedError("Synthetic restart.");
    h.setExecute(async () => {
      h.controller.abort(interruption);
      throw interruption;
    });
    await expect(runDeepScans(h.input)).rejects.toThrow(interruption.message);
    const original = h.calls[0]!;
    h.input.scanOptions.scanPrompt = "Changed context after restart.";
    h.input.signal = new AbortController().signal;
    h.setExecute(async () => {});
    await runDeepScans(h.input);
    expect(h.calls).toHaveLength(3);
    expect(h.calls[1]!.outputDir).toBe(original.outputDir);
    expect(h.calls[1]!.resumeScanId).toBeDefined();
    expect(h.calls[2]!.outputDir).not.toBe(original.outputDir);
    expect(h.calls.map((call) => call.scanPrompt)).toEqual([
      scanPrompt,
      scanPrompt,
      scanPrompt,
    ]);
    const checkpoint = JSON.parse(
      await readFile(join(h.input.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
    );
    expect(checkpoint.discoveryUserContext).toBe(scanPrompt ?? null);
  },
);

test.each(
  (["discovery", "merge"] as const).flatMap((role) =>
    [false, true].flatMap((resumed) =>
      ["exit", "rpc"].map((failure) => ({ role, resumed, failure })),
    ),
  ),
)(
  "transient preflight consumes a discovery slot or retries the reducer: %j",
  async ({ role, resumed, failure }) => {
    const h = await fixture({
      workers: role === "discovery" ? 1 : 2,
      maxDiscoveryRuns: 2,
    });
    const executable = join(h.input.scanDir, "synthetic-codex.exe");
    const script = join(h.input.scanDir, "preflight.cjs");
    const attempted = join(h.input.scanDir, "preflight-attempted");
    const config = {
      default_permissions: "fixture",
      permissions: {
        fixture: {
          filesystem: { ":root": "read" },
          network: { enabled: false },
        },
      },
    };
    await writeFile(
      script,
      `
      const fs = require("node:fs");
      if (process.argv.includes("app-server")) {
        const first = !fs.existsSync(${JSON.stringify(attempted)});
        fs.writeFileSync(${JSON.stringify(attempted)}, "attempted");
        require("node:readline").createInterface({ input: process.stdin }).on("line", line => {
          const request = JSON.parse(line);
          if (request.id === undefined) return;
          if (first && request.method === "config/read") {
            if (${JSON.stringify(failure)} === "exit") process.exit(1);
            console.log(JSON.stringify({ id: request.id, error: { code: -32603, message: "Synthetic transient error" } }));
            return;
          }
          const result = request.method === "initialize" ? {}
            : request.method === "config/read" ? { config: ${JSON.stringify(config)} }
            : { data: [{ id: "fixture", allowed: true }], nextCursor: null };
          console.log(JSON.stringify({ id: request.id, result }));
        });
      } else {
        process.stdin.resume();
        process.stdin.on("end", () => {
          console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-thread" }));
          console.log(JSON.stringify({ type: "turn.completed", usage: null }));
        });
      }
      `,
    );
    const launches: string[][] = [];
    const spawning = spyOn(childProcess, "spawn").mockImplementation(
      fixtureSpawn(executable, script, (_child, args) => launches.push(args)),
    );
    const codex = createPermissionCheckedCodex({
      codexPathOverride: executable,
      env: { PATH: process.env["PATH"] ?? "" },
      config,
    });
    const threadOptions = { workingDirectory: h.input.scanDir };
    const thread = resumed
      ? codex.resumeThread("synthetic-thread", threadOptions)
      : codex.startThread(threadOptions);
    const execute = async (signal: AbortSignal) =>
      readCodexTurn({
        thread,
        events: (await thread.runStreamed("Inert fixture.", { signal })).events,
      });
    h.setExecute(async (options) => {
      if (role === "discovery") await execute(options.signal!);
    });
    const merge = h.input.merge;
    if (role === "merge")
      h.input.merge = async (prompt, signal) => {
        await execute(signal);
        return merge(prompt, signal);
      };
    try {
      const state = await runDeepScans(h.input);
      expect(launches.map((args) => args.includes("app-server"))).toEqual([
        true,
        true,
        false,
      ]);
      expect(launches[2]!.includes("resume")).toBe(resumed);
      expect(h.calls).toHaveLength(2);
      expect(new Set(h.calls.map((call) => call.outputDir)).size).toBe(2);
      expect(state.passes).toHaveLength(2);
      expect(state.mergedScanIds).toHaveLength(role === "discovery" ? 1 : 2);
      expect(
        [...h.records.values()].map((scan) => scan.progress.status),
      ).toEqual(
        role === "discovery"
          ? ["failed", "complete"]
          : ["complete", "complete"],
      );
      expect(state.consecutiveErrors).toBe(0);
      expect(state.mergeFailures ?? 0).toBe(0);
      expect(h.publications.at(-1)!.findings).toHaveLength(
        role === "merge" ? 2 : 1,
      );
    } finally {
      spawning.mockRestore();
    }
  },
);

test("composes each child once, hydrates history once and persists compact aggregate references", async () => {
  const h = await fixture({ maxDiscoveryRuns: 4 });
  const state = await runDeepScans(h.input);
  expect(h.calls).toHaveLength(4);
  expect(h.metrics()).toEqual({ merges: 3, closes: 4 });
  expect(
    h.operations.filter((command) => command === "list-scans"),
  ).toHaveLength(1);
  expect(state.mergedScanIds).toHaveLength(4);
  expect(state.terminalReason).toBe("capped");
  const disk = JSON.parse(
    await readFile(join(h.input.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
  );
  expect(disk.version).toBe(3);
  expect(disk.aggregate).toBeUndefined();
  expect(disk.aggregatePath).toMatch(/aggregates\/[a-f0-9]{64}\.json$/);
  expect((await loadDeepScanCheckpoint(h.input.scanDir))!.aggregate).toEqual(
    state.aggregate,
  );
  expect(h.publications.at(-1)!.findings).toHaveLength(4);
  expect(
    h.publications.at(-1)!.findings[0]!.provenance.sourceFindings,
  ).toHaveLength(1);
});

test("pass bookkeeping reuses persisted aggregates across saves and resume", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 3 });
  const writes: string[] = [];
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    if (
      args[0] === "save-scan-artifact" &&
      args[4]!.startsWith("artifacts/deep-scan/aggregates/")
    )
      writes.push(args[4]!);
    return workbench(args, contents);
  };

  const state = await runDeepScans(h.input);
  expect(state.mergedScanIds).toHaveLength(3);
  expect(writes).toHaveLength(3);
  expect(new Set(writes).size).toBe(writes.length);
  expect((await loadDeepScanCheckpoint(h.input.scanDir))!.aggregate).toEqual(
    state.aggregate,
  );
  await runDeepScans(h.input);
  expect(writes).toHaveLength(3);
});

test.each([
  { phase: "aggregate", partial: false },
  { phase: "aggregate", partial: true },
  { phase: "accepted-checkpoint", partial: false },
  { phase: "merge-start", partial: false },
])(
  "merge persistence failures remain resumable (%p)",
  async ({ phase, partial }) => {
    const h = await fixture({
      workers: phase === "merge-start" ? 2 : 1,
      maxDiscoveryRuns: phase === "merge-start" ? 2 : 1,
    });
    const workbench = h.input.workbench;
    const persistenceFailure = new Error(
      "Synthetic one-shot merge persistence failure",
    );
    let failedPath: string | undefined;
    h.input.workbench = async (args, contents) => {
      if (!failedPath && args[0] === "save-scan-artifact") {
        const path = args[4]!;
        const checkpoint =
          path === DEEP_SCAN_CHECKPOINT ? JSON.parse(contents!) : null;
        const selected =
          phase === "aggregate"
            ? path.startsWith("artifacts/deep-scan/aggregates/")
            : phase === "accepted-checkpoint"
              ? checkpoint?.mergedScanIds.length > 0
              : checkpoint?.mergeStarted === true;
        if (selected) {
          failedPath = path;
          if (partial) await h.write(path, contents!);
          throw persistenceFailure;
        }
      }
      return workbench(args, contents);
    };
    let caught: unknown;
    try {
      await runDeepScans(h.input);
    } catch (error) {
      caught = error;
    }
    expect(failedPath).toBeDefined();
    expect(caught).toBeInstanceOf(DeepScanRecoveryError);
    expect((caught as Error).cause).toBe(persistenceFailure);
    const saved = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect(saved.terminalReason).toBeUndefined();
    expect(saved.pendingStop).toBeUndefined();
    expect(saved.mergeFailures ?? 0).toBe(0);
    expect(h.metrics().merges).toBe(0);
    expect(h.publications).toHaveLength(0);
    expect(
      [...h.records.values()].every(
        (record) => record.progress.status === "complete",
      ),
    ).toBe(true);
    const calls = h.calls.length;
    const resumed = await runDeepScans(h.input);
    expect(resumed.terminalReason).toBe("capped");
    expect(resumed.mergedScanIds).toHaveLength(calls);
    expect(h.publications.at(-1)!.findings).toHaveLength(calls);
    expect(h.calls).toHaveLength(calls);
    expect(h.metrics().merges).toBe(phase === "merge-start" ? 1 : 0);
  },
);

test.each([
  { findings: false, blocked: "merge-context.json" },
  { findings: true, blocked: "sources" },
  { findings: true, blocked: "merge-context.json" },
])(
  "merge source writes recover completed children after a filesystem failure (%p)",
  async ({ findings, blocked }) => {
    const h = await fixture();
    if (!findings) {
      const projectChild = h.input.projectChild;
      h.input.projectChild = async (...args) => {
        const child = await projectChild(...args);
        return {
          ...child,
          sourceFindings: [],
          draft: { ...child.draft, findings: [] },
        };
      };
    }
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    h.input.writer = await prepareScanArtifactRestorer(
      { python: python!, pluginRoot, environment: {} },
      h.input.scanDir,
    );
    const blockedPath = join(h.input.scanDir, "artifacts/deep-scan", blocked);
    await mkdir(dirname(blockedPath), { recursive: true, mode: 0o700 });
    if (blocked === "sources")
      await writeFile(blockedPath, "Synthetic temporary filesystem blocker");
    else await mkdir(blockedPath);

    const failure = await runDeepScans(h.input).catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(DeepScanRecoveryError);
    expect((failure as Error).cause).toBeInstanceOf(OutputDirectoryError);
    const saved = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect(saved.terminalReason).toBeUndefined();
    expect(saved.pendingStop).toBeUndefined();
    expect(saved.mergeFailures ?? 0).toBe(0);
    expect(h.metrics().merges).toBe(0);
    expect(h.publications).toHaveLength(0);
    expect(h.operations).not.toContain("fail-scan");
    expect(
      [...h.records.values()].map((record) => record.progress.status),
    ).toEqual(["complete", "complete"]);
    if (findings && blocked === "merge-context.json")
      expect(
        await readdir(join(h.input.scanDir, "artifacts/deep-scan/sources")),
      ).toHaveLength(2);

    await rm(blockedPath, { recursive: true });
    const resumed = await runDeepScans(h.input);
    expect(resumed.terminalReason).toBe("capped");
    expect(resumed.mergedScanIds).toHaveLength(2);
    expect(h.calls).toHaveLength(2);
    expect(h.metrics().merges).toBe(findings ? 1 : 0);
    expect(h.publications.at(-1)!.findings).toHaveLength(findings ? 2 : 0);
    expect(Object.values(resumed.aggregate!.sourceFindings)).toEqual(
      findings
        ? [...h.projected.values()].flatMap((child) => child.sourceFindings)
        : [],
    );
    expect((await loadDeepScanCheckpoint(h.input.scanDir))!.aggregate).toEqual(
      resumed.aggregate,
    );
  },
);

test.each(["sources", "aggregate", "accepted-checkpoint"] as const)(
  "a discovery deadline keeps %s persistence recoverable",
  async (phase) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 2 });
    const writer = h.input.writer;
    const disconnected = new ScanTransportClosedError(
      "Synthetic disconnect before merging the completed child",
    );
    h.input.writer = {
      ...writer,
      async restoreMany() {
        throw disconnected;
      },
    };
    await expect(runDeepScans(h.input)).rejects.toBe(disconnected);
    const checkpoint = JSON.parse(
      await readFile(join(h.input.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
    );
    checkpoint.startedAt = new Date(Date.now() - 2 * 3_600_000).toISOString();
    await h.write(DEEP_SCAN_CHECKPOINT, JSON.stringify(checkpoint));
    expect(h.calls).toHaveLength(1);
    expect([...h.records.values()][0]!.progress.status).toBe("complete");

    const failure = new Error(
      "Synthetic one-shot persistence failure after deadline",
    );
    let injected = false;
    h.input.writer = {
      ...writer,
      async restoreMany(artifacts) {
        if (phase === "sources" && !injected) {
          injected = true;
          throw failure;
        }
        return writer.restoreMany(artifacts);
      },
    };
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (!injected && args[0] === "save-scan-artifact") {
        const selected =
          phase === "aggregate"
            ? args[4]!.startsWith("artifacts/deep-scan/aggregates/")
            : phase === "accepted-checkpoint" &&
              args[4] === DEEP_SCAN_CHECKPOINT &&
              JSON.parse(contents!).mergedScanIds.length > 0;
        if (selected) {
          injected = true;
          throw failure;
        }
      }
      return workbench(args, contents);
    };
    const caught = await runDeepScans(h.input).catch((error: unknown) => error);
    expect(injected).toBe(true);
    expect(caught).toBeInstanceOf(DeepScanRecoveryError);
    expect((caught as Error).cause).toBe(failure);
    expect(h.input.signal.aborted).toBe(false);
    const saved = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    expect(saved.terminalReason).toBeUndefined();
    expect(saved.pendingStop).toBeUndefined();
    expect(saved.mergeFailures ?? 0).toBe(0);
    expect(h.operations).not.toContain("fail-scan");
    expect(h.publications).toHaveLength(0);

    const resumed = await runDeepScans(h.input);
    expect(resumed.terminalReason).toBe("capped");
    expect(resumed.mergedScanIds).toEqual([...h.records.keys()]);
    expect(h.calls).toHaveLength(1);
    expect(h.metrics().merges).toBe(0);
    expect(h.publications.at(-1)!.findings).toHaveLength(1);
    expect([...h.records.values()][0]!.progress.status).toBe("complete");
  },
);

test.each([
  { phase: "projection", requireCost: true },
  { phase: "completed-checkpoint", requireCost: false },
  { phase: "registration-checkpoint", requireCost: false },
  { phase: "registration-checkpoint", requireCost: true },
])(
  "a deadline during child recovery preserves the failure: %j",
  async ({ phase, requireCost }) => {
    const h = await fixture({ workers: 1, stopAfterConsecutiveErrors: 3 });
    h.input.scanOptions.requireCost = requireCost;
    if (phase === "completed-checkpoint")
      h.setExecute(async () => {
        if (h.calls.length === 1)
          throw new Error("Synthetic first child failure");
      });
    const failure = new Error("Synthetic one-shot child recovery failure");
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
    let injected = false;
    const interrupt = () => {
      injected = true;
      clock.mockReturnValue(now + 3_600_000);
      expect(expire).toBeDefined();
      expire!();
      expect(h.calls.at(-1)!.signal!.aborted).toBe(true);
      expect(h.input.signal.aborted).toBe(false);
      throw failure;
    };
    const projectChild = h.input.projectChild;
    h.input.projectChild = async (...args) => {
      if (!injected && phase === "projection") interrupt();
      return projectChild(...args);
    };
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (
        !injected &&
        args[0] === "save-scan-artifact" &&
        args[4] === DEEP_SCAN_CHECKPOINT
      ) {
        const saved = JSON.parse(contents!);
        if (
          phase === "registration-checkpoint" &&
          saved.passes.some(
            (pass: { scanId?: string }) => pass.scanId !== undefined,
          )
        )
          interrupt();
        if (
          phase === "completed-checkpoint" &&
          saved.consecutiveErrors === 0 &&
          [...h.records.values()].some(
            (record) => record.progress.status === "complete",
          )
        )
          interrupt();
      }
      return workbench(args, contents);
    };
    try {
      const caught = await runDeepScans(h.input).catch(
        (error: unknown) => error,
      );
      expect(injected).toBe(true);
      expect(h.publications).toHaveLength(0);
      const launches = phase === "completed-checkpoint" ? 2 : 1;
      expect(h.calls).toHaveLength(launches);
      const saved = (await loadDeepScanCheckpoint(h.input.scanDir))!;
      if (phase === "registration-checkpoint" && requireCost) {
        expect(caught).toBeInstanceOf(ScanCostTrackingError);
        expect(saved.terminalReason).toBe("failed");
        expect([...h.records.values()][0]!.progress.status).toBe("failed");
        await expect(runDeepScans(h.input)).rejects.toThrow(
          "saved Deep Scan is failed",
        );
      } else {
        expect(caught).toBeInstanceOf(DeepScanRecoveryError);
        expect((caught as Error).cause).toBe(failure);
        expect(saved.terminalReason).toBeUndefined();
        const registering = phase === "registration-checkpoint";
        expect(saved.pendingStop?.reason).toBe(
          registering ? "capped" : undefined,
        );
        expect([...h.records.values()].at(-1)!.progress.status).toBe(
          registering ? "failed" : "complete",
        );
        const resumed = await runDeepScans(h.input);
        expect(resumed.terminalReason).toBe("capped");
        expect(resumed.mergedScanIds).toHaveLength(registering ? 0 : 1);
        expect(h.publications.at(-1)!.findings).toHaveLength(
          registering ? 0 : 1,
        );
        expect(resumed.pendingStop).toBeUndefined();
      }
      expect(h.calls).toHaveLength(launches);
      expect(h.metrics().merges).toBe(0);
      expect(
        h.operations.filter((operation) => operation === "fail-scan"),
      ).toHaveLength(phase === "projection" ? 0 : 1);
    } finally {
      clock.mockRestore();
      timer.mockRestore();
    }
  },
);

test("a single first child needs no model merge", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  await runDeepScans(h.input);
  expect(h.metrics()).toEqual({ merges: 0, closes: 1 });
});

test.each([false, true])(
  "compatible empty initial workers finish without a reducer (context: %p)",
  async (withContext) => {
    const h = await fixture();
    const projectChild = h.input.projectChild;
    h.input.projectChild = async (...args) => {
      const child = await projectChild(...args);
      return {
        ...child,
        sourceFindings: [],
        draft: {
          ...child.draft,
          findings: [],
          ...(withContext
            ? {
                scope: { summary: "Shared synthetic scope" },
                threatModel: { summary: "Shared synthetic context" },
              }
            : {}),
        },
      };
    };
    h.input.merge = async () => {
      throw new Error("An empty compatible batch must not need a reducer.");
    };
    const state = await runDeepScans(h.input);
    expect(h.calls).toHaveLength(2);
    expect(state.mergedScanIds).toHaveLength(2);
    expect(state.noNewStreak).toBe(2);
    expect(state.mergeStarted).toBeUndefined();
    expect(state.terminalReason).toBe("capped");
    expect(h.publications.at(-1)!.findings).toEqual([]);
    if (withContext)
      expect(h.publications.at(-1)).toMatchObject({
        scope: { summary: "Shared synthetic scope" },
        threatModel: { summary: "Shared synthetic context" },
      });
    expect((await loadDeepScanCheckpoint(h.input.scanDir))!.aggregate).toEqual(
      state.aggregate,
    );
  },
);

test("projection failure never reexecutes a completed child", async () => {
  const h = await fixture({ workers: 1 });
  h.input.projectChild = async () => {
    throw new Error("synthetic projection failure");
  };
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "synthetic projection failure",
  );
  expect(h.calls).toHaveLength(1);
  expect(h.operations).not.toContain("fail-scan");
});

test("accepted matches replay publication without repeating matching or losing evidence", async () => {
  const h = await fixture();
  let matchingTurns = 0;
  let response: unknown;
  h.input.merge = async (prompt) => {
    matchingTurns++;
    const catalogue = JSON.parse(prompt.split("\n").at(-1)!);
    if (catalogue.findings) {
      response = {
        matches: [
          {
            beforeOccurrenceIds: catalogue.findings.before.map(
              (finding: { occurrenceId: string }) => finding.occurrenceId,
            ),
            afterOccurrenceIds: catalogue.findings.after.map(
              (finding: { occurrenceId: string }) => finding.occurrenceId,
            ),
            confidence: "high",
            reason: "The same control and correction appear in both scans.",
          },
        ],
        uncertain: [],
        related: [],
        request: null,
      };
    }
    return response;
  };
  const publicationCause = new Error("ENOSPC: synthetic publication failure");
  h.input.publish = async () => {
    throw publicationCause;
  };
  const publicationFailure = await runDeepScans(h.input).catch(
    (error: unknown) => error,
  );
  expect(publicationFailure).toBeInstanceOf(DeepScanPublicationError);
  expect((publicationFailure as Error).message).toContain(
    publicationCause.message,
  );
  expect((publicationFailure as Error).cause).toBe(publicationCause);
  const checkpoint = await loadDeepScanCheckpoint(h.input.scanDir);
  expect(checkpoint!.mergedScanIds).toHaveLength(2);
  expect(checkpoint!.aggregate!.findings).toHaveLength(1);
  expect(
    checkpoint!.aggregate!.findings[0]!.provenance.sourceFindingIds,
  ).toHaveLength(2);
  expect(checkpoint!.terminalReason).toBeUndefined();
  expect(matchingTurns).toBeGreaterThan(0);
  const acceptedTurns = matchingTurns;
  h.input.merge = async () => {
    throw new Error("Accepted matching must not run again.");
  };
  h.input.publish = async (draft) => {
    h.publications.push(draft);
  };
  await runDeepScans(h.input);
  expect(h.calls).toHaveLength(2);
  expect(matchingTurns).toBe(acceptedTurns);
  expect(h.publications.at(-1)!.findings).toHaveLength(1);
  expect(h.publications.at(-1)!.findings[0]!.provenance.sourceFindings).toEqual(
    Object.entries(checkpoint!.aggregate!.sourceFindings).map(
      ([id, finding]) => ({ id, finding }),
    ),
  );
});

test("invalid matching leaves accepted findings and source evidence unchanged", async () => {
  const h = await fixture({
    workers: 1,
    maxDiscoveryRuns: 2,
    stopAfterConsecutiveErrors: 1,
  });
  let accepted: Awaited<ReturnType<typeof loadDeepScanCheckpoint>>;
  h.input.publish = async (draft) => {
    h.publications.push(draft);
    accepted = await loadDeepScanCheckpoint(h.input.scanDir);
  };
  h.input.merge = async (prompt) => {
    const catalogue = JSON.parse(prompt.split("\n").at(-1)!);
    return {
      matches: [
        {
          beforeOccurrenceIds: ["missing-source"],
          afterOccurrenceIds: catalogue.findings.after.map(
            (finding: { occurrenceId: string }) => finding.occurrenceId,
          ),
          confidence: "high",
          reason: "Synthetic invalid match.",
        },
      ],
      uncertain: [],
      related: [],
      request: null,
    };
  };
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "Scan comparison referenced an unknown before occurrence.",
  );
  const saved = await loadDeepScanCheckpoint(h.input.scanDir);
  expect(accepted!.mergedScanIds).toHaveLength(1);
  expect(saved!.mergedScanIds).toEqual(accepted!.mergedScanIds);
  for (const field of ["findings", "sourceFindings", "revisions"] as const)
    expect(saved!.aggregate![field]).toEqual(accepted!.aggregate![field]);
  expect(Object.keys(saved!.aggregate!.sourceFindings)).toHaveLength(1);
  expect(saved!.aggregate!.coverage!).not.toHaveProperty("completeness");
  expect(saved!.mergeFailures).toBe(1);
  expect(h.calls).toHaveLength(2);
  expect(h.publications).toHaveLength(1);
});

test("corrects invalid matching in the same conversation using the persisted retry budget", async () => {
  const h = await fixture();
  let turns = 0;
  h.input.merge = async (prompt) => {
    if (++turns === 1) {
      const catalogue = JSON.parse(prompt.split("\n").at(-1)!);
      return {
        matches: [
          {
            beforeOccurrenceIds: ["missing-source"],
            afterOccurrenceIds: [catalogue.findings.after[0].occurrenceId],
            confidence: "high",
            reason: "Synthetic invalid match.",
          },
        ],
        uncertain: [],
        related: [],
        request: null,
      };
    }
    expect(prompt).toContain("unknown before occurrence");
    expect((await loadDeepScanCheckpoint(h.input.scanDir))!.mergeFailures).toBe(
      1,
    );
    return { matches: [], uncertain: [], related: [], request: null };
  };
  const state = await runDeepScans(h.input);
  expect(turns).toBe(2);
  expect(h.calls).toHaveLength(2);
  expect(state.mergedScanIds).toHaveLength(2);
  expect(Object.keys(state.aggregate!.sourceFindings)).toHaveLength(2);
});

test.each(["invalid", "missing"])(
  "corrects %s context using the persisted merge retry budget",
  async (response) => {
    const h = await fixture();
    const project = h.input.projectChild;
    h.input.projectChild = async (...args) => {
      const child = await project(...args);
      child.draft.threatModel = { summary: child.scanId };
      return child;
    };
    let contextTurns = 0;
    h.input.merge = async (prompt, _signal, schema) => {
      if (schema)
        return { matches: [], uncertain: [], related: [], request: null };
      if (++contextTurns === 1)
        return response === "invalid" ? { threatModel: { summary: 12 } } : {};
      expect(prompt).toContain(
        response === "invalid" ? "Invalid scan merge" : "ambiguous threatModel",
      );
      const checkpoint = await loadDeepScanCheckpoint(h.input.scanDir);
      expect(checkpoint!.mergeFailures).toBe(1);
      expect(checkpoint!.aggregate).toBeNull();
      return { threatModel: { summary: "Combined context" } };
    };
    const state = await runDeepScans(h.input);
    expect(contextTurns).toBe(2);
    expect(h.calls).toHaveLength(2);
    expect(state.mergedScanIds).toHaveLength(2);
    expect(Object.keys(state.aggregate!.sourceFindings)).toHaveLength(2);
    expect(h.publications.at(-1)!.threatModel).toEqual({
      summary: "Combined context",
    });
  },
);

test.each(["capped", "expired"] as const)(
  "publication recovery preserves %s discovery after deadline child failures",
  async (stopping) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 3 });
    h.input.scanOptions.requireCost = true;
    h.input.publish = async () => {
      throw new Error("synthetic publication failure");
    };
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      DeepScanPublicationError,
    );
    const checkpoint = JSON.parse(
      await readFile(join(h.input.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
    );
    checkpoint.startedAt = new Date(Date.now() - 2 * 3_600_000).toISOString();
    if (stopping === "capped") checkpoint.terminalReason = "capped";
    const cost = [...h.records.values()][0]!.cost!;
    const stoppedChildren: SavedScanRecord[] = [];
    for (let index = 2; index <= 3; index++) {
      const scanId = randomUUID();
      const directory = `artifacts/deep-scan/passes/pass-${index}`;
      checkpoint.passes.push({ scanId, directory });
      const record: SavedScanRecord = {
        scanId,
        scanDir: join(h.input.scanDir, directory),
        targetPath: h.input.repository,
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        progress: { status: "failed" },
        completedAt: new Date(Date.now() + index).toISOString(),
        cost,
      };
      h.records.set(scanId, record);
      stoppedChildren.push(record);
    }
    await h.write(DEEP_SCAN_CHECKPOINT, JSON.stringify(checkpoint));
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      DeepScanPublicationError,
    );
    expect(
      (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
    ).toBe("capped");
    h.input.publish = async (draft) => {
      h.publications.push(draft);
    };
    const state = await runDeepScans(h.input);
    expect(state.terminalReason).toBe("capped");
    expect(h.publications.at(-1)!.findings).toHaveLength(1);
    expect(h.publications.at(-1)!.coverage!).not.toHaveProperty("completeness");
    expect([...h.costs.values()]).toEqual([cost, cost, cost]);
    expect(h.calls).toHaveLength(1);
    expect(h.metrics().merges).toBe(0);

    stoppedChildren[0]!.cost = null;
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      ScanCostTrackingError,
    );
    expect(h.calls).toHaveLength(1);
    expect(h.publications).toHaveLength(1);
  },
);

test("publication interrupted by cancellation terminalizes accepted output", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 2 });
  const cancellation = new Error("synthetic caller cancellation");
  h.input.publish = async () => {
    h.controller.abort(cancellation);
    throw new Error("synthetic interrupted publication process");
  };
  await expect(runDeepScans(h.input)).rejects.toBe(cancellation);
  const checkpoint = await loadDeepScanCheckpoint(h.input.scanDir);
  expect(checkpoint!.terminalReason).toBe("canceled");
  expect(checkpoint!.mergedScanIds).toHaveLength(1);
  expect(checkpoint!.aggregate!.findings).toHaveLength(1);
  h.input.signal = new AbortController().signal;
  await expect(runDeepScans(h.input)).rejects.toThrow("is canceled");
  expect(h.calls).toHaveLength(1);
});

test.each(["failed", "canceled"] as const)(
  "rejects %s resume without accounting or writes",
  async (terminalReason) => {
    const h = await fixture();
    await h.write(
      DEEP_SCAN_CHECKPOINT,
      JSON.stringify({
        ...newDeepScanCheckpoint(h.input.startedAt),
        terminalReason,
      }),
    );
    await expect(runDeepScans(h.input)).rejects.toThrow(`is ${terminalReason}`);
    expect(h.calls).toHaveLength(0);
    expect(h.operations).toHaveLength(0);
    expect(h.costs.size).toBe(0);
  },
);

test.each([1, 2])("rejects retired checkpoint version %i", async (version) => {
  const h = await fixture();
  await h.write(
    DEEP_SCAN_CHECKPOINT,
    JSON.stringify({ ...newDeepScanCheckpoint(h.input.startedAt), version }),
  );
  await expect(runDeepScans(h.input)).rejects.toThrow("original version");
  expect(h.calls).toHaveLength(0);
});

test("failed execution consumes its reserved slot once and honors the error limit", async () => {
  const h = await fixture({
    workers: 1,
    maxDiscoveryRuns: 10,
    stopAfterConsecutiveErrors: 2,
  });
  h.setExecute(async () => {
    throw new Error("synthetic execution failure");
  });
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "consecutive error limit",
  );
  expect(h.calls).toHaveLength(2);
  expect(h.metrics().closes).toBe(2);
  expect((await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason).toBe(
    "failed",
  );
});

test("permission errors stop discovery immediately", async () => {
  const h = await fixture({ workers: 1 });
  h.setExecute(async () => {
    throw new ScanPermissionError("synthetic denied profile");
  });
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "synthetic denied profile",
  );
  expect(h.calls).toHaveLength(1);
});

test.each(["child receipt", "previous work"])(
  "reports recovered spending before rejecting unknown cost from %s",
  async (unknown) => {
    const h = await fixture();
    h.input.scanOptions.requireCost = true;
    h.input.costUnavailable = unknown === "previous work";
    const receipt = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 30,
    })!;
    const checkpoint = newDeepScanCheckpoint(h.input.startedAt);
    for (let index = 1; index <= 2; index++) {
      const directory = `artifacts/deep-scan/passes/pass-${index}`;
      const scanId = randomUUID();
      checkpoint.passes.push({ directory, scanId });
      h.records.set(scanId, {
        scanId,
        scanDir: join(h.input.scanDir, directory),
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        targetPath: h.input.repository,
        progress: { status: "complete" },
        cost: index === 1 && unknown === "child receipt" ? null : receipt,
      });
    }
    await h.write(DEEP_SCAN_CHECKPOINT, JSON.stringify(checkpoint));

    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      ScanCostTrackingError,
    );
    expect(h.costs.get(checkpoint.passes[1]!.directory)).toEqual(receipt);
    expect(
      h.costs.get(
        unknown === "previous work"
          ? "previous-work"
          : checkpoint.passes[0]!.directory,
      ),
    ).toBeNull();
    expect(h.calls).toHaveLength(0);
    expect(h.metrics().merges).toBe(0);
  },
);

test.each([false, true])(
  "transport loss leaves the reserved pass resumable (signal aborted: %p)",
  async (abortSignal) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
    h.setExecute(async () => {
      const error = new ScanTransportClosedError("synthetic transport loss");
      if (abortSignal) h.controller.abort(error);
      throw error;
    });
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const state = await loadDeepScanCheckpoint(h.input.scanDir);
    expect(state!.passes).toHaveLength(1);
    expect(state!.terminalReason).toBeUndefined();
    expect(h.operations).not.toContain("fail-scan");
  },
);

test("merge transport loss does not consume retries or repeat completed passes", async () => {
  const h = await fixture();
  const merge = h.input.merge;
  const error = new ScanTransportClosedError("synthetic merge transport loss");
  let attempts = 0;
  h.input.merge = async () => {
    attempts += 1;
    throw error;
  };
  await expect(runDeepScans(h.input)).rejects.toBe(error);
  const checkpoint = await loadDeepScanCheckpoint(h.input.scanDir);
  expect(attempts).toBe(1);
  expect(checkpoint!.mergeFailures ?? 0).toBe(0);
  expect(checkpoint!.terminalReason).toBeUndefined();
  expect(h.operations).not.toContain("fail-scan");
  const calls = h.calls.length;
  h.input.merge = merge;
  await runDeepScans(h.input);
  expect(h.calls).toHaveLength(calls);
  expect(h.publications.at(-1)!.findings).toHaveLength(2);
});

const runtimeRefusals = [
  "Request blocked by cyberPolicy.",
  "Request flagged for possible cybersecurity risk.",
  "Request flagged for potentially high-risk cyber activity.",
  "Request rejected: cyber_policy.",
  "cyber_policy",
  "Quota exceeded. Check your plan and billing details.",
  "You’ve hit your usage limit. Try again later.",
  "You’ve hit your usage limit for synthetic-model. Try again later.",
];

test.each(runtimeRefusals)(
  "stops discovery after runtime refusal %s",
  async (message) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 3 });
    const failure = new Error(message);
    h.setExecute(async () => {
      throw failure;
    });
    await expect(runDeepScans(h.input)).rejects.toBe(failure);
    expect(h.calls).toHaveLength(1);
    expect(
      (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
    ).toBe("failed");
  },
);

test.each([...runtimeRefusals, "SDK parser", "schema"])(
  "distinguishes a %s from policy-like diagnostic data during merging",
  async (kind) => {
    const h = await fixture();
    const runtimeRefusal = kind !== "SDK parser" && kind !== "schema";
    let failure: unknown = new Error(
      "findings.findings[0].severity.level: unsupported severity: cyber_policy",
    );
    if (kind !== "schema") {
      const thread = new Codex({
        codexPathOverride: process.execPath,
      }).startThread();
      const executable = thread as unknown as {
        _exec: { run(): AsyncGenerator<string> };
      };
      executable._exec.run = async function* () {
        yield runtimeRefusal
          ? JSON.stringify({
              type: "turn.failed",
              error: { message: kind },
            })
          : '{"type":"item.completed","item":{"command":"cat cyber_policy.py","output":"truncated';
      };
      try {
        await readCodexTurn({
          thread,
          events: (await thread.runStreamed("Synthetic stream.")).events,
        });
        throw new Error("Expected synthetic stream failure");
      } catch (error) {
        failure = error;
      }
      if (kind === "SDK parser")
        expect((failure as Error).cause).toBeInstanceOf(SyntaxError);
    }
    const merge = h.input.merge;
    let attempts = 0;
    h.input.merge = async (...args) => {
      if (++attempts === 1) throw failure;
      return merge(...args);
    };
    if (runtimeRefusal) {
      await expect(runDeepScans(h.input)).rejects.toBe(failure);
      expect(attempts).toBe(1);
    } else {
      const state = await runDeepScans(h.input);
      expect(state.mergedScanIds).toHaveLength(2);
      expect(attempts).toBe(2);
    }
    expect(h.calls).toHaveLength(2);
  },
);
test("a failed registered pass without a final receipt stops required-cost discovery", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 3 });
  h.input.scanOptions.requireCost = true;
  h.setExecute(async (options) => {
    // A live estimate does not replace the child's final saved receipt.
    options.onCost?.(
      estimateScanCost("gpt-6-astra", { input_tokens: 10, output_tokens: 3 })!,
    );
    throw new Error("synthetic execution failure");
  });
  await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
    ScanCostTrackingError,
  );
  expect(h.calls).toHaveLength(1);
  expect(h.costs.get("artifacts/deep-scan/passes/pass-1")).toBeNull();
  expect(
    [...h.records.values()].map((record) => record.progress.status),
  ).toEqual(["failed"]);
});

test.each([
  ["required missing receipt", true, "missing", false],
  ["required unreadable receipt", true, "unreadable", false],
  ["required final receipt", true, "known", false],
  ["optional missing receipt", false, "missing", false],
  ["caller cancellation", true, "missing", true],
] as const)(
  "deadline cancellation preserves accounting: %s",
  async (_scenario, requireCost, receipt, canceled) => {
    const h = await fixture({ workers: 1, maxTimeHours: 1 / 3_600_000 });
    h.input.scanOptions.requireCost = requireCost;
    const now = Date.now();
    h.input.startedAt = new Date(now).toISOString();
    const clock = spyOn(Date, "now").mockReturnValue(now);
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 10,
      output_tokens: 3,
    })!;
    const cancellation = new Error("synthetic caller cancellation");
    const workbench = h.input.workbench;
    h.input.workbench = async (args, input) => {
      if (receipt === "unreadable" && args[0] === "get-scan")
        throw new Error("synthetic final receipt read failure");
      return await workbench(args, input);
    };
    h.setExecute(async (options) => {
      options.onCost?.(cost);
      if (receipt === "known") [...h.records.values()][0]!.cost = cost;
      const aborted = new Promise<never>((_resolve, reject) => {
        options.signal!.addEventListener(
          "abort",
          () => reject(options.signal!.reason),
          { once: true },
        );
      });
      if (canceled) h.controller.abort(cancellation);
      else clock.mockReturnValue(now + 2);
      await aborted;
    });
    try {
      if (canceled) {
        await expect(runDeepScans(h.input)).rejects.toBe(cancellation);
        expect(h.publications).toHaveLength(0);
        expect(
          (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
        ).toBe("canceled");
      } else if (receipt === "unreadable") {
        await expect(runDeepScans(h.input)).rejects.toThrow("resume to retry");
        const checkpoint = await loadDeepScanCheckpoint(h.input.scanDir);
        expect(checkpoint!.terminalReason).toBeUndefined();
        expect(checkpoint!.pendingStop?.reason).toBe("capped");
        expect(h.publications).toHaveLength(0);
        h.input.workbench = workbench;
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
        expect(
          (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
        ).toBe("failed");
      } else if (requireCost && receipt !== "known") {
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
        expect(h.publications).toHaveLength(0);
        expect(
          (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
        ).toBe("failed");
      } else {
        expect((await runDeepScans(h.input)).terminalReason).toBe("capped");
        expect(h.publications).toHaveLength(1);
      }
      expect(h.calls).toHaveLength(1);
      expect(h.costs.get("artifacts/deep-scan/passes/pass-1")).toEqual(
        receipt === "known" ? cost : null,
      );
      expect(h.metrics().closes).toBe(1);
    } finally {
      clock.mockRestore();
    }
  },
);

test("a failed pass contributes its saved final receipt before the next pass", async () => {
  const h = await fixture({ workers: 1 });
  h.input.scanOptions.requireCost = true;
  const receipt = estimateScanCost("gpt-6-astra", {
    input_tokens: 100,
    output_tokens: 30,
  })!;
  h.setExecute(async () => {
    if (h.calls.length !== 1) return;
    [...h.records.values()][0]!.cost = receipt;
    throw new Error("synthetic execution failure");
  });
  await runDeepScans(h.input);
  expect(h.calls).toHaveLength(2);
  expect(h.costs.get("artifacts/deep-scan/passes/pass-1")).toEqual(receipt);
  expect(
    h.operations.filter((command) => command === "list-scans"),
  ).toHaveLength(1);
});

test("a completed child remains resumable after one checkpoint write fails", async () => {
  const h = await fixture({ workers: 1, stopAfterConsecutiveErrors: 3 });
  h.setExecute(async () => {
    if (h.calls.length === 1) throw new Error("Synthetic discovery failure");
  });
  const persistenceFailure = new Error("Synthetic one-shot checkpoint failure");
  const workbench = h.input.workbench;
  let injected = false;
  h.input.workbench = async (args, contents) => {
    if (
      !injected &&
      args[0] === "save-scan-artifact" &&
      args[4] === DEEP_SCAN_CHECKPOINT &&
      JSON.parse(contents!).consecutiveErrors === 0 &&
      [...h.records.values()].some(
        (record) => record.progress.status === "complete",
      )
    ) {
      injected = true;
      throw persistenceFailure;
    }
    return workbench(args, contents);
  };
  let caught: unknown;
  try {
    await runDeepScans(h.input);
  } catch (error) {
    caught = error;
  }
  expect(injected).toBe(true);
  expect(caught).toBeInstanceOf(DeepScanRecoveryError);
  expect((caught as Error).cause).toBe(persistenceFailure);
  expect((caught as Error).message).toContain(persistenceFailure.message);
  const saved = (await loadDeepScanCheckpoint(h.input.scanDir))!;
  expect(saved.terminalReason).toBeUndefined();
  expect(saved.pendingStop).toBeUndefined();
  expect(h.calls).toHaveLength(2);
  expect(
    [...h.records.values()].map((record) => record.progress.status),
  ).toEqual(["failed", "complete"]);
  expect(h.publications).toHaveLength(0);
  const resumed = await runDeepScans(h.input);
  expect(resumed.terminalReason).toBe("capped");
  expect(resumed.consecutiveErrors).toBe(0);
  expect(resumed.mergedScanIds).toEqual([
    [...h.records.values()].find(
      (record) => record.progress.status === "complete",
    )!.scanId,
  ]);
  expect(h.publications.at(-1)!.findings).toHaveLength(1);
  expect(h.calls).toHaveLength(2);
  expect(h.metrics().merges).toBe(0);
});

test("a failure before registration consumes one reserved discovery slot", async () => {
  const h = await fixture({
    workers: 1,
    maxDiscoveryRuns: 1,
    stopAfterConsecutiveErrors: 3,
  });
  let attempts = 0;
  h.input.createClient = () => ({
    async run() {
      attempts++;
      throw new Error("synthetic preparation failure");
    },
    async close() {},
  });
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "every discovery run failed",
  );
  expect(attempts).toBe(1);
  const state = await loadDeepScanCheckpoint(h.input.scanDir);
  expect(state!.passes).toHaveLength(1);
  expect(state!.passes[0]!.scanId).toBeUndefined();
  expect(state!.passes[0]!.failedBeforeRegistration).toBeString();
});

test("a sibling success cannot erase the consecutive-error stop during persistence", async () => {
  const h = await fixture({ stopAfterConsecutiveErrors: 1 });
  const failureSaving = Promise.withResolvers<void>();
  const siblingCompleted = Promise.withResolvers<void>();
  h.setExecute(async (options) => {
    if (options.outputDir!.endsWith("pass-1"))
      throw new Error("synthetic discovery failure");
    await failureSaving.promise;
  });
  const onCost = h.input.onCost;
  h.input.onCost = (key, cost) => {
    onCost(key, cost);
    if (key.endsWith("pass-2") && cost !== null) siblingCompleted.resolve();
  };
  const workbench = h.input.workbench;
  let heldFailure = false;
  h.input.workbench = async (args, contents) => {
    if (
      !heldFailure &&
      args[0] === "save-scan-artifact" &&
      args[4] === DEEP_SCAN_CHECKPOINT &&
      JSON.parse(contents!).consecutiveErrors === 1
    ) {
      heldFailure = true;
      failureSaving.resolve();
      await siblingCompleted.promise;
    }
    return workbench(args, contents);
  };

  await expect(runDeepScans(h.input)).rejects.toThrow(
    "consecutive error limit",
  );
  expect(h.calls).toHaveLength(2);
  expect(h.metrics().merges).toBe(0);
  expect((await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason).toBe(
    "failed",
  );
});

test.each(
  (["failed", "canceled"] as const).flatMap((status) =>
    [true, false].map((successLast) => [status, successLast] as const),
  ),
)(
  "resume orders saved %s children by completion time (success last: %p)",
  async (unsuccessful, successLast) => {
    const h = await fixture({ stopAfterConsecutiveErrors: 1 });
    const passes = (["complete", unsuccessful] as const).map(
      (status, index) => {
        const scanId = randomUUID();
        const directory = `artifacts/deep-scan/passes/pass-${index + 1}`;
        const scanDir = join(h.input.scanDir, directory);
        h.records.set(scanId, {
          scanId,
          scanDir,
          targetPath: h.input.repository,
          parentScanId: h.input.scanId,
          parentScanRole: "deep_pass",
          progress: { status },
          completedAt: new Date(
            Date.parse(h.input.startedAt) + (successLast ? 2 - index : index),
          ).toISOString(),
        });
        h.projected.set(scanId, {
          scanId,
          scanDir,
          sourceFindings: [],
          draft: {
            scanId: h.input.scanId,
            findings: [],
            coverage: semanticCoverage(),
          },
        });
        return { scanId, directory };
      },
    );
    await h.write(
      DEEP_SCAN_CHECKPOINT,
      JSON.stringify({
        ...newDeepScanCheckpoint(h.input.startedAt),
        passes,
        consecutiveErrors: successLast ? 1 : 0,
      }),
    );
    const run = runDeepScans(h.input);
    if (successLast) await run;
    else await expect(run).rejects.toThrow("consecutive error limit");
    expect(h.calls).toHaveLength(0);
    expect(
      (await loadDeepScanCheckpoint(h.input.scanDir))!.consecutiveErrors,
    ).toBe(successLast ? 0 : 1);
  },
);

test.each([false, true])(
  "a canceled final pass preserves only completed discovery (prior success: %p)",
  async (priorSuccess) => {
    const h = await fixture({
      workers: 1,
      maxDiscoveryRuns: priorSuccess ? 2 : 1,
    });
    const statuses = priorSuccess
      ? (["complete", "canceled"] as const)
      : (["canceled"] as const);
    const passes = statuses.map((status, index) => {
      const scanId = randomUUID();
      const directory = `artifacts/deep-scan/passes/pass-${index + 1}`;
      const scanDir = join(h.input.scanDir, directory);
      h.records.set(scanId, {
        scanId,
        scanDir,
        targetPath: h.input.repository,
        parentScanId: h.input.scanId,
        parentScanRole: "deep_pass",
        progress: { status },
        completedAt: new Date(
          Date.parse(h.input.startedAt) + index,
        ).toISOString(),
      });
      if (status === "complete") {
        const finding = semanticFinding({
          provenance: {
            source: "local_plugin",
            sourceFindingIds: [`${scanId}:0`],
          },
        });
        h.projected.set(scanId, {
          scanId,
          scanDir,
          sourceFindings: [finding],
          draft: {
            scanId: h.input.scanId,
            findings: [finding],
            coverage: semanticCoverage(),
          },
        });
      }
      return { scanId, directory };
    });
    await h.write(
      DEEP_SCAN_CHECKPOINT,
      JSON.stringify({ ...newDeepScanCheckpoint(h.input.startedAt), passes }),
    );
    const resumed = runDeepScans(h.input);
    if (priorSuccess) {
      expect(await resumed).toMatchObject({
        terminalReason: "capped",
        consecutiveErrors: 1,
      });
      expect(h.publications.at(-1)!.findings).toHaveLength(1);
      expect(h.publications.at(-1)!.coverage!.deferred).not.toHaveLength(0);
    } else {
      await expect(resumed).rejects.toThrow("every discovery run failed");
      expect(h.publications).toHaveLength(0);
      expect(
        (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
      ).toBe("failed");
    }
    expect(h.calls).toHaveLength(0);
    expect([...h.records.values()].at(-1)!.progress.status).toBe("canceled");
  },
);

test("resume retains preregistration failures in the consecutive-error limit", async () => {
  const h = await fixture({
    workers: 1,
    maxDiscoveryRuns: 3,
    stopAfterConsecutiveErrors: 2,
  });
  await h.write(
    DEEP_SCAN_CHECKPOINT,
    JSON.stringify({
      ...newDeepScanCheckpoint(h.input.startedAt),
      passes: [
        {
          directory: "artifacts/deep-scan/passes/pass-1",
          failedBeforeRegistration: new Date().toISOString(),
        },
      ],
    }),
  );
  let attempts = 0;
  h.input.createClient = () => ({
    async run(_repository, options) {
      attempts++;
      expect(options!.outputDir).toEndWith("pass-2");
      throw new Error("synthetic preparation failure");
    },
    async close() {},
  });
  await expect(runDeepScans(h.input)).rejects.toThrow(
    "consecutive error limit",
  );
  expect(attempts).toBe(1);
});

test("progress publication failure does not stop discovery", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  const workbench = h.input.workbench;
  const phases: string[] = [];
  h.input.workbench = async (args, input) => {
    if (args[0] === "update-progress") {
      phases.push(args.at(-1)!);
      throw new Error("synthetic optional progress failure");
    }
    return workbench(args, input);
  };
  await runDeepScans(h.input);
  expect(phases).toEqual(["discovery", "reporting"]);
  expect(h.calls).toHaveLength(1);
});

test("inter-batch merges keep discovery active until the stop decision", async () => {
  const h = await fixture({ workers: 2, maxDiscoveryRuns: 4 });
  const phases: string[] = [];
  const workbench = h.input.workbench;
  h.input.workbench = async (args, input) => {
    if (args[0] === "update-progress") {
      const phase = args.at(-1)!;
      phases.push(phase);
      if (phase === "reporting") expect(h.calls).toHaveLength(4);
    }
    return workbench(args, input);
  };
  h.setExecute(async () => {
    expect(phases.at(-1)).toBe("discovery");
    if (h.calls.length > 2) expect(h.metrics().merges).toBeGreaterThan(0);
  });
  const state = await runDeepScans(h.input);
  expect(state.terminalReason).toBe("capped");
  expect(h.metrics().merges).toBeGreaterThan(0);
  expect(phases).toEqual(["discovery", "reporting"]);
});

test("durable cancellation prevents later checkpoint writes before the next abort poll", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  const workbench = h.input.workbench;
  let stopped = false;
  let saved = "";
  h.input.workbench = async (args, contents) => {
    if (stopped && args[0] === "save-scan-artifact")
      throw new Error("The scan stopped; its artifacts cannot be modified.");
    return workbench(args, contents);
  };
  h.setExecute(async () => {
    saved = await readFile(join(h.input.scanDir, DEEP_SCAN_CHECKPOINT), "utf8");
    stopped = true;
  });
  await expect(runDeepScans(h.input)).rejects.toThrow("The scan stopped");
  expect(h.input.signal.aborted).toBe(false);
  expect(
    await readFile(join(h.input.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
  ).toBe(saved);
});

test("only the parent owns the workflow across fresh and resumed passes", async () => {
  const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
  h.input.scanOptions.workflowId = "synthetic-parent-workflow";
  const transport = new ScanTransportClosedError("synthetic disconnected host");
  h.setExecute(async () => {
    throw transport;
  });
  await expect(runDeepScans(h.input)).rejects.toBe(transport);
  h.setExecute(async () => {});
  await runDeepScans(h.input);
  expect(h.calls).toHaveLength(2);
  expect(h.calls[1]!.resumeScanId).toBe([...h.records.keys()][0]);
  for (const call of h.calls) {
    expect(call.workflowId).toBeUndefined();
    expect(call.outputDir).toBe(
      join(h.input.scanDir, "artifacts/deep-scan/passes/pass-1"),
    );
  }
});

test.each([false, true])(
  "registration persistence retries preserve the child and required accounting (%p)",
  async (requireCost) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
    h.input.scanOptions.requireCost = requireCost;
    const workbench = h.input.workbench;
    let injected = false;
    h.input.workbench = async (args, contents) => {
      if (
        !injected &&
        args[0] === "save-scan-artifact" &&
        args[4] === DEEP_SCAN_CHECKPOINT &&
        JSON.parse(contents!).passes.some(
          (pass: { scanId?: string }) => pass.scanId !== undefined,
        )
      ) {
        injected = true;
        throw new Error("Synthetic one-shot registration checkpoint failure");
      }
      return workbench(args, contents);
    };
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      DeepScanRecoveryError,
    );
    expect(injected).toBe(true);
    expect(h.calls).toHaveLength(1);
    expect(h.operations).not.toContain("fail-scan");
    expect(
      (await loadDeepScanCheckpoint(h.input.scanDir))!.terminalReason,
    ).toBeUndefined();
    const child = [...h.records.values()][0]!;
    expect(child.progress.status).toBe("running");
    if (requireCost) {
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanCostTrackingError,
      );
      expect(h.calls).toHaveLength(1);
      expect(child.progress.status).toBe("failed");
      expect(h.publications).toHaveLength(0);
    } else {
      await runDeepScans(h.input);
      expect(h.calls).toHaveLength(2);
      expect(h.calls[1]!.resumeScanId).toBe(child.scanId);
      expect(h.publications.at(-1)!.findings).toHaveLength(1);
    }
    expect(h.records.size).toBe(1);
  },
);
