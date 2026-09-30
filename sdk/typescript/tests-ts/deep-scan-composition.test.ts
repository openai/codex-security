import { semanticCoverage } from "./helpers/semantic-scan.js";
import { fixtureSpawn } from "./support/codex-process.js";
import * as childProcess from "node:child_process";
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
import { Codex } from "@openai/codex-sdk";
import type { ScanOptions } from "../src/api.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
} from "../src/errors.js";
import {
  estimateScanCost,
  ScanCostTracker,
  type ScanCost,
} from "../src/cost.js";
import { createScanCostReporter } from "../src/scan-monitoring.js";
import { readCodexTurn } from "../src/scan-events.js";
import { createPermissionCheckedCodex } from "../src/permission-profile.js";
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
import {
  scanFindingIdentity,
  semanticScanDraft,
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

async function diagnosticError(kind: string): Promise<Error> {
  if (kind === "SDK parser") {
    const error = await codexStreamError(
      '{"type":"item.completed","item":{"type":"command_execution","command":"cat cyber_policy.py","output":"truncated',
    );
    expect(error.cause).toBeInstanceOf(SyntaxError);
    return error;
  }
  return new Error(
    "Could not save the Codex Security scan: findings.findings[0].severity.level: unsupported severity: cyber_policy",
  );
}

interface SavedRecord {
  completedAt?: string;
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
      expect(
        JSON.parse(await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"))
          .mergeStarted,
      ).toBe(true);
      const path = join(scanDir, "artifacts/deep-scan/merge-inputs.json");
      expect(prompt).toContain(JSON.stringify(path));
      const payload = JSON.parse(await readFile(path, "utf8")) as {
        findings: SemanticScan["findings"];
      };
      const checkpoint = checkpoints.at(-1)!;
      mergeInputs.push(
        checkpoint.passes.filter(
          (pass) =>
            pass.completed && !checkpoint.mergedScanIds.includes(pass.scanId!),
        ).length,
      );
      const byIdentity = new Map<
        string,
        { sourceFindingIds: string[]; canonicalSourceFindingId: string }
      >();
      for (const source of payload.findings) {
        const identity = scanFindingIdentity(source);
        const ids = source.provenance.sourceFindingIds!;
        const existing = byIdentity.get(identity);
        if (existing) existing.sourceFindingIds.push(...ids);
        else
          byIdentity.set(identity, {
            sourceFindingIds: [...ids],
            canonicalSourceFindingId: ids[0]!,
          });
      }
      return { scanId, groups: [...byIdentity.values()] };
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
  test.each(
    (["discovery", "merge"] as const).flatMap((role) =>
      [false, true].flatMap((resumed) =>
        ["exit", "rpc"].map((failure) => ({ role, resumed, failure })),
      ),
    ),
  )(
    "retries a transient permission preflight before executing the worker: %j",
    async ({ role, resumed, failure }) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ maxDiscoveryRuns: 1 });
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
          events: (await thread.runStreamed("Inert fixture.", { signal }))
            .events,
        });
      h.setRun(async (options) => {
        if (role === "discovery") await execute(options.signal!);
        return result(
          options.resumeScanId!,
          options.outputDir!,
          role === "merge" ? "supported-issue" : undefined,
        );
      });
      const merge = h.input.merge;
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
        expect(h.calls).toHaveLength(role === "discovery" ? 2 : 1);
        expect(state.passes).toHaveLength(1);
        expect(state.mergedScanIds).toHaveLength(1);
        expect(state.consecutiveErrors).toBe(0);
        expect(state.mergeFailures ?? 0).toBe(0);
        expect(h.published.at(-1)!.findings).toHaveLength(
          role === "merge" ? 1 : 0,
        );
      } finally {
        spawning.mockRestore();
      }
    },
  );

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
    expect(h.mergeInputs).toEqual([]);
    expect(h.published).toHaveLength(2);
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

  test.each([false, true])(
    "counts clean passes after a novel finding in the same batch (repeated finding: %p)",
    async (repeated) => {
      const h = await harness({ workers: 3, stopAfterNoNew: 2 });
      h.setRun(async (options) =>
        result(
          options.resumeScanId!,
          options.outputDir!,
          options.outputDir!.endsWith("pass-1") || repeated
            ? "supported-issue"
            : undefined,
        ),
      );
      const state = await runDeepScans(h.input);
      expect(h.calls).toHaveLength(3);
      expect(h.mergeInputs).toEqual([3]);
      expect(state.noNewStreak).toBe(2);
      expect(state.terminalReason).toBe("saturated");
      expect(state.aggregate!.findings).toHaveLength(1);
    },
  );

  test.each(
    (["failed", "canceled"] as const).flatMap((terminalReason) =>
      [false, true].map((populated) => ({ terminalReason, populated })),
    ),
  )(
    "does not execute a saved $terminalReason checkpoint (aggregate: $populated)",
    async ({ terminalReason, populated }) => {
      const h = await harness();
      const checkpoint: DeepScanCheckpoint = {
        version: 2,
        startedAt: h.input.startedAt,
        passes: [],
        mergedScanIds: [],
        aggregate: populated
          ? {
              scanId: h.input.scanId,
              findings: [],
              coverage: semanticCoverage(),
            }
          : null,
        noNewStreak: 0,
        consecutiveErrors: 0,
        terminalReason,
      };
      await h.seed(checkpoint);
      const execution = runDeepScans(h.input);
      await expect(execution).rejects.toThrow(
        `saved Deep Scan is ${terminalReason}`,
      );
      await expect(execution).rejects.toBeInstanceOf(ScanInterruptedError);
      await expect(execution).rejects.toMatchObject({
        scanDir: h.input.scanDir,
      });
      expect(h.calls).toEqual([]);
      expect(h.mergeInputs).toEqual([]);
      expect(h.published).toEqual([]);
      expect(await h.checkpoint()).toEqual(checkpoint);
    },
  );

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
        passes: [{ directory: childDirectory, completed: true }],
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
            kind === "failed discovery"
              ? "saved Deep Scan is failed"
              : discoveryLimit
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
          ...(kind === "failed discovery"
            ? {}
            : {
                mergeFailures:
                  discoveryLimit || fatalMergeFailure ? priorFailures : 3,
              }),
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

  test.each([
    ["missing field", "canonicalSourceFindingId"],
    ["unexpected field", "cyber_policy"],
    ["JSON syntax", "cyber_policy"],
  ])(
    "retries an invalid merge with the %s diagnostic",
    async (kind, diagnostic) => {
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
        if (kind === "JSON syntax") return JSON.parse("cyber_policy");
        const invalid = structuredClone(output) as { groups: JsonObject[] };
        if (kind === "unexpected field")
          return { ...invalid, cyber_policy: false };
        delete invalid.groups[0]!["canonicalSourceFindingId"];
        return invalid;
      };

      await runDeepScans(h.input);

      expect(prompts).toHaveLength(2);
      expect(prompts[1]).toContain(diagnostic);
      expect(h.calls).toHaveLength(1);
      expect((await h.checkpoint()).mergeFailures).toBe(0);
      expect(h.published.at(-1)!.findings).toHaveLength(1);
    },
  );

  test.each([
    "Request blocked by cyberPolicy.",
    "Request flagged for possible cybersecurity risk.",
    "Request flagged for potentially high-risk cyber activity.",
    "Request rejected: cyber_policy.",
    "cyber_policy",
  ])(
    "keeps runtime refusal %s fatal after a merge validation error",
    async (message) => {
      const h = await harness({ maxDiscoveryRuns: 1 });
      h.setRun(async (options) =>
        result(options.resumeScanId!, options.outputDir!, "supported-issue"),
      );
      const merge = h.input.merge;
      const refusal = await codexStreamError(
        JSON.stringify({ type: "turn.failed", error: { message } }),
      );
      let attempts = 0;
      h.input.merge = async (prompt, signal) => {
        if (++attempts > 1) throw refusal;
        return {
          ...((await merge(prompt, signal)) as JsonObject),
          cyber_policy: false,
        };
      };

      await expect(runDeepScans(h.input)).rejects.toBe(refusal);

      expect(attempts).toBe(2);
      expect(h.calls).toHaveLength(1);
      expect(await h.checkpoint()).toMatchObject({
        terminalReason: "failed",
        mergeFailures: 1,
        mergedScanIds: [],
      });
      expect(h.published).toEqual([]);
    },
  );

  test.each(["SDK parser", "schema"])(
    "retries a merge after a %s diagnostic containing policy-like data",
    async (kind) => {
      const h = await harness({ maxDiscoveryRuns: 1 });
      h.setRun(async (options) =>
        result(options.resumeScanId!, options.outputDir!, "supported-issue"),
      );
      const failure = await diagnosticError(kind);
      const merge = h.input.merge;
      let attempts = 0;
      h.input.merge = async (...args) => {
        if (++attempts === 1) throw failure;
        return merge(...args);
      };

      await runDeepScans(h.input);

      expect(attempts).toBe(2);
      expect(h.calls).toHaveLength(1);
      expect((await h.checkpoint()).mergedScanIds).toHaveLength(1);
      expect((await h.checkpoint()).mergeFailures).toBe(0);
    },
  );

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

  test.each([
    { savedCost: false, usage: true, budget: "none" },
    { savedCost: true, usage: true, budget: "none" },
    { savedCost: true, usage: false, budget: "none" },
    { savedCost: true, usage: false, budget: "required" },
    { savedCost: true, usage: true, budget: "exhausted" },
    ...[false, true].flatMap((savedCost) =>
      ["none", "required"].map((budget) => ({
        savedCost,
        usage: true,
        budget,
        threadSaved: false,
      })),
    ),
    ...["failed", "canceled"].flatMap((status) =>
      ["none", "required"].map((budget) => ({
        savedCost: false,
        usage: false,
        budget,
        status,
        threadSaved: false,
      })),
    ),
    ...["failed", "canceled"].map((status) => ({
      savedCost: true,
      usage: false,
      budget: "required",
      status,
      threadSaved: false,
      zeroCost: true,
    })),
  ] as const)(
    "recovers running child usage before a pending merge can saturate: %j",
    async ({ savedCost, usage, budget, ...saved }) => {
      const threadSaved = !("threadSaved" in saved) || saved.threadSaved;
      const status = "status" in saved ? saved.status : "running";
      const h = await harness({
        stopAfterNoNew: 1,
        maxDiscoveryRuns: budget === "exhausted" ? 3 : 2,
      });
      const directory = "artifacts/deep-scan/passes/pass-1";
      const childDirectory = join(h.input.scanDir, directory);
      const pendingDirectory = "artifacts/deep-scan/passes/pass-2";
      const pendingScanDir = join(h.input.scanDir, pendingDirectory);
      const childId = randomUUID();
      const pendingId = randomUUID();
      const siblingId = randomUUID();
      const siblingDirectory = "artifacts/deep-scan/passes/pass-3";
      const siblingScanDir = join(h.input.scanDir, siblingDirectory);
      const partialCost = estimateScanCost("gpt-6-astra", {
        input_tokens: "zeroCost" in saved ? 0 : 10,
        output_tokens: "zeroCost" in saved ? 0 : 1,
      })!;
      const recoveredCost = estimateScanCost("gpt-6-astra", {
        input_tokens: 1150,
        output_tokens: 115,
      })!;
      h.records.set(childId, {
        scanId: childId,
        scanDir: childDirectory,
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status },
        ...(threadSaved ? { continuationThreadId: "interrupted-child" } : {}),
        ...(savedCost ? { cost: partialCost } : {}),
      });
      h.records.set(pendingId, {
        scanId: pendingId,
        scanDir: pendingScanDir,
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status: "complete" },
        cost: partialCost,
      });
      if (budget === "exhausted")
        h.records.set(siblingId, {
          scanId: siblingId,
          scanDir: siblingScanDir,
          parentScanId: h.input.scanId,
          targetPath: h.input.repository,
          progress: { status: "running" },
          continuationThreadId: "sibling",
          cost: partialCost,
        });
      h.input.projectChild = async (scanId, scanDir, projectionSignal) => {
        projectionSignal.throwIfAborted();
        const completed = result(
          scanId,
          scanDir,
          budget === "exhausted" ? "retained-issue" : undefined,
        );
        const draft = semanticScanDraft(
          h.input.scanId,
          completed.manifest.scan,
          completed.findings.findings,
          {
            ...completed.coverage,
            deferred: [{ reason: "Retained accepted coverage." }],
          },
        );
        for (const [index, finding] of draft.findings.entries())
          finding.provenance = {
            ...finding.provenance,
            sourceFindingIds: [`${scanId}:${index}`],
            sourceFindings: [
              {
                id: `${scanId}:${index}`,
                finding: completed.findings.findings[index]!,
              },
            ],
          };
        return {
          scanId,
          scanDir,
          draft,
          sourceFindings: completed.findings.findings,
        };
      };
      const aggregate =
        budget === "exhausted"
          ? (
              await h.input.projectChild(
                pendingId,
                pendingScanDir,
                h.controller.signal,
              )
            ).draft
          : null;
      await h.seed({
        version: 2,
        startedAt: h.input.startedAt,
        passes: [
          { directory, scanId: childId },
          { directory: pendingDirectory, scanId: pendingId, completed: true },
          ...(budget === "exhausted"
            ? [{ directory: siblingDirectory, scanId: siblingId }]
            : []),
        ],
        mergedScanIds: aggregate ? [pendingId] : [],
        aggregate,
        noNewStreak: 0,
        consecutiveErrors: 0,
      });
      const codexHome = join(h.input.scanDir, "codex");
      await mkdir(join(codexHome, "sessions"), { recursive: true });
      const sessions = [
        ["interrupted-child", childDirectory, undefined, 1000],
        ["child-local", join(childDirectory, "artifacts"), undefined, 100],
        ["descendant", undefined, "interrupted-child", 50],
        ["sibling", siblingScanDir, undefined, 1000000],
        [
          "parent-local",
          join(h.input.scanDir, "artifacts"),
          undefined,
          1000000,
        ],
      ] as const;
      for (const [
        index,
        [id, cwd, parentThreadId, tokens],
      ] of sessions.entries()) {
        await writeFile(
          join(codexHome, "sessions", `rollout-${id}.jsonl`),
          [
            {
              type: "session_meta",
              payload: {
                id,
                cwd,
                parent_thread_id: parentThreadId,
                timestamp: h.input.startedAt,
              },
            },
            ...(usage || index >= 3
              ? [
                  {
                    type: "event_msg",
                    payload: {
                      type: "token_count",
                      info: {
                        total_token_usage: {
                          input_tokens: tokens,
                          output_tokens: tokens / 10,
                        },
                      },
                    },
                  },
                ]
              : []),
          ]
            .map((event) => JSON.stringify(event))
            .join("\n") + "\n",
        );
      }
      let historyReads = 0;
      h.input.historicalCost = async (
        threadId,
        scanDirectory = h.input.scanDir,
      ) => {
        historyReads += 1;
        const tracker = new ScanCostTracker({
          codexHome,
          model: "gpt-6-astra",
          scanDirectory,
        });
        tracker.start(threadId);
        const snapshot = await tracker.stop();
        h.controller.signal.throwIfAborted();
        return snapshot.cost;
      };
      h.input.scanOptions.requireCost = budget !== "none";
      const reportCost = createScanCostReporter({
        options:
          budget === "exhausted"
            ? { maxCostUsd: recoveredCost.estimatedUsd / 2 }
            : {},
        scanDir: h.input.scanDir,
        costAbortController: h.controller,
        budgetSignal: h.controller.signal,
        getActiveScan: () => null,
        workbench: async () => ({}),
      });
      const costs = new Map<string, Readonly<ScanCost> | null>();
      h.input.onCost = (key, cost) => {
        costs.set(key, cost);
        if (cost !== null) reportCost(cost);
      };
      const costsBeforePublication: Array<
        Readonly<ScanCost> | null | undefined
      > = [];
      const publish = h.input.publish;
      h.input.publish = async (...args) => {
        costsBeforePublication.push(costs.get(directory));
        return publish(...args);
      };
      const expectedReceipt =
        status !== "running" && savedCost
          ? partialCost
          : usage && threadSaved
            ? recoveredCost
            : null;
      if (
        (budget === "required" && expectedReceipt === null) ||
        budget === "exhausted"
      ) {
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          budget === "required"
            ? ScanCostTrackingError
            : ScanCostLimitExceededError,
        );
        expect(h.mergeInputs).toEqual([]);
        if (aggregate) {
          expect((await h.checkpoint()).terminalReason).toBe("capped");
          expect(h.published.at(-1)!.findings).toEqual(aggregate.findings);
          expect(h.published.at(-1)!.coverage.deferred).toContainEqual({
            reason: "Retained accepted coverage.",
          });
          expect(costs.get(siblingDirectory)).toEqual(
            estimateScanCost("gpt-6-astra", {
              input_tokens: 1000000,
              output_tokens: 100000,
            }),
          );
        } else expect(h.published).toEqual([]);
      } else {
        await runDeepScans(h.input);
        expect(h.mergeInputs).toEqual([]);
        expect(costsBeforePublication).toEqual([expectedReceipt]);
        expect((await h.checkpoint()).terminalReason).toBe("saturated");
      }
      expect(h.calls).toEqual([]);
      expect(historyReads).toBe(aggregate ? 2 : threadSaved ? 1 : 0);
      expect(costs.get(directory)).toEqual(expectedReceipt);
    },
  );

  test.each([
    [false, false],
    [false, true],
    [true, false],
    [true, true],
  ])(
    "keeps lost child accounting unknown across completion and resume (required: %p, resumed: %p)",
    async (requireCost, resuming) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ maxDiscoveryRuns: 1 });
      h.input.scanOptions.requireCost = requireCost;
      const known = estimateScanCost("gpt-6-astra", {
        input_tokens: 100,
        output_tokens: 10,
      })!;
      const costs = new Map<string, Readonly<ScanCost> | null>();
      h.input.onCost = (key, cost) => costs.set(key, cost);
      if (resuming) {
        const id = randomUUID();
        const directory = "artifacts/deep-scan/passes/pass-1";
        h.records.set(id, {
          scanId: id,
          scanDir: join(h.input.scanDir, directory),
          parentScanId: h.input.scanId,
          targetPath: h.input.repository,
          progress: { status: "running" },
          cost: known,
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
      }
      let turns = 0;
      h.setRun(async (options) => {
        turns++;
        const id = options.resumeScanId!;
        options.onCost?.(known);
        if (!resuming && turns === 1)
          throw new Error(
            "Synthetic interruption after optional session write failed.",
          );
        const completed = new ScanResult({
          ...result(id, options.outputDir!),
          turnResult: {
            model: "gpt-6-astra",
            usage: { input_tokens: 100, output_tokens: 10 },
          },
        });
        h.records.get(id)!.continuationThreadId = completed.threadId!;
        h.records.get(id)!.cost = completed.cost;
        return completed;
      });
      if (requireCost) {
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
        expect(turns).toBe(resuming ? 0 : 1);
        expect(h.mergeInputs).toEqual([]);
        expect([...costs.values()]).toContain(null);
        return;
      }
      const publish = h.input.publish;
      h.input.publish = async () => {
        throw new ScanTransportClosedError(
          "Synthetic interruption after accepted merge.",
        );
      };
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      expect(turns).toBe(resuming ? 1 : 2);
      expect([...costs.values()]).toContain(null);
      expect([...costs.values()]).toContainEqual(known);

      h.input.publish = publish;
      costs.clear();
      await runDeepScans(h.input);
      expect(turns).toBe(resuming ? 1 : 2);
      expect(h.published.at(-1)!.findings).toEqual([]);
      expect([...costs.values()]).toContain(null);
      expect([...costs.values()]).toContainEqual(known);
      h.input.scanOptions.requireCost = true;
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanCostTrackingError,
      );
      expect(turns).toBe(resuming ? 1 : 2);
    },
  );

  test("keeps every registered sibling in accounting when a budget callback aborts the batch", async () => {
    const h = await harness({ workers: 2, maxDiscoveryRuns: 2 });
    const cost = estimateScanCost("gpt-6-astra", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const costs = new Map<string, Readonly<ScanCost> | null>();
    const reportCost = createScanCostReporter({
      options: { maxCostUsd: cost.estimatedUsd / 2 },
      scanDir: h.input.scanDir,
      costAbortController: h.controller,
      budgetSignal: h.controller.signal,
      getActiveScan: () => null,
      workbench: async () => ({}),
    });
    h.input.onCost = (key, receipt) => {
      costs.set(key, receipt);
      if (receipt !== null) reportCost(receipt);
    };
    let secondStarted!: () => void;
    const ready = new Promise<void>((resolve) => {
      secondStarted = resolve;
    });
    h.setRun(async (options) => {
      if (options.outputDir!.endsWith("pass-1")) {
        await ready;
        options.onCost?.(cost);
        options.signal!.throwIfAborted();
      } else {
        secondStarted();
        await abortable(
          () => new Promise<never>(() => undefined),
          options.signal,
        );
      }
      throw new Error("The budget must stop both workers.");
    });
    await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
      ScanCostLimitExceededError,
    );
    expect(h.calls).toHaveLength(2);
    expect(costs.get("artifacts/deep-scan/passes/pass-1")).toEqual(cost);
    expect(costs.get("artifacts/deep-scan/passes/pass-2")).toBeNull();
    expect((await h.checkpoint()).terminalReason).toBe("capped");
  });

  test("rejects legacy active checkpoints without changing saved evidence", async () => {
    const h = await harness();
    const checkpoint: DeepScanCheckpoint = {
      version: 2,
      startedAt: h.input.startedAt,
      passes: [],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
      legacy: { discoveryRuns: 1, coverage: semanticCoverage() },
    };
    await h.seed(checkpoint);
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "Saved legacy Deep Scans cannot be resumed; their reports remain available.",
    );
    expect(h.calls).toEqual([]);
    expect(h.mergeInputs).toEqual([]);
    expect(h.published).toEqual([]);
    expect(await h.checkpoint()).toEqual(checkpoint);
  });

  test.each([
    "Transient scan interruption",
    "429: request flagged for possible cybersecurity risk.",
    "Rate-limited: request refused under safety policy.",
    "Source fixture: Request blocked by cyberPolicy.",
    'Codex Exec exited with code 1: "Request blocked by cyberPolicy."',
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
      expect(h.mergeInputs).toEqual([]);
    },
  );

  test.each(["SDK parser", "schema"])(
    "retries a child after a %s diagnostic without canceling its sibling",
    async (kind) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ workers: 2, maxDiscoveryRuns: 2 });
      const failure = await diagnosticError(kind);
      const siblingStarted = Promise.withResolvers<void>();
      const retryObserved = Promise.withResolvers<void>();
      h.input.onRetry = () => retryObserved.resolve();
      let attempts = 0;
      h.setRun(async (options) => {
        if (options.outputDir!.endsWith("pass-1")) {
          await siblingStarted.promise;
          if (++attempts === 1) throw failure;
        } else {
          siblingStarted.resolve();
          await abortable(() => retryObserved.promise, options.signal);
          options.signal!.throwIfAborted();
        }
        return result(options.resumeScanId!, options.outputDir!);
      });

      await runDeepScans(h.input);

      expect(attempts).toBe(2);
      expect(h.calls).toHaveLength(3);
      expect(
        [...h.records.values()].map((record) => record.progress.status),
      ).toEqual(["complete", "complete"]);
      const state = await h.checkpoint();
      expect(h.calls[2]!.resumeScanId).toBe(state.passes[0]!.scanId);
      expect(state.passes).toHaveLength(2);
      expect(state.mergedScanIds).toHaveLength(2);
      expect(state.terminalReason).not.toBe("failed");
      expect(state.terminalReason).not.toBe("canceled");
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

  test.each(["recovered", "completed", "merged"] as const)(
    "only an unobserved success resets the saved failure streak (%s)",
    async (success) => {
      retryDelay = spyOn(timers, "setTimeout").mockImplementation(
        async <T>(_delay?: number, value?: T): Promise<T> => value as T,
      );
      const h = await harness({ workers: 3, maxDiscoveryRuns: 4 });
      const directory = "artifacts/deep-scan/passes/pass-3";
      const scanDir = join(h.input.scanDir, directory);
      await mkdir(dirname(scanDir), { recursive: true });
      await cp(example, scanDir, { recursive: true });
      await chmod(scanDir, 0o700);
      const scanId = exampleManifest.scan.id;
      h.records.set(scanId, {
        scanId,
        scanDir,
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status: "complete" },
      });
      await h.seed({
        version: 2,
        startedAt: h.input.startedAt,
        passes: [
          { directory: "artifacts/deep-scan/passes/pass-1", failed: true },
          { directory: "artifacts/deep-scan/passes/pass-2", failed: true },
          {
            directory,
            scanId,
            ...(success === "completed" ? { completed: true as const } : {}),
          },
        ],
        mergedScanIds: success === "merged" ? [scanId] : [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors: 2,
      });
      h.setRun(async () => {
        throw new Error("Synthetic next pass failure");
      });
      if (success === "recovered") {
        await expect(runDeepScans(h.input)).resolves.toMatchObject({
          terminalReason: "capped",
          consecutiveErrors: 1,
        });
      } else {
        await expect(runDeepScans(h.input)).rejects.toThrow(
          "consecutive error limit",
        );
        expect((await h.checkpoint()).consecutiveErrors).toBe(3);
      }
    },
  );

  test.each([
    ...[2, 3].flatMap((limit) =>
      [false, true].flatMap((successLast) =>
        [false, true].map((failureSaved) => ({
          limit,
          successLast,
          failureSaved,
          successSaved: false,
        })),
      ),
    ),
    { limit: 1, successLast: true, failureSaved: false, successSaved: true },
  ])(
    "recovers terminal outcomes in completion order across repeated resumes (%j)",
    async ({ limit, successLast, failureSaved, successSaved }) => {
      const h = await harness({
        maxDiscoveryRuns: 3,
        stopAfterConsecutiveErrors: limit,
      });
      const directory = "artifacts/deep-scan/passes/pass-2";
      const scanDir = join(h.input.scanDir, directory);
      await mkdir(dirname(scanDir), { recursive: true });
      await cp(example, scanDir, { recursive: true });
      await chmod(scanDir, 0o700);
      const scanId = exampleManifest.scan.id;
      const failedId = randomUUID();
      const records: SavedRecord[] = [
        {
          scanId,
          scanDir,
          parentScanId: h.input.scanId,
          targetPath: h.input.repository,
          progress: { status: "complete" },
          completedAt: successLast
            ? "2026-01-01T00:00:02Z"
            : "2026-01-01T00:00:01Z",
        },
        {
          scanId: failedId,
          scanDir: join(h.input.scanDir, "artifacts/deep-scan/passes/pass-3"),
          parentScanId: h.input.scanId,
          targetPath: h.input.repository,
          progress: { status: "failed" },
          completedAt: successLast
            ? "2026-01-01T00:00:01Z"
            : "2026-01-01T00:00:02Z",
        },
      ];
      // The workbench lists the most recently finished scan first.
      for (const record of records.sort((a, b) =>
        b.completedAt!.localeCompare(a.completedAt!),
      ))
        h.records.set(record.scanId, record);
      await h.seed({
        version: 2,
        startedAt: h.input.startedAt,
        passes: [
          { directory: "artifacts/deep-scan/passes/pass-1", failed: true },
          {
            directory,
            scanId,
            ...(successSaved ? { completed: true as const } : {}),
          },
          {
            directory: "artifacts/deep-scan/passes/pass-3",
            scanId: failedId,
            ...(failureSaved ? { failed: true as const } : {}),
          },
        ],
        mergedScanIds: [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors: successSaved ? 0 : failureSaved ? 2 : 1,
      });
      const workbench = h.input.workbench;
      h.input.workbench = async (args, contents) => {
        const result = await workbench(args, contents);
        if (
          args[0] === "save-scan-artifact" &&
          JSON.parse(contents!).passes[1].completed &&
          JSON.parse(contents!).passes[2].failed
        )
          throw new ScanTransportClosedError(
            "Synthetic interruption after recovery",
          );
        return result;
      };
      await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      h.input.workbench = workbench;
      await expect(runDeepScans(h.input)).resolves.toMatchObject({
        terminalReason: "capped",
        consecutiveErrors: successLast ? 0 : 1,
      });
      expect(h.calls).toEqual([]);
      expect(h.mergeInputs).toEqual([1]);
      expect(h.published[0]!.findings).toHaveLength(
        exampleFindings.findings.length,
      );
    },
  );

  test("does not recount a saved failure after recovering an earlier failure", async () => {
    const h = await harness({
      maxDiscoveryRuns: 2,
      stopAfterConsecutiveErrors: 3,
    });
    const passes = [1, 2].map((number) => ({
      directory: `artifacts/deep-scan/passes/pass-${number}`,
      scanId: randomUUID(),
      ...(number === 2 ? { failed: true as const } : {}),
    }));
    for (const [index, pass] of passes.entries())
      h.records.set(pass.scanId, {
        scanId: pass.scanId,
        scanDir: join(h.input.scanDir, pass.directory),
        parentScanId: h.input.scanId,
        targetPath: h.input.repository,
        progress: { status: "failed" },
        completedAt: `2026-01-01T00:00:0${index + 1}Z`,
      });
    await h.seed({
      version: 2,
      startedAt: h.input.startedAt,
      passes,
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 1,
    });

    await expect(runDeepScans(h.input)).rejects.toThrow(
      "every discovery run failed",
    );
    expect(await h.checkpoint()).toMatchObject({
      terminalReason: "failed",
      consecutiveErrors: 2,
      passes: passes.map((pass) => ({ ...pass, failed: true })),
    });
    expect(h.calls).toEqual([]);
    expect(h.mergeInputs).toEqual([]);
    expect(h.published).toEqual([]);
  });

  test.each(["none", "cancel", "cost"] as const)(
    "keeps the consecutive error limit when a sibling finishes after it (late stop: %s)",
    async (lateStop) => {
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
        ) {
          if (lateStop === "cancel")
            h.controller.abort(new Error("Canceled after threshold."));
          if (lateStop === "cost")
            h.controller.abort(
              new ScanCostLimitExceededError(
                0.001,
                estimateScanCost("gpt-6-astra", {
                  input_tokens: 10000,
                  output_tokens: 2000,
                })!,
                h.input.scanDir,
              ),
            );
          releaseSibling();
        }
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
    },
  );

  test("persists threshold failure before transport loss can admit a later sibling", async () => {
    retryDelay = spyOn(timers, "setTimeout").mockImplementation(
      async <T>(_delay?: number, value?: T): Promise<T> => value as T,
    );
    const h = await harness({
      workers: 2,
      maxDiscoveryRuns: 2,
      stopAfterConsecutiveErrors: 1,
    });
    const thresholdSaved = Promise.withResolvers<void>();
    const transport = new ScanTransportClosedError(
      "Transport stopped after threshold save.",
    );
    const createClient = h.input.createClient;
    h.input.createClient = () => {
      const client = createClient();
      return {
        ...client,
        run(repository, options = {}) {
          return client.run(repository, {
            ...options,
            ...(options.outputDir!.endsWith("pass-2")
              ? { resumeScanId: exampleManifest.scan.id }
              : {}),
          });
        },
      };
    };
    const workbench = h.input.workbench;
    h.input.workbench = async (args, contents) => {
      if (h.controller.signal.aborted) throw transport;
      const response = await workbench(args, contents);
      if (
        args[0] === "save-scan-artifact" &&
        JSON.parse(contents!).consecutiveErrors === 1
      ) {
        h.controller.abort(transport);
        thresholdSaved.resolve();
      }
      return response;
    };
    h.setRun(async (options) => {
      if (options.outputDir!.endsWith("pass-1"))
        throw new Error("Discovery failed.");
      await thresholdSaved.promise;
      await cp(example, options.outputDir!, { recursive: true });
      return result(options.resumeScanId!, options.outputDir!);
    });
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "consecutive error limit",
    );
    expect(h.records.get(exampleManifest.scan.id)!.progress.status).toBe(
      "complete",
    );
    const checkpointPath = join(h.input.scanDir, DEEP_SCAN_CHECKPOINT);
    const saved = await readFile(checkpointPath);
    expect(JSON.parse(saved.toString()).consecutiveErrors).toBe(1);
    h.input.signal = new AbortController().signal;
    h.input.workbench = workbench;
    await expect(runDeepScans(h.input)).rejects.toThrow(
      "saved Deep Scan is failed",
    );
    expect(await readFile(checkpointPath)).toEqual(saved);
    expect(h.calls).toHaveLength(5);
    expect(h.mergeInputs).toEqual([]);
    expect(h.published).toEqual([]);
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
      const stopped = requireCost;
      if (stopped)
        await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
          ScanCostTrackingError,
        );
      else {
        await runDeepScans(h.input);
        expect((await h.checkpoint()).terminalReason).toBe("saturated");
        expect(h.published.at(-1)!.coverage["completeness"]).toBe("partial");
      }
      expect(h.calls).toHaveLength(
        (resumed ? 0 : requireCost && !executed ? 2 : 4) + (stopped ? 0 : 1),
      );
      expect(h.mergeInputs).toEqual([]);
      expect(costs.get(failedDirectory)).toBeNull();
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
        expect(h.mergeInputs).toEqual([]);
        expect((await h.checkpoint()).terminalReason).toBe("saturated");
      }
      expect(h.calls).toHaveLength(1);
      expect(costs).toContainEqual(partial);
      expect(costs.at(-1)).toBeNull();
    },
  );

  test.each([
    "metering",
    "permission before registration",
    "permission after registration",
    "Request flagged for possible cybersecurity risk.",
    "Request flagged for potentially high-risk cyber activity.",
    "Request rejected: cyber_policy.",
    "cyber_policy",
    "This content was flagged for possible cybersecurity risk.",
    "This content was flagged for potentially high-risk cyber activity.",
    "This request has been flagged for possible cybersecurity risk.",
    "This request has been flagged for potentially high-risk cyber activity.",
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
            : await codexStreamError(
                JSON.stringify({
                  type: "turn.failed",
                  error: { message: kind },
                }),
              );
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
    const project = h.input.projectChild;
    const clock = spyOn(Date, "now");
    h.input.projectChild = async (...args) => {
      const merged = await project(...args);
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
      expect(h.mergeInputs).toEqual([]);
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
        continuationThreadId: "saved-child-session",
      });
      const coverage = semanticCoverage({ completeness: "partial" });
      const checkpoint: DeepScanCheckpoint = {
        version: 2,
        startedAt,
        passes: [{ directory, scanId }],
        mergedScanIds: [],
        aggregate: { scanId: h.input.scanId, findings: [], coverage },
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
        expect(h.mergeInputs).toEqual([]);
        expect(h.metrics()).toEqual({ closed: 2, maximumActive: 1 });
        expect(await readFile(childCheckpoint)).toEqual(childBytes);
      } finally {
        clock.mockRestore();
      }
    },
  );
});

test("caps an expired empty composition without requesting a model merge", async () => {
  const h = await harness();
  h.input.startedAt = "2000-01-01T00:00:00.000Z";
  const result = await runDeepScans(h.input);
  expect(h.calls).toEqual([]);
  expect(h.mergeInputs).toEqual([]);
  expect(result.terminalReason).toBe("capped");
  expect(result.aggregate?.findings).toEqual([]);
  expect(result.aggregate?.coverage["completeness"]).toBe("partial");
  expect(h.published).toHaveLength(1);
});

test("persists a completed child while its sibling is running before the first merge", async () => {
  const h = await harness({ workers: 2, maxDiscoveryRuns: 2 });
  const sibling = Promise.withResolvers<void>();
  const transport = new ScanTransportClosedError(
    "Synthetic mid-batch transport loss.",
  );
  const workbench = h.input.workbench;
  h.input.workbench = async (args, contents) => {
    const reply = await workbench(args, contents);
    if (args[0] === "save-scan-artifact") {
      const state = JSON.parse(contents!) as DeepScanCheckpoint;
      if (state.passes[0]?.completed && state.passes[1]?.scanId)
        h.controller.abort(transport);
    }
    return reply;
  };
  h.setRun(async (options) => {
    if (options.outputDir!.endsWith("pass-1")) {
      await sibling.promise;
      return result(options.resumeScanId!, options.outputDir!);
    }
    sibling.resolve();
    await abortable(() => new Promise<never>(() => {}), options.signal);
    throw new Error("Unreachable unfinished sibling.");
  });
  await expect(runDeepScans(h.input)).rejects.toBe(transport);
  const state = await h.checkpoint();
  expect(state.passes).toHaveLength(2);
  expect(state.passes[0]?.completed).toBe(true);
  expect(state.passes[1]?.completed).toBeUndefined();
  expect(
    [...h.records.values()].map((record) => record.progress.status),
  ).toEqual(["complete", "running"]);
  expect(state.aggregate).toBeNull();
  expect(state.mergedScanIds).toEqual([]);
  expect(state.terminalReason).toBeUndefined();
  expect(h.mergeInputs).toEqual([]);
  expect(h.metrics()).toEqual({ closed: 2, maximumActive: 2 });
});
