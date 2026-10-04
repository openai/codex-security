import * as childProcess from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, spyOn, test } from "bun:test";
import { Codex } from "@openai/codex-sdk";
import type { ScanOptions } from "../src/api.js";
import { estimateScanCost } from "../src/cost.js";
import {
  DEEP_SCAN_CHECKPOINT,
  DeepScanPublicationError,
  runDeepScans,
  ScanCostTrackingError,
  type DeepScanComposition,
} from "../src/deep-scan.js";
import {
  loadDeepScanCheckpoint,
  newDeepScanCheckpoint,
} from "../src/deep-scan-checkpoint.js";
import { ScanResult } from "../src/result.js";
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
        await options.onRegisteredScan?.({
          scanId: childId,
          threadId: "session",
          scanDir: options.outputDir!,
        });
        records.set(childId, {
          scanId: childId,
          scanDir: options.outputDir!,
          targetPath: repository,
          parentScanId: scanId,
          continuationThreadId: "session",
          progress: { status: "running" },
        });
        await execute(options);
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
        const cost = estimateScanCost("gpt-6-astra", {
          input_tokens: 10,
          output_tokens: 3,
        });
        records.get(childId)!.progress.status = "complete";
        records.get(childId)!.cost = cost;
        records.get(childId)!.completedAt = new Date().toISOString();
        return {
          manifest: { scan: { id: childId } },
          scanDir: options.outputDir!,
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
    metrics: () => ({ merges, closes }),
  };
}

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

test.each([false, true])(
  "failed aggregate writes are retried (partial write: %p)",
  async (partial) => {
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
    const workbench = h.input.workbench;
    const attempts: string[] = [];
    h.input.workbench = async (args, contents) => {
      if (
        args[0] === "save-scan-artifact" &&
        args[4]!.startsWith("artifacts/deep-scan/aggregates/")
      ) {
        attempts.push(args[4]!);
        if (attempts.length === 1) {
          if (partial) await h.write(args[4]!, contents!);
          throw new Error("Synthetic aggregate write failure");
        }
      }
      return workbench(args, contents);
    };

    await expect(runDeepScans(h.input)).rejects.toThrow(
      "Synthetic aggregate write failure",
    );
    expect(attempts).toHaveLength(2);
    expect(attempts[1]).toBe(attempts[0]);
    const saved = await loadDeepScanCheckpoint(h.input.scanDir);
    expect(saved!.terminalReason).toBe("failed");
    expect(saved!.aggregate!.findings).toHaveLength(1);
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
  h.input.publish = async () => {
    throw new Error("synthetic publication failure");
  };
  await expect(runDeepScans(h.input)).rejects.toBeInstanceOf(
    DeepScanPublicationError,
  );
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
  expect(saved!.aggregate!.coverage!.completeness).toBe("partial");
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
    expect(h.publications.at(-1)!.coverage!.completeness).toBe("partial");
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
  expect(h.operations.filter((command) => command === "get-scan")).toHaveLength(
    1,
  );
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

test.each([true, false])(
  "resume orders saved child outcomes by completion time (success last: %p)",
  async (successLast) => {
    const h = await fixture({ stopAfterConsecutiveErrors: 1 });
    const passes = (["complete", "failed"] as const).map((status, index) => {
      const scanId = randomUUID();
      const directory = `artifacts/deep-scan/passes/pass-${index + 1}`;
      const scanDir = join(h.input.scanDir, directory);
      h.records.set(scanId, {
        scanId,
        scanDir,
        targetPath: h.input.repository,
        parentScanId: h.input.scanId,
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
    });
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
  let updates = 0;
  h.input.workbench = async (args, input) => {
    if (args[0] === "update-progress") {
      expect(args.slice(-2)).toEqual(["--phase", "discovery"]);
      updates++;
      throw new Error("synthetic optional progress failure");
    }
    return workbench(args, input);
  };
  await runDeepScans(h.input);
  expect(updates).toBe(1);
  expect(h.calls).toHaveLength(1);
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

test("a sibling failure aborts an in-flight projection", async () => {
  const h = await fixture();
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
  h.setExecute(async () => {
    if (++pass === 2) {
      await projecting;
      throw failure;
    }
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
    const h = await fixture({ workers: 1, maxDiscoveryRuns: 1 });
    const transport = new ScanTransportClosedError(
      "synthetic disconnected host",
    );
    h.setExecute(async () => {
      throw transport;
    });
    await expect(runDeepScans(h.input)).rejects.toBe(transport);
    const checkpoint = (await loadDeepScanCheckpoint(h.input.scanDir))!;
    const now = Date.now();
    checkpoint.startedAt = new Date(
      when === "before recovery" ? now - 2 * 3_600_000 : now,
    ).toISOString();
    await h.write(DEEP_SCAN_CHECKPOINT, JSON.stringify(checkpoint));
    expect([...h.records.values()][0]!.progress.status).toBe("running");
    const clock = spyOn(Date, "now").mockReturnValue(now);
    const workbench = h.input.workbench;
    h.input.workbench = async (args, input) => {
      if (args[0] === "list-scans" && when === "during recovery")
        clock.mockReturnValue(now + 2 * 3_600_000);
      return workbench(args, input);
    };
    try {
      const state = await runDeepScans(h.input);
      expect(state.terminalReason).toBe("capped");
      expect([...h.records.values()][0]!.progress.status).toBe("failed");
      expect(h.calls).toHaveLength(1);
      expect(
        h.operations.filter((operation) => operation === "fail-scan"),
      ).toHaveLength(1);
      expect(h.publications.at(-1)!.coverage!.completeness).toBe("partial");
    } finally {
      clock.mockRestore();
    }
  },
);
