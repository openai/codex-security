import { tmpdir } from "node:os";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import {
  DEEP_SCAN_CHECKPOINT,
  runDeepScans,
  type DeepScanCheckpoint,
  type DeepScanComposition,
} from "../src/deep-scan.js";
import { ScanResult } from "../src/result.js";
import type { JsonObject } from "../src/config.js";

const scratch = tmpdir();
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

test.each([false, true])(
  "concurrent checkpoint callers retain every registration and retry a failed shared write (failure=%s)",
  async (failFirst) => {
    await mkdir(scratch, { recursive: true });
    const root = await mkdtemp(join(scratch, "checkpoint-reuse-"));
    roots.push(root);
    const scanId = "11111111-2222-4333-8444-555555555555";
    const childIds = [
      "11111111-2222-4333-8444-666666666661",
      "11111111-2222-4333-8444-666666666662",
      "11111111-2222-4333-8444-666666666663",
    ];
    const path = join(root, DEEP_SCAN_CHECKPOINT);
    const [manifest, findings, coverage] = await Promise.all(
      ["scan-manifest.json", "findings.json", "coverage.json"].map(
        async (file) =>
          JSON.parse(
            await readFile(
              join(pluginRoot, "examples/completed-scan", file),
              "utf8",
            ),
          ),
      ),
    );
    findings.findings = [];
    coverage.surfaces = [];
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const failure = new Error("synthetic checkpoint failure");
    const snapshots: string[] = [];
    let registrationAttempts = 0;
    let closed = 0;
    let launched = 0;
    let completed = 0;
    let registered = 0;
    let maximum = 0;
    let active = 0;
    const input: DeepScanComposition = {
      scanId,
      scanDir: root,
      repository: join(root, "repository"),
      pluginRoot,
      startedAt: new Date().toISOString(),
      signal: new AbortController().signal,
      settings: {
        workers: childIds.length,
        subagents: 0,
        maxDiscoveryRuns: childIds.length,
        maxTimeHours: 1,
        stopAfterNoNew: childIds.length + 1,
        stopAfterConsecutiveErrors: 3,
      },
      scanOptions: {},
      onCost() {},
      createClient: () => ({
        async run(_repository, options = {}) {
          const index = launched++;
          const childId = childIds[index]!;
          const registration = { scanId: childId, scanDir: options.outputDir! };
          const first = options.onRegisteredScan!(registration);
          const second = options.onRegisteredScan!(registration);
          const outcomes = await Promise.allSettled([first, second]);
          if (failFirst) {
            expect(outcomes[0]).toEqual({
              status: "rejected",
              reason: failure,
            });
            expect(outcomes[1]).toEqual({
              status: "rejected",
              reason: failure,
            });
            await options.onRegisteredScan!(registration);
          } else
            expect(outcomes.map((value) => value.status)).toEqual([
              "fulfilled",
              "fulfilled",
            ]);
          registered++;
          expect(
            JSON.parse(await readFile(path, "utf8")).passes[index].scanId,
          ).toBe(childId);
          // Another identical caller still observes the durable registration.
          await options.onRegisteredScan!(registration);
          completed++;
          return new ScanResult({
            manifest: { ...manifest, scan: { ...manifest.scan, id: childId } },
            findings: { ...findings, scanId: childId },
            coverage: { ...coverage, scanId: childId },
            scanDir: options.outputDir!,
            threadId: "synthetic-child",
            turnResult: {},
          });
        },
        async close() {
          closed++;
        },
      }),
      async workbench(args, contents): Promise<JsonObject> {
        if (args[0] === "list-scans")
          return {
            scans:
              completed === childIds.length
                ? childIds.map((id, index) => ({
                    scanId: id,
                    scanDir: join(
                      root,
                      `artifacts/deep-scan/passes/pass-${index + 1}`,
                    ),
                    parentScanId: scanId,
                    targetPath: input.repository,
                    progress: { status: "complete" },
                  }))
                : [],
          };
        if (args[0] !== "save-scan-artifact")
          throw new Error(`Unexpected ${args[0]}`);
        const state = JSON.parse(contents!) as DeepScanCheckpoint;
        active++;
        maximum = Math.max(maximum, active);
        try {
          if (
            state.passes.some((pass) => pass.scanId) &&
            state.passes.every((pass) => !pass.completed)
          ) {
            expect(state.passes.map((pass) => pass.scanId)).toEqual(childIds);
            registrationAttempts++;
            if (registrationAttempts === 1) {
              entered.resolve();
              await release.promise;
              if (failFirst) throw failure;
            }
          }
          await mkdir(dirname(path), { recursive: true });
          await writeFile(`${path}.tmp`, contents!);
          await rename(`${path}.tmp`, path);
          snapshots.push(contents!);
          return {};
        } finally {
          active--;
        }
      },
      writer: {
        async restore(path, bytes) {
          await mkdir(dirname(join(root, path)), { recursive: true });
          await writeFile(join(root, path), bytes);
        },
      },
      async merge() {
        return { scanId, findings: [] };
      },
      async publish(draft) {
        expect(JSON.parse(await readFile(path, "utf8")).aggregate).toEqual(
          draft,
        );
      },
    };
    const pending = runDeepScans(input);
    try {
      await entered.promise;
      expect(registered).toBe(0);
      expect(completed).toBe(0);
    } finally {
      release.resolve();
    }
    const state = await pending;
    expect(registrationAttempts).toBe(failFirst ? 2 : 1);
    expect(maximum).toBe(1);
    expect(closed).toBe(childIds.length);
    expect(state.terminalReason).toBe("capped");
    expect(state.mergedScanIds).toEqual(childIds);
    expect(state.passes.every((pass) => pass.completed)).toBe(true);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(state);
    expect(
      snapshots.every(
        (snapshot, index) => index === 0 || snapshot !== snapshots[index - 1],
      ),
    ).toBe(true);
  },
);
