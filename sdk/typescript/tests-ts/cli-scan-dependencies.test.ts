import { mkdir, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  ScanInterruptedError,
  ScanCostLimitExceededError,
} from "../src/errors.js";
import { estimateScanCost, formatUsd } from "../src/cost.js";
import type {
  CodexSecurityConfig,
  DependencyScanOptions,
  ScaResult,
} from "../src/index.js";
import type { ProjectConfigInput } from "../src/project-config-schema.js";
import { dependencies, fakeInterval, FakeSignals } from "./cli-fixtures.js";
import { createCliTest, selectionPrompt } from "./support/cli-run.js";
import { throwing } from "./support/errors.js";
import { runCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "cli-scan-dependencies-",
);
afterEach(cleanup);

function dependencyResult(
  status: ScaResult["status"] = "completed",
): ScaResult {
  return {
    schemaVersion: "sca/v0",
    status,
    startedAt: "2026-09-01T00:00:00Z",
    completedAt: "2026-09-01T00:01:00Z",
    repository: {
      path: "/synthetic/repository",
      revision: "synthetic-revision",
      dirty: false,
    },
    scanner: {
      name: "osv-scanner",
      version: "2.6.0",
      argv: ["scan", "source"],
      startedAt: "2026-09-01T00:00:00Z",
      completedAt: "2026-09-01T00:00:30Z",
      exitCode: 0,
      rawOutputPath: "/synthetic/output/osv.json",
      stderrPath: "/synthetic/output/osv.stderr",
      advisoryMode: "online",
      advisorySnapshotId: null,
    },
    coverage: {
      status: status === "completed" ? "complete" : status,
      inputs: [
        {
          path: "package-lock.json",
          sha256: "synthetic-digest",
          format: "npm",
          status: "scanned",
          reason: null,
        },
      ],
      configFiles: [],
      limitations: [],
      unresolvedPackages: 0,
    },
    components: [
      {
        id: "component-1",
        name: "synthetic-package",
        version: "1.0.0",
        ecosystem: "npm",
        sourcePath: "package-lock.json",
        dependencyGroups: [],
      },
    ],
    matches: [],
    assessments: [],
    diagnostics: [],
    model: { model: null, skillDigest: null, threadId: null, costUsd: null },
    outputDir: "/synthetic/output",
  };
}

function addMatch(result: ScaResult): void {
  result.scanner.exitCode = 1;
  result.matches.push({
    id: "match-1",
    componentId: "component-1",
    advisoryIds: ["SYNTHETIC-ADVISORY-1"],
    aliases: [],
    sourceAdvisories: [{ id: "SYNTHETIC-ADVISORY-1" }],
    severity: "HIGH",
    fixedVersions: ["1.0.1"],
    advisoryModifiedAt: [],
  });
  result.assessments.push({
    matchId: "match-1",
    status: result.status === "completed" ? "completed" : "failed",
    verdict: result.status === "completed" ? "confirmed" : null,
    triage: null,
    error: result.status === "completed" ? null : "Synthetic model unavailable",
  });
}

async function configFixture(config: ProjectConfigInput) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const settings = join(root, "settings");
  await mkdir(repository);
  await mkdir(settings);
  const configPath = join(settings, "scan.json");
  await writeFile(configPath, JSON.stringify(config));
  return { root, repository, settings, configPath };
}

describe("scan dependencies CLI", () => {
  test.each([
    "same signal",
    "different signal",
    "timer failure",
    "cursor failure",
  ])("restores dependency progress before forced exit: %s", async (mode) => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
    const signals = new FakeSignals();
    const result = dependencyResult("partial");
    const order: string[] = [];
    const restored: string[] = [];
    const forced: string[] = [];
    let now = 0;
    const repeated = mode === "different signal" ? "SIGTERM" : "SIGINT";
    const deps = dependencies({
      signals,
      onScanDependencies: async ({ signal }) => {
        signals.emit("SIGINT");
        expect(signal?.aborted).toBe(true);
        signals.emit("SIGINT");
        expect(forced).toEqual([]);
        now = mode === "different signal" ? 100 : 1_000;
        signals.emit(repeated);
        expect(order).toEqual(["stop", "restore", "force"]);
        expect(signals.listeners.get("SIGINT")?.size).toBe(0);
        expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
        return result;
      },
    });
    deps.now = () => now;
    deps.clearInterval = () => {
      order.push("stop");
      if (mode === "timer failure") throw new Error("Synthetic timer failure");
    };
    deps.writeSynchronously = (_stream, value) => {
      order.push("restore");
      restored.push(value);
      if (mode === "cursor failure")
        throw new Error("Synthetic terminal failure");
    };
    deps.forceExit = (signal) => {
      order.push("force");
      forced.push(signal);
    };
    expect(await runCli(["scan", "dependencies", "--json"], deps)).toBe(130);
    expect(forced).toEqual([repeated]);
    expect(restored).toEqual(["\u001B[?25h"]);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toContain("\u001B[?25l");
  });

  test.skipIf(process.platform === "win32").each([
    {
      label: "SIGINT with graceful cleanup",
      first: "SIGINT",
      repeated: null,
      exitCode: 130,
    },
    {
      label: "SIGTERM with graceful cleanup",
      first: "SIGTERM",
      repeated: null,
      exitCode: 143,
    },
    {
      label: "repeated SIGINT",
      first: "SIGINT",
      repeated: "SIGINT",
      exitCode: null,
    },
    {
      label: "repeated SIGTERM",
      first: "SIGTERM",
      repeated: "SIGTERM",
      exitCode: null,
    },
    {
      label: "SIGTERM after SIGINT",
      first: "SIGINT",
      repeated: "SIGTERM",
      exitCode: null,
    },
  ] as const)(
    "handles real $label during dependency cancellation",
    async ({ first, repeated, exitCode }) => {
      const result = dependencyResult("partial");
      const child = spawn(
        process.execPath,
        [
          "--eval",
          `
            import { writeSync } from "node:fs";
            import { main } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)};
            import { dependencies } from ${JSON.stringify(new URL("./cli-fixtures.ts", import.meta.url).href)};
            const notice = (value) => writeSync(1, "SYNTHETIC_SIGNAL_NOTICE:" + value + "\\n");
            const finish = Promise.withResolvers();
            let now = 0;
            const timers = new Set();
            process.stdin.setEncoding("utf8");
            process.stdin.on("data", (command) => {
              if (command.trim() === "repeat") {
                now = 1000;
                notice("repeat ready");
              } else finish.resolve();
            });
            process.stderr.isTTY = true;
            process.stderr.columns = 160;
            const deps = dependencies({
              onScanDependencies: async ({ signal }) => {
                const aborted = Promise.withResolvers();
                signal.addEventListener("abort", () => {
                  notice("aborted:" + signal.reason);
                  aborted.resolve();
                }, { once: true });
                notice("ready");
                await aborted.promise;
                await finish.promise;
                return ${JSON.stringify(result)};
              },
              onClose: () => notice("closed"),
            });
            Object.assign(deps, {
              now: () => now,
              addSignalListener: (signal, listener) => process.on(signal, listener),
              removeSignalListener: (signal, listener) => process.off(signal, listener),
              setInterval: (callback, delay) => {
                const timer = setInterval(callback, delay);
                timers.add(timer);
                return timer;
              },
              clearInterval: (timer) => { timers.delete(timer); clearInterval(timer); },
              writeSynchronously: (_stream, value) => {
                writeSync(2, value);
                notice("cursor restored synchronously");
              },
              forceExit: (signal) => {
                notice("forcing:" + signal + ":timers:" + timers.size);
                process.kill(process.pid, signal);
              },
            });
            const status = await main(["scan", "dependencies", "--json"], process.stdout, process.stderr, deps);
            process.stdin.destroy();
            process.exitCode = status;
          `,
        ],
        { stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
      );
      let stdout = "";
      let stderr = "";
      let notices = "";
      const received = new Map<
        string,
        ReturnType<typeof Promise.withResolvers<void>>
      >();
      const notice = (name: string) => {
        let entry = received.get(name);
        if (entry === undefined) {
          entry = Promise.withResolvers<void>();
          received.set(name, entry);
        }
        return entry;
      };
      child.stdout!.on("data", (chunk) => {
        stdout += chunk;
        notices =
          stdout
            .split("\n")
            .slice(0, -1)
            .filter((line) => line.startsWith("SYNTHETIC_SIGNAL_NOTICE:"))
            .map((line) => line.slice("SYNTHETIC_SIGNAL_NOTICE:".length))
            .join("\n") + "\n";
        for (const line of notices.split("\n").slice(0, -1))
          notice(line).resolve();
      });
      child.stderr!.on("data", (chunk) => {
        stderr += chunk;
      });
      const closed = new Promise<{
        code: number | null;
        signal: NodeJS.Signals | null;
      }>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ code, signal }));
      });
      const waitFor = async (name: string) =>
        await Promise.race([
          notice(name).promise,
          closed.then(() => {
            throw new Error(`Child exited before ${name}: ${stderr}`);
          }),
        ]);
      const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
      try {
        await waitFor("ready");
        child.kill(first);
        await waitFor(`aborted:${first}`);
        if (repeated === null) child.stdin!.end("finish\n");
        else {
          child.stdin!.write("repeat\n");
          await waitFor("repeat ready");
          child.kill(repeated);
        }
        expect(await closed, stderr).toEqual({
          code: exitCode,
          signal: repeated,
        });
        expect(stderr).toContain("\u001B[?25l");
        expect(stderr).toContain("\u001B[?25h");
        const output = stdout
          .split("\n")
          .filter((line) => !line.startsWith("SYNTHETIC_SIGNAL_NOTICE:"))
          .join("\n");
        if (repeated === null) {
          expect(JSON.parse(output)).toEqual(result);
          expect(notices).toContain("closed\n");
          expect(notices).not.toContain("forcing:");
        } else {
          expect(output).toBe("");
          expect(notices).toContain(
            `cursor restored synchronously\nforcing:${repeated}:timers:0\n`,
          );
          expect(notices).not.toContain("closed\n");
        }
      } finally {
        clearTimeout(timeout);
        child.kill("SIGKILL");
        await closed;
      }
    },
  );

  test("TTY progress shows observed work, quiet time, activity, and requested cost without changing JSON", async () => {
    const result = dependencyResult();
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
    Object.assign(stderr.stream, { columns: 240 });
    let now = 0;
    let redraw = () => {};
    let captured: DependencyScanOptions | undefined;
    let artifactReadyLine: string | undefined;
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      output_tokens: 1000,
    })!;
    const deps = dependencies({
      onScanDependencies: async (options) => {
        captured = options;
        now = 1_500;
        options.onOutputDirReady?.(result.outputDir);
        artifactReadyLine = stripVTControlCharacters(
          stderr
            .text()
            .split(/[\r\n]/)
            .at(-1)!,
        );
        options.onProgress?.({
          phase: "matching",
          inputsTotal: 2,
          inputsProcessed: 0,
          inputsFailed: 0,
          currentInput: "nested/package-lock.json",
          components: 0,
          matches: 0,
        });
        redraw();
        expect(stderr.text()).toContain("Matching 0/2 inputs, 0 failed");
        expect(stderr.text()).toContain("nested/package-lock.json");
        now = 2_000;
        options.onProgress?.({
          phase: "assessing",
          assessmentsTotal: 4,
          assessmentsCompleted: 1,
          assessmentsFailed: 1,
          current: {
            matchId: "match-3",
            componentId: "component-1",
            packageName: "synthetic-package",
            packageVersion: "1.0.0",
            advisoryIds: ["SYNTHETIC-3"],
          },
        });
        redraw();
        expect(stderr.text()).toContain("Assessing 1/4, 1 failed, 1 queued");
        expect(stderr.text()).toContain(
          "synthetic-package@1.0.0 (SYNTHETIC-3)",
        );
        now = 5_000;
        redraw();
        expect(stderr.text()).toContain("last event 3s");
        options.onCost?.(cost);
        options.onActivity?.({
          id: "match-3:tool",
          kind: "command",
          status: "running",
          description: "rg token=SYNTHETIC_VALUE . \u001b[31m",
          paths: [],
        });
        now = 6_000;
        redraw();
        expect(stderr.text()).toContain("last event 1s");
        expect(stderr.text()).toContain(`est. ${formatUsd(cost.estimatedUsd)}`);
        expect(stderr.text()).toContain(
          "Tool running: rg token=SYNTHETIC_VALUE",
        );
        expect(stderr.text()).not.toContain("\u001b[31m");
        expect(stderr.text()).not.toContain("Dependency scan partial");
        options.onProgress?.({ phase: "saving" });
        redraw();
        return result;
      },
    });
    deps.now = () => now;
    deps.setInterval = mock((callback) => {
      redraw = callback;
      return fakeInterval(callback);
    });
    deps.clearInterval = mock();
    expect(
      await runCli(["scan", "dependencies", "--json", "--show-cost"], deps),
    ).toBe(0);
    expect(artifactReadyLine).toContain("last event 0s");
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toContain("Saving dependency results");
    expect(stderr.text()).toContain("\u001b[?25h");
    expect(deps.clearInterval).toHaveBeenCalledTimes(
      (deps.setInterval as ReturnType<typeof mock>).mock.calls.length,
    );
    const finished = stderr.text();
    captured!.onProgress?.({ phase: "discovering" });
    captured!.onActivity?.({
      id: "late",
      kind: "tool",
      status: "running",
      description: "late activity",
      paths: [],
    });
    captured!.onOutputDirReady?.("late output");
    expect(stderr.text()).toBe(finished);
  });

  test("80-column progress retains the quiet duration and requested cost limit", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });
    Object.assign(stderr.stream, { columns: 80 });
    let now = 0;
    let redraw = () => {};
    const deps = dependencies({
      onScanDependencies: async (options) => {
        options.onProgress?.({
          phase: "assessing",
          assessmentsTotal: 4,
          assessmentsCompleted: 1,
          assessmentsFailed: 1,
          current: null,
        });
        const checkLine = (seconds: number, expectedCost: string) => {
          now += seconds * 1000;
          redraw();
          const line = stripVTControlCharacters(
            stderr.text().split("\r").at(-1)!,
          );
          expect(line).toContain(`last event ${seconds}s`);
          expect(line).toContain(`est. ${expectedCost}/$5.00`);
          expect(line.length).toBeLessThan(80);
        };
        checkLine(600, "n/a");
        const cost = estimateScanCost("gpt-5.6-sol", {
          input_tokens: 1000,
          output_tokens: 1000,
        })!;
        options.onCost?.(cost, 5);
        checkLine(600, formatUsd(cost.estimatedUsd));
        return dependencyResult();
      },
    });
    deps.now = () => now;
    deps.setInterval = (callback) => {
      redraw = callback;
      return fakeInterval(callback);
    };
    expect(
      await runCli(["scan", "dependencies", "--max-cost", "5"], deps),
    ).toBe(0);
  });

  test.each([false, true])(
    "redirected progress is opt-in with verbose=%p",
    async (verbose) => {
      const result = dependencyResult();
      const { stdout, stderr, runCli } = createCliTest(main);
      const deps = dependencies({
        onScanDependencies: async (options) => {
          options.onProgress?.({ phase: "discovering" });
          options.onProgress?.({
            phase: "matching",
            inputsTotal: 2,
            inputsProcessed: 1,
            inputsFailed: 0,
            currentInput: "nested/package-lock.json",
            components: 12,
            matches: 3,
          });
          options.onActivity?.({
            id: "tool",
            kind: "command",
            status: "running",
            description: "rg synthetic .",
            paths: [],
          });
          options.onOutputDirReady?.(result.outputDir);
          return result;
        },
      });
      deps.now = () => 2_000;
      deps.setInterval = mock(fakeInterval);
      expect(
        await runCli(
          ["scan", "dependencies", "--json", ...(verbose ? ["--verbose"] : [])],
          deps,
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(result);
      expect(stderr.text()).not.toContain("\u001b");
      expect(deps.setInterval).not.toHaveBeenCalled();
      if (verbose) {
        expect(stderr.text()).toContain("[00:00] Discovering dependency files");
        expect(stderr.text()).toContain(
          "Matching 1/2 inputs, 0 failed · nested/package-lock.json",
        );
        expect(stderr.text()).toContain("Tool running: rg synthetic .");
      } else {
        expect(stderr.text()).not.toContain("Discovering");
        expect(stderr.text()).not.toContain("Matching");
        expect(stderr.text()).not.toContain("rg synthetic");
      }
    },
  );

  test.each([{ CI: "true" }, { TERM: "dumb" }])(
    "disables live redraws for %j",
    async (environment) => {
      const { stderr, runCli } = createCliTest(main, { stderr: true });
      const deps = dependencies({
        environment,
        onScanDependencies: async (options) => {
          options.onProgress?.({ phase: "discovering" });
          return dependencyResult();
        },
      });
      deps.setInterval = mock(fakeInterval);
      expect(await runCli(["scan", "dependencies"], deps)).toBe(0);
      expect(deps.setInterval).not.toHaveBeenCalled();
      expect(stderr.text()).not.toContain("\u001b");
      expect(stderr.text()).not.toContain("Discovering");
    },
  );

  test.each(["partial", "failed", "throw"] as const)(
    "cleans up live progress after %s",
    async (outcome) => {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
      const close = mock();
      const deps = dependencies({
        onClose: close,
        onScanDependencies: async (options) => {
          options.onProgress?.({ phase: "discovering" });
          if (outcome === "throw") throw new Error("Synthetic scanner failure");
          return dependencyResult(outcome);
        },
      });
      deps.clearInterval = mock();
      expect(await runCli(["scan", "dependencies"], deps)).toBe(2);
      expect(stdout.text()).toBe("");
      expect(deps.clearInterval).toHaveBeenCalledTimes(1);
      expect(stderr.text()).toContain("\u001b[?25h");
      expect(close).toHaveBeenCalledTimes(1);
    },
  );

  test("budget interruption stops live progress and preserves checkpointed JSON", async () => {
    const result = dependencyResult("partial");
    result.outputDir = await temporaryDirectory();
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      output_tokens: 1000,
    })!;
    result.model.costUsd = cost.estimatedUsd;
    await writeFile(
      join(result.outputDir, "sca-result.json"),
      JSON.stringify(result),
    );
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
    const deps = dependencies({
      onScanDependencies: async (options) => {
        options.onCost?.(cost, 0.001);
        throw new ScanCostLimitExceededError(0.001, cost, result.outputDir);
      },
    });
    deps.clearInterval = mock();
    expect(
      await runCli(
        [
          "scan",
          "dependencies",
          "--json",
          "--full-output",
          "--max-cost",
          "0.001",
        ],
        deps,
      ),
    ).toBe(2);
    expect(JSON.parse(stdout.text())).toMatchObject({
      ok: false,
      data: result,
    });
    expect(stderr.text()).toContain("Estimated cost:");
    expect(stderr.text()).toContain("\u001b[?25h");
    expect(deps.clearInterval).toHaveBeenCalledTimes(1);
  });

  test.each([
    ["local JSON shortcut", ["scan", "dependencies", "--json"]],
    ["global JSON shortcut", ["--json", "scan", "dependencies"]],
    ["global JSON format", ["--format", "json", "scan", "dependencies"]],
    ["interleaved JSON shortcut", ["scan", "--json", "dependencies", "."]],
    [
      "interleaved JSON format",
      ["scan", "--format", "json", "dependencies", "."],
    ],
    ["local JSON format", ["scan", "dependencies", ".", "--format", "json"]],
    ["global equals format", ["--format=json", "scan", "dependencies"]],
    [
      "interleaved equals format",
      ["scan", "--format=json", "dependencies", "."],
    ],
    ["local equals format", ["scan", "dependencies", ".", "--format=json"]],
  ] as const)("routes %s without generic model preflight", async (_, args) => {
    const result = dependencyResult();
    const scan = mock(async (_options: DependencyScanOptions) => result);
    const close = mock();
    const deps = dependencies({ onScanDependencies: scan, onClose: close });
    deps.createSecurity = throwing("Source scan preflight must not run");
    deps.runCodex = throwing("Model authentication must not run");
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(await runCli(args, deps), stderr.text()).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(scan).toHaveBeenCalledTimes(1);
    expect(scan.mock.calls[0]?.[0]).toMatchObject({
      repositoryPath: resolve("/current/repository"),
      auth: "auto",
    });
    expect(close).toHaveBeenCalledTimes(1);
  });

  test.each([
    { label: "full output", flags: ["--json", "--full-output"] },
    { label: "token count", flags: ["--json", "--token-count"] },
    {
      label: "token window",
      flags: ["--json", "--token-limit=10", "--token-offset", "2"],
    },
  ])(
    "preserves $label controls before, between, and after command tokens",
    async ({ label, flags }) => {
      const result = dependencyResult();
      const outputs: string[] = [];
      const scan = mock(async (_options: DependencyScanOptions) => result);
      for (const args of [
        [...flags, "scan", "dependencies", "synthetic-repository"],
        ["scan", ...flags, "dependencies", "synthetic-repository"],
        ["scan", "dependencies", "synthetic-repository", ...flags],
      ]) {
        const { stdout, stderr, runCli } = createCliTest(main);
        const deps = dependencies({ onScanDependencies: scan });
        deps.createSecurity = throwing(
          "Output flags must retain the dependency route",
        );
        expect(await runCli(args, deps), stderr.text()).toBe(0);
        outputs.push(stdout.text());
      }
      expect(scan).toHaveBeenCalledTimes(3);
      for (const [options] of scan.mock.calls)
        expect(options.repositoryPath).toBe(
          resolve("/current/repository", "synthetic-repository"),
        );
      if (label === "full output") {
        for (const output of outputs)
          expect(JSON.parse(output)).toMatchObject({ ok: true, data: result });
      } else {
        expect(new Set(outputs).size).toBe(1);
        if (label === "token count")
          expect(JSON.parse(outputs[0]!)).toBeGreaterThan(0);
        else
          expect(outputs[0]!.length).toBeLessThan(
            JSON.stringify(result).length,
          );
      }
    },
  );

  for (const fullOutput of [false, true]) {
    test.each(["completed", "partial", "failed"] as const)(
      `retains %s advisory and coverage facts in ${fullOutput ? "full-output" : "raw"} JSON`,
      async (status) => {
        const result = dependencyResult(status);
        addMatch(result);
        const { stdout, stderr, runCli } = createCliTest(main);
        const code = await runCli(
          [
            "scan",
            "dependencies",
            ".",
            "--json",
            ...(fullOutput ? ["--full-output"] : []),
          ],
          dependencies({ onScanDependencies: async () => result }),
        );

        expect(code, stderr.text()).toBe(status === "completed" ? 0 : 2);
        const output = JSON.parse(stdout.text());
        expect(fullOutput ? output.data : output).toEqual(result);
        if (fullOutput) {
          expect(output.ok).toBe(status === "completed");
          if (status !== "completed")
            expect(output.error).toMatchObject({ code: "SCAN_FAILED" });
        }
      },
    );
  }

  test("prints a human summary and preserves diagnostic text on stderr", async () => {
    const result = dependencyResult("partial");
    addMatch(result);
    result.diagnostics = [
      "Synthetic scanner token=SYNTHETIC_VALUE\u001b[2J\ncontinued",
    ];
    result.coverage.limitations = ["Synthetic unsupported lockfile"];
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "dependencies"],
        dependencies({ onScanDependencies: async () => result }),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("partial");
    expect(stderr.text()).toContain("1 components, 1 advisory matches");
    expect(stderr.text()).toContain(result.outputDir);
    expect(stderr.text()).toContain("token=SYNTHETIC_VALUE");
    expect(stderr.text()).not.toContain("\u001b");
    expect(stderr.text()).toContain("Synthetic unsupported lockfile");
  });

  test.each([
    { label: "default", flags: [], cost: false, verbose: false },
    {
      label: "explicit cost and diagnostics",
      flags: ["--show-cost", "--verbose"],
      cost: true,
      verbose: true,
    },
    {
      label: "cost limit",
      flags: ["--max-cost", "3"],
      cost: true,
      verbose: false,
    },
  ])(
    "keeps $label presentation on stderr without changing JSON",
    async ({ flags, cost, verbose }) => {
      const result = dependencyResult();
      result.model.costUsd = 1.25;
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", "dependencies", "--json", ...flags],
          dependencies({ onScanDependencies: async () => result }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(result);
      expect(stderr.text().includes("Estimated cost:")).toBe(cost);
      if (cost) expect(stderr.text()).toContain("$1.25");
      expect(stderr.text().includes("osv-scanner")).toBe(verbose);
    },
  );

  test.each([
    {
      label: "primary debug level",
      environment: { CODEX_SECURITY_LOG_LEVEL: "debug" },
      flag: false,
      verbose: true,
    },
    {
      label: "fallback debug level",
      environment: { LOG_LEVEL: "debug" },
      flag: false,
      verbose: true,
    },
    {
      label: "trimmed case-insensitive primary level",
      environment: { CODEX_SECURITY_LOG_LEVEL: "  DeBuG  " },
      flag: false,
      verbose: true,
    },
    {
      label: "blank primary with trimmed case-insensitive fallback",
      environment: { CODEX_SECURITY_LOG_LEVEL: "  ", LOG_LEVEL: "  DEBUG  " },
      flag: false,
      verbose: true,
    },
    {
      label: "nondebug primary overrides debug fallback",
      environment: { CODEX_SECURITY_LOG_LEVEL: " info ", LOG_LEVEL: "debug" },
      flag: false,
      verbose: false,
    },
    {
      label: "explicit flag overrides nondebug levels",
      environment: { CODEX_SECURITY_LOG_LEVEL: "error", LOG_LEVEL: "warn" },
      flag: true,
      verbose: true,
    },
  ])(
    "uses $label for dependency diagnostics",
    async ({ environment, flag, verbose }) => {
      const result = dependencyResult();
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", "dependencies", "--json", ...(flag ? ["--verbose"] : [])],
          dependencies({ environment, onScanDependencies: async () => result }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(result);
      expect(stderr.text().includes("Dependency scan repository:")).toBe(
        verbose,
      );
      expect(stderr.text().includes("Scanner: osv-scanner")).toBe(verbose);
    },
  );

  test.each([
    { format: "raw JSON", fullOutput: false },
    { format: "full-output JSON", fullOutput: true },
  ])(
    "closes failed clients and retains structured diagnostics in $format",
    async ({ fullOutput }) => {
      const message = "Synthetic failure token=SYNTHETIC_VALUE\u001b[2J";
      const close = mock();
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "scan",
            "dependencies",
            "--json",
            ...(fullOutput ? ["--full-output"] : []),
          ],
          dependencies({
            onScanDependencies: async () => {
              throw new Error(message);
            },
            onClose: close,
          }),
        ),
      ).toBe(2);
      const output = JSON.parse(stdout.text());
      expect(fullOutput ? output.error : output).toMatchObject({
        code: "SCAN_FAILED",
        message,
      });
      if (fullOutput) {
        expect(output.ok).toBe(false);
        expect(output).not.toHaveProperty("data");
      }
      expect(stderr.text()).toContain("token=SYNTHETIC_VALUE");
      expect(stderr.text()).not.toContain("\u001b");
      expect(close).toHaveBeenCalledTimes(1);
    },
  );

  test.each([false, true])(
    "keeps completed JSON successful when optional diagnostics cannot be written (TTY=%p)",
    async (interactive) => {
      const result = dependencyResult();
      const { stdout, stderr, runCli } = createCliTest(main, {
        stderr: interactive,
      });
      stderr.stream.write = throwing("Synthetic closed diagnostic stream");

      expect(
        await runCli(
          ["scan", "dependencies", "--json", "--verbose"],
          dependencies({
            onScanDependencies: async (options) => {
              options.onProgress?.({ phase: "discovering" });
              options.onActivity?.({
                id: "tool",
                kind: "tool",
                status: "running",
                description: "Synthetic tool",
                paths: [],
              });
              return result;
            },
          }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(result);
    },
  );

  test.each([
    {
      phase: "verbose startup",
      flags: ["--verbose"],
      errorCode: "EPIPE",
      interactive: false,
    },
    {
      phase: "completion summary",
      flags: [],
      errorCode: "ENOSPC",
      interactive: false,
    },
    {
      phase: "live progress",
      flags: [],
      errorCode: "EPIPE",
      interactive: true,
    },
  ])(
    "survives an asynchronous $errorCode during $phase without losing JSON or cleanup",
    async ({ flags, errorCode, interactive }) => {
      const result = dependencyResult();
      const child = await runCommand(process.execPath, [
        "--eval",
        `
          import { Writable } from "node:stream";
          import { setImmediate as flush } from "node:timers/promises";
          import { main } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)};
          import { capture, dependencies } from ${JSON.stringify(new URL("./cli-fixtures.ts", import.meta.url).href)};
          const result = ${JSON.stringify(result)};
          const stdout = capture();
          let completed = 0;
          let closed = 0;
          const stderr = new Writable({
            write(_chunk, _encoding, callback) {
              setImmediate(() => callback(Object.assign(
                new Error("Synthetic diagnostic stream failure"),
                { code: ${JSON.stringify(errorCode)} },
              )));
            },
          });
          stderr.isTTY = ${interactive};
          const status = await main(
            ${JSON.stringify(["scan", "dependencies", "--json", ...flags])},
            stdout.stream,
            stderr,
            dependencies({
              onScanDependencies: async () => {
                await flush();
                completed += 1;
                return result;
              },
              onClose: () => { closed += 1; },
            }),
          );
          await flush();
          process.stdout.write(JSON.stringify({
            status, completed, closed,
            errorCode: stderr.errored?.code,
            errorListeners: stderr.listenerCount("error"),
            output: JSON.parse(stdout.text()),
          }));
        `,
      ]);

      expect(child.status, child.stderr).toBe(0);
      expect(child.stderr).toBe("");
      expect(JSON.parse(child.stdout)).toEqual({
        status: 0,
        completed: 1,
        closed: 1,
        errorCode,
        errorListeners: 0,
        output: result,
      });
    },
  );

  test.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "forwards %s, retains partial JSON, and removes listeners",
    async (signalName, code) => {
      const result = dependencyResult("partial");
      const signals = new FakeSignals();
      const close = mock();
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
      const clearInterval = mock();

      expect(
        await runCli(["scan", "dependencies", "--json", "--full-output"], {
          ...dependencies({
            signals,
            onClose: close,
            onScanDependencies: async ({ signal }) => {
              expect(signal?.aborted).toBe(false);
              signals.emit(signalName);
              expect(signal?.aborted).toBe(true);
              return result;
            },
          }),
          clearInterval,
        }),
      ).toBe(code);
      expect(JSON.parse(stdout.text())).toMatchObject({
        ok: false,
        data: result,
      });
      expect(close).toHaveBeenCalledTimes(1);
      expect(clearInterval).toHaveBeenCalledTimes(1);
      expect(stderr.text()).toContain("\u001b[?25h");
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    },
  );

  test("recovers checkpointed facts from an interrupted SDK operation", async () => {
    const outputDir = await temporaryDirectory();
    const result = { ...dependencyResult("partial"), outputDir };
    addMatch(result);
    await writeFile(join(outputDir, "sca-result.json"), JSON.stringify(result));
    const signals = new FakeSignals();
    const { stdout, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "dependencies", "--json", "--full-output"],
        dependencies({
          signals,
          onScanDependencies: async () => {
            signals.emit("SIGINT");
            throw new ScanInterruptedError("Synthetic cancellation", outputDir);
          },
        }),
      ),
    ).toBe(130);
    expect(JSON.parse(stdout.text())).toMatchObject({
      ok: false,
      data: result,
    });
  });

  test("honors a termination signal received while closing the client", async () => {
    const signals = new FakeSignals();
    const result = dependencyResult();
    const { stdout, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "dependencies", "--json", "--full-output"],
        dependencies({
          signals,
          onScanDependencies: async () => result,
          onClose: () => signals.emit("SIGTERM"),
        }),
      ),
    ).toBe(143);
    expect(JSON.parse(stdout.text())).toMatchObject({
      ok: false,
      data: result,
    });
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });

  test("applies project values, CLI overrides, and their respective path bases", async () => {
    const input = await configFixture({
      auth: "chatgpt",
      codex: {
        model: "synthetic-project-model",
        model_reasoning_effort: "medium",
        synthetic_setting: { enabled: true },
      },
      limits: { max_cost_usd_per_scan: 5 },
      output: { directory: "../project-output" },
    });
    for (const override of [false, true]) {
      const configs: CodexSecurityConfig[] = [];
      const scans: DependencyScanOptions[] = [];
      const { stderr, runCli } = createCliTest(main);
      const plugin = join(input.root, "plugin");
      expect(
        await runCli(
          [
            "scan",
            "dependencies",
            "repository",
            "-c",
            "settings/scan.json",
            ...(override
              ? [
                  "--auth",
                  "api-key",
                  "--model",
                  "synthetic-cli-model",
                  "--effort",
                  "high",
                  "--provider",
                  "amazon-bedrock",
                  "--codex",
                  "synthetic_setting.enabled=false",
                  "--max-cost",
                  "3",
                  "--output-dir",
                  "cli-output",
                  "--plugin-path",
                  plugin,
                  "--python",
                  "synthetic-python",
                ]
              : []),
          ],
          dependencies({
            currentDirectory: input.root,
            onConfig: (config) => configs.push(config),
            onScanDependencies: async (options) => {
              scans.push(options);
              return dependencyResult();
            },
          }),
        ),
        stderr.text(),
      ).toBe(0);
      expect(scans).toHaveLength(1);
      expect(scans[0]).toMatchObject({
        repositoryPath: input.repository,
        auth: override ? "api-key" : "chatgpt",
        maxCostUsd: override ? 3 : 5,
        outputDir: join(input.root, override ? "cli-output" : "project-output"),
      });
      expect(configs[0]?.codexOverrides).toMatchObject({
        model: override ? "synthetic-cli-model" : "synthetic-project-model",
        model_reasoning_effort: override ? "high" : "medium",
        synthetic_setting: { enabled: !override },
        ...(override ? { model_provider: "amazon-bedrock" } : {}),
      });
      if (override)
        expect(configs[0]).toMatchObject({
          pluginPath: plugin,
          pythonPath: "synthetic-python",
        });
    }
  });

  test.each([
    ["source scope", ["--path", "src"]],
    ["deep settings", ["--workers", "2"]],
    ["custom prompts", ["--scan-prompt-file", "instructions.md"]],
    ["severity policy", ["--fail-on-severity", "high"]],
    ["headless dashboard", ["--headless"]],
    ["dry-run", ["--dry-run"]],
    ["inline patch", ["--patch"]],
    ["archive", ["--archive-existing"]],
    ["unsupported Markdown", ["--format", "md"]],
    ["filtered facts", ["--filter-output", "matches"]],
    ["extra repository", [".", "extra"]],
  ] as const)("rejects %s before creating a client", async (_, flags) => {
    const initialize = mock();
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "dependencies", ...flags],
        dependencies({ onConfig: initialize }),
      ),
    ).toBe(2);
    expect(initialize).not.toHaveBeenCalled();
    expect(stderr.text()).not.toBe("");
    if (flags[0] === ".")
      expect(stderr.text()).toContain("Unexpected positional argument");
    else if (flags[0] !== "--format") expect(stderr.text()).toContain(flags[0]);
  });

  test.each([
    ["scan.mode", { scan: { mode: "standard" } }],
    ["scan.scope", { scan: { scope: { paths: ["src"] } } }],
    ["scan.knowledge_base", { scan: { knowledge_base: [] } }],
    ["scan.instructions_file", { scan: { instructions_file: "missing.md" } }],
    ["scan.validation_file", { scan: { validation_file: "missing.md" } }],
    ["scan.deep", { scan: { deep: {} } }],
    ["policy.fail_on_severity", { policy: { fail_on_severity: "high" } }],
  ] satisfies [string, ProjectConfigInput][])(
    "rejects explicitly configured %s before creating a client",
    async (field, config) => {
      const input = await configFixture(config);
      const initialize = mock();
      const { stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", "dependencies", "-c", input.configPath],
          dependencies({
            currentDirectory: input.repository,
            onConfig: initialize,
          }),
        ),
      ).toBe(2);
      expect(initialize).not.toHaveBeenCalled();
      expect(stderr.text()).toContain(field);
      expect(stderr.text()).not.toContain("ENOENT");
    },
  );

  test.each([
    {
      label: "relative dependencies directory",
      args: ["scan", "./dependencies", "--json"],
    },
    {
      label: "model value named dependencies",
      args: ["scan", "--model", "dependencies", "--json"],
    },
  ])("keeps $label on the source scan route", async ({ args }) => {
    const sourceScan = mock();
    const dependencyScan = mock(async () => dependencyResult());
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        args,
        dependencies({ onRun: sourceScan, onScanDependencies: dependencyScan }),
      ),
      stderr.text(),
    ).toBe(0);
    expect(sourceScan).toHaveBeenCalledTimes(1);
    expect(dependencyScan).not.toHaveBeenCalled();
  });

  test("does not promote a dependencies argument after the existing unsupported delimiter", async () => {
    const dependencyScan = mock(async () => dependencyResult());
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "--json", "--", "dependencies"],
        dependencies({ onScanDependencies: dependencyScan }),
      ),
    ).toBe(2);
    expect(stderr.text()).not.toBe("");
    expect(dependencyScan).not.toHaveBeenCalled();
  });

  test.each(["--format", "--token-limit"])(
    "validates dependencies as a %s value without selecting a subcommand",
    async (flag) => {
      const initialize = mock();
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", flag, "dependencies"],
          dependencies({ onConfig: initialize }),
        ),
      ).toBe(2);
      expect(initialize).not.toHaveBeenCalled();
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        flag === "--format" ? "Invalid format" : `Invalid value for ${flag}`,
      );
      expect(stderr.text()).toContain('"dependencies"');
    },
  );
});

test.each([
  "selection",
  "rejection",
  "interruption",
  "pause write failure",
] as const)(
  "dependency authentication prompt pauses live progress: %s",
  async (ending) => {
    const signals = new FakeSignals();
    const result = dependencyResult();
    addMatch(result);
    const { stderr, runCli } = createCliTest(main, { stderr: true });
    Object.assign(stderr.stream, { columns: 240 });
    const started = Promise.withResolvers<void>();
    const answer = Promise.withResolvers<"chatgpt" | "api-key">();
    const activeTimers = new Map<NodeJS.Timeout, () => void>();
    let now = 0;
    let timersStarted = 0;
    let promptStarted = false;
    let pauseFailures = 0;
    let promptSignal: AbortSignal | undefined;
    let closed = 0;
    let afterSelectionTimers: number | undefined;
    let afterSelectionOutput: string | undefined;
    let selectedAuth: DependencyScanOptions["auth"];
    const write = stderr.stream.write;
    stderr.stream.write = (chunk) => {
      if (
        ending === "pause write failure" &&
        !promptStarted &&
        chunk === "\n"
      ) {
        pauseFailures++;
        throw new Error("Synthetic progress write failure");
      }
      return write(chunk);
    };
    const deps = dependencies({
      environment: { OPENAI_API_KEY: "synthetic-progress-auth-key" },
      signals,
    });
    deps.now = () => now;
    deps.setInterval = (callback) => {
      const handle = fakeInterval(callback);
      activeTimers.set(handle, callback);
      timersStarted++;
      return handle;
    };
    deps.clearInterval = (handle) => {
      activeTimers.delete(handle);
    };
    deps.hasStoredChatGPTSignIn = async () => true;
    deps.scanAuthenticationPrompt = selectionPrompt(
      async (question, choices, _presentation, signal) => {
        promptSignal = signal;
        promptStarted = true;
        stderr.stream.write(`${question}\n> ChatGPT subscription`);
        started.resolve();
        const selected = await answer.promise;
        return choices.find((choice) => choice.value === selected)!.value;
      },
    );
    // Exercise the real CLI chooser after the SDK's preparing-assessment event.
    // Scanner checkpoint and auth propagation are covered by the SDK tests.
    deps.createDependencySecurity = (_config, chooseAuthentication) => ({
      scanDependencies: async (options) => {
        options.onProgress?.({ phase: "preparing_assessment" });
        selectedAuth = await chooseAuthentication!(
          options.auth,
          options.signal!,
        );
        afterSelectionTimers = activeTimers.size;
        options.onProgress?.({ phase: "saving" });
        const before = stderr.text();
        now = 3_000;
        for (const tick of activeTimers.values()) tick();
        afterSelectionOutput = stderr.text().slice(before.length);
        return result;
      },
      close: async () => {
        closed++;
      },
    });
    const run = runCli(["scan", "dependencies"], deps);
    await started.promise;
    const timersDuringPrompt = activeTimers.size;
    const beforeTick = stderr.text();
    now = 2_000;
    for (const tick of activeTimers.values()) tick();
    const writesDuringPrompt = stderr.text().slice(beforeTick.length);
    if (ending === "rejection")
      answer.reject(new Error("Synthetic prompt rejection"));
    else if (ending === "interruption") signals.emit("SIGINT");
    else answer.resolve("chatgpt");
    const status = await run;
    if (ending === "interruption") answer.resolve("chatgpt");
    expect(status).toBe(
      ending === "rejection" ? 2 : ending === "interruption" ? 130 : 0,
    );
    expect(closed).toBe(1);
    expect(activeTimers.size).toBe(0);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    expect(timersDuringPrompt).toBe(0);
    expect(writesDuringPrompt).toBe("");
    expect(timersStarted).toBe(ending === "selection" ? 2 : 1);
    if (ending === "selection") {
      expect(beforeTick).toContain("\n\u001b[?25hBoth a ChatGPT sign-in");
      expect(afterSelectionTimers).toBe(1);
      expect(afterSelectionOutput).toContain("Saving dependency results");
      expect(selectedAuth).toBe("chatgpt");
    } else if (ending === "pause write failure") {
      expect(pauseFailures).toBe(1);
      expect(afterSelectionTimers).toBe(0);
      expect(afterSelectionOutput).toBe("");
      expect(selectedAuth).toBe("chatgpt");
    } else {
      expect(afterSelectionTimers).toBeUndefined();
      if (ending === "interruption") expect(promptSignal?.aborted).toBe(true);
      else expect(stderr.text()).toContain("Synthetic prompt rejection");
    }
  },
);

test.each([
  "explicit ChatGPT",
  "explicit API key",
  "no API key",
  "no stored sign-in",
  "non-TTY",
  "noninteractive input",
  "JSON",
  "JSONL",
  "external provider",
  "zero matches",
] as const)(
  "dependency authentication leaves prompt-free progress unchanged: %s",
  async (mode) => {
    const terminal = mode !== "non-TTY";
    const { stderr, runCli } = createCliTest(main, { stderr: terminal });
    const result = dependencyResult();
    if (mode !== "zero matches") addMatch(result);
    const activeTimers = new Set<NodeJS.Timeout>();
    let timersStarted = 0;
    let prompts = 0;
    let probes = 0;
    const deps = dependencies({
      environment:
        mode === "no API key"
          ? {}
          : { OPENAI_API_KEY: "synthetic-progress-auth-key" },
    });
    deps.setInterval = (callback) => {
      const handle = fakeInterval(callback);
      activeTimers.add(handle);
      timersStarted++;
      return handle;
    };
    deps.clearInterval = (handle) => {
      activeTimers.delete(handle);
    };
    deps.hasStoredChatGPTSignIn = async () => {
      probes++;
      return false;
    };
    deps.scanAuthenticationPrompt = selectionPrompt(
      async (_question, choices) => {
        prompts++;
        return choices[0]!.value;
      },
      () => mode !== "noninteractive input",
    );
    deps.createDependencySecurity = (_config, chooseAuthentication) => ({
      scanDependencies: async (options) => {
        options.onProgress?.({ phase: "preparing_assessment" });
        if (result.matches.length > 0)
          await chooseAuthentication?.(options.auth, options.signal!);
        return result;
      },
      close: async () => {},
    });
    const flags =
      mode === "explicit ChatGPT"
        ? ["--auth", "chatgpt"]
        : mode === "explicit API key"
          ? ["--auth", "api-key"]
          : mode === "JSON"
            ? ["--json"]
            : mode === "JSONL"
              ? ["--format", "jsonl"]
              : mode === "external provider"
                ? ["--provider", "fireworks", "--model", "synthetic-model"]
                : [];
    expect(await runCli(["scan", "dependencies", ...flags], deps)).toBe(0);
    expect(prompts).toBe(0);
    expect(probes).toBe(mode === "no stored sign-in" ? 1 : 0);
    expect(timersStarted).toBe(terminal ? 1 : 0);
    expect(activeTimers.size).toBe(0);
    expect(stderr.text().split("\u001b[?25l").length - 1).toBe(
      terminal ? 1 : 0,
    );
    expect(stderr.text().split("\u001b[?25h").length - 1).toBe(
      terminal ? 1 : 0,
    );
    expect(stderr.text()).not.toContain("Both a ChatGPT sign-in");
  },
);
