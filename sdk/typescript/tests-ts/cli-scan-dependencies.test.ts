import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { ScanInterruptedError } from "../src/errors.js";
import type {
  CodexSecurityConfig,
  DependencyScanOptions,
  ScaResult,
} from "../src/index.js";
import type { ProjectConfigInput } from "../src/project-config-schema.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
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

  test("keeps completed JSON successful when optional diagnostics cannot be written", async () => {
    const result = dependencyResult();
    const { stdout, stderr, runCli } = createCliTest(main);
    stderr.stream.write = throwing("Synthetic closed diagnostic stream");

    expect(
      await runCli(
        ["scan", "dependencies", "--json", "--verbose"],
        dependencies({ onScanDependencies: async () => result }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
  });

  test.each([
    { phase: "verbose startup", flags: ["--verbose"], errorCode: "EPIPE" },
    { phase: "completion summary", flags: [], errorCode: "ENOSPC" },
  ])(
    "survives an asynchronous $errorCode during $phase without losing JSON or cleanup",
    async ({ flags, errorCode }) => {
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
      const { stdout, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", "dependencies", "--json", "--full-output"],
          dependencies({
            signals,
            onClose: close,
            onScanDependencies: async ({ signal }) => {
              expect(signal?.aborted).toBe(false);
              signals.emit(signalName);
              expect(signal?.aborted).toBe(true);
              return result;
            },
          }),
        ),
      ).toBe(code);
      expect(JSON.parse(stdout.text())).toMatchObject({
        ok: false,
        data: result,
      });
      expect(close).toHaveBeenCalledTimes(1);
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
