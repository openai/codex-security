import * as childProcess from "node:child_process";
import { chmod, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { DEEP_SCAN_CHECKPOINT } from "../src/deep-scan.js";
import { ScanInterruptedError } from "../src/errors.js";
import { executablePathForSpawn } from "../src/runtime.js";
import { ScanPermissionError } from "../src/scan-execution.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mockWorkbench, TEST_SNAPSHOT_DIGEST } from "./support/api-client.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

type Role = "discovery" | "merge" | "standard" | "custom" | "comparison";
type Scenario = "rejected" | "fallback" | "active";

async function fixture(
  role: Role,
  resumed: boolean,
  scenario: Scenario,
  surface: "sdk" | "cli",
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const codexHome = join(root, "codex-home");
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "synthetic-codex.cjs");
  const capture = join(root, "processes.jsonl");
  const scanId =
    role === "comparison" ? "scan_example_001" : "parent-permission-fixture";
  const threadId = "00000000-0000-4000-8000-000000000001";
  const cwd =
    role === "merge" ? join(scanDir, "artifacts/deep-scan/merge") : scanDir;
  const inheritedPermissions = {
    filesystem: { [join(root, "private")]: "deny" },
    network: { enabled: false },
  };
  await Promise.all([
    mkdir(repository),
    mkdir(codexHome),
    mkdir(scanDir, { mode: 0o700 }),
  ]);
  await writeFile(join(repository, "app.py"), "print('synthetic fixture')\n");
  await writeFile(capture, "");
  await writeFile(
    script,
    [
      'const fs = require("node:fs");',
      "const { parse } = require(" +
        JSON.stringify(createRequire(import.meta.url).resolve("smol-toml")) +
        ");",
      "const args = process.argv.slice(2);",
      "const record = (value) => fs.appendFileSync(" +
        JSON.stringify(capture) +
        ', JSON.stringify(value) + "\\n");',
      "  const config = {};",
      "  const merge = (target, value) => {",
      '    for (const [key, child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {}, child) : child;',
      "    return target;",
      "  };",
      '  for (let index = 0; index < args.length; index++) if (["-c", "--config"].includes(args[index])) merge(config, parse(args[++index]));',
      'record({ kind: args.includes("mcp") ? "mcp" : args.includes("app-server") ? "preflight" : "exec", args, cwd: process.cwd(), surface: process.env.CODEX_SECURITY_SURFACE, profile: config.default_permissions, permissions: config.permissions });',
      'if (args.includes("mcp")) { console.log("[]"); process.exit(0); }',
      'if (args.includes("app-server")) {',
      '  require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {',
      "    const request = JSON.parse(line);",
      "    if (request.id === undefined) return;",
      '    const result = request.method === "initialize" ? {} : request.method === "config/read" ? { config } : request.method === "permissionProfile/list" ? { data: [{ id: config.default_permissions, allowed: ' +
        (role === "comparison"
          ? 'config.default_permissions !== "codex_security_comparison" || '
          : "") +
        (scenario !== "rejected") +
        " }], nextCursor: null } : undefined;",
      '    if (!result) throw new Error("Unexpected fixture request " + request.method);',
      "    console.log(JSON.stringify({ id: request.id, result }));",
      "  });",
      "} else {",
      "  process.stdin.resume();",
      '  console.log(JSON.stringify({ type: "thread.started", thread_id: ' +
        JSON.stringify(threadId) +
        " }));",
      ...(role === "comparison"
        ? [
            'if (config.default_permissions === "codex_security_scan") {',
            "  fs.cpSync(" +
              JSON.stringify(join(PLUGIN_ROOT, "examples/completed-scan")) +
              ", process.env.CODEX_SECURITY_SCAN_DIR, { recursive: true });",
            '  fs.writeFileSync(require("node:path").join(process.env.CODEX_SECURITY_SCAN_DIR, "report.md"), "# Synthetic scan report\\n");',
            '  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));',
            "  process.exit(0);",
            "}",
          ]
        : []),
      ...(scenario === "active"
        ? []
        : [
            "  console.log(JSON.stringify(" +
              JSON.stringify(
                role === "standard"
                  ? {
                      type: "turn.failed",
                      error: { message: "synthetic standard execution" },
                    }
                  : {
                      type: "error",
                      message:
                        "Configured value for `permission_profile` is disallowed by requirements; falling back from `" +
                        (role === "comparison"
                          ? "codex_security_comparison"
                          : "codex_security_scan") +
                        "` to required value `:read-only`.",
                    },
              ) +
              "));",
          ]),
      '  process.on("SIGTERM", () => process.exit(0));',
      ...(role === "standard" ? [] : ["  setInterval(() => {}, 1000);"]),
      "}",
    ].join("\n"),
  );
  if (resumed) {
    await mkdir(join(codexHome, "sessions"));
    await writeFile(
      join(codexHome, "sessions", "rollout-" + threadId + ".jsonl"),
      JSON.stringify({ type: "session_meta", payload: { id: threadId, cwd } }) +
        "\n",
    );
  }
  const childDir = join(scanDir, "artifacts/deep-scan/passes/pass-1");
  if (role === "merge") {
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), childDir, {
      recursive: true,
    });
    await chmod(childDir, 0o700);
    await writeFile(
      join(scanDir, DEEP_SCAN_CHECKPOINT),
      JSON.stringify({
        version: 2,
        startedAt: new Date().toISOString(),
        passes: [{ directory: "artifacts/deep-scan/passes/pass-1" }],
        mergedScanIds: [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors: 0,
      }),
    );
  }
  const environment = Object.fromEntries(
    Object.entries({
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      CODEX_CLI_PATH: executable,
      OPENAI_API_KEY: "synthetic-fixture-key",
    }).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
  const commands: string[] = [];
  const warnings: string[] = [];
  const completedArtifacts = new Map<string, Buffer<ArrayBuffer>>();
  let customCalls = 0;
  const registration: JsonObject = {
    scanId,
    scanDir,
    targetId: "target_sha256_example",
    targetRevision: "unversioned",
    threadId: resumed ? threadId : null,
    recipe: { repository, target: { kind: "repository", paths: [] } },
    contract: {
      target: {
        allowedKinds: ["directory_snapshot"],
        requiredSnapshotDigest: TEST_SNAPSHOT_DIGEST,
      },
    },
  };
  const client = new CodexSecurity(
    { pluginPath: PLUGIN_ROOT },
    {
      environment,
      prepareRuntime: async () => ({
        ...preparedRuntime(codexHome),
        environment,
        persistentCredentialHome: true,
      }),
      resolvePluginPython: async () => process.execPath,
      prepareOutputDir: async () => scanDir,
      acquireScanExecution: async () => () => {},
      repositoryRevision: async () => null,
      prepareScanArtifactRestorer: async () => ({
        async prepareDirectory(path) {
          await mkdir(join(scanDir, path), { recursive: true });
        },
        async restore(path, contents) {
          await mkdir(dirname(join(scanDir, path)), { recursive: true });
          await writeFile(join(scanDir, path), contents);
        },
        async remove(path) {
          await rm(join(scanDir, path), { force: true });
        },
      }),
      runWorkbench: async (_options, args, input): Promise<JsonObject> => {
        commands.push(args[0]!);
        if (role === "comparison") {
          const current = {
            findingId: "csf_852f90d6e1177502ff113d4a",
            occurrenceId: "occ_e79cb19591e696572a1c22be",
          };
          const previous = {
            findingId: "previous",
            occurrenceId: "old",
            scanId: "prior",
            targetId: registration["targetId"]!,
          };
          if (args[0] === "list-global-findings")
            return { findings: [previous] };
          if (args[0] === "list-unmatched-scan-pairs")
            return {
              batches: [
                {
                  afterScanId: scanId,
                  afterFindings: [current],
                  beforeScans: [{ scanId: "prior", findings: [previous] }],
                },
              ],
            };
          if (args[0] === "complete-scan") {
            for (const file of [
              "scan-manifest.json",
              "findings.json",
              "coverage.json",
              "report.md",
            ])
              completedArtifacts.set(file, await readFile(join(scanDir, file)));
            return { scan: { scanId, progress: { status: "complete" } } };
          }
        }
        if (["register-cli-scan", "get-cli-scan-resume"].includes(args[0]!))
          return registration;
        if (args[0] === "get-scan-feedback")
          return {
            scanId,
            targetId: registration["targetId"]!,
            falsePositives: [],
          };
        if (args[0] === "list-scans")
          return {
            scans:
              role === "merge"
                ? [
                    {
                      scanId: "scan_example_001",
                      scanDir: childDir,
                      parentScanId: scanId,
                      targetPath: repository,
                      progress: { status: "complete" },
                    },
                  ]
                : [],
          };
        if (args[0] === "get-scan")
          return { scan: { progress: { status: "running" } } };
        if (args[0] === "save-scan-artifact") {
          await writeFile(join(scanDir, DEEP_SCAN_CHECKPOINT), input!);
          return {};
        }
        return mockWorkbench(args, input);
      },
      ...(role === "custom"
        ? {
            createCodex: () => ({
              startThread: () => ({
                id: null,
                async runStreamed() {
                  customCalls++;
                  throw new Error("synthetic custom factory");
                },
              }),
            }),
          }
        : {}),
    },
    { surface },
  );
  const originalSpawn = childProcess.spawn;
  const children: childProcess.ChildProcess[] = [];
  const childSignals: { kind: string; signal: AbortSignal | undefined }[] = [];
  const spawn = spyOn(childProcess, "spawn").mockImplementation(((
    ...args: Parameters<typeof childProcess.spawn>
  ) => {
    const [command, argv, options] = args;
    if (command !== executablePathForSpawn(executable) || !Array.isArray(argv))
      return originalSpawn(...args);
    const child = originalSpawn(process.execPath, [script, ...argv], options);
    children.push(child);
    childSignals.push({
      kind: argv.includes("mcp")
        ? "mcp"
        : argv.includes("app-server")
          ? "preflight"
          : "exec",
      signal: options?.signal,
    });
    return child;
  }) as typeof childProcess.spawn);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  const options: ScanOptions = {
    mode: role === "merge" ? "deep" : "standard",
    outputDir: scanDir,
    ...(role === "comparison" ? { inheritedPermissions } : {}),
    ...(role === "discovery" || role === "custom"
      ? { deepScanPass: true }
      : {}),
    ...(resumed || role === "merge" ? { resumeScanId: scanId } : {}),
    ...(role === "merge"
      ? { workers: 1, subagents: 0, maxDiscoveryRuns: 1, maxTimeHours: 1 }
      : {}),
    signal: controller.signal,
  };
  return {
    run: (onScanStarted?: () => void) =>
      client.run(repository, {
        ...options,
        onScanStarted,
        onWarning: (message) => warnings.push(message),
      }),
    abort: (reason: Error) => controller.abort(reason),
    signal: controller.signal,
    childSignals,
    commands,
    scanDir,
    cwd,
    repository,
    inheritedPermissions,
    warnings,
    completedArtifacts,
    customCalls: () => customCalls,
    observations: async () =>
      (await readFile(capture, "utf8"))
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line)),
    async close() {
      clearTimeout(timeout);
      try {
        await client.close();
        // The Codex SDK removes child listeners during cleanup; exit state is retained.
        for (const child of children)
          while (child.exitCode === null && child.signalCode === null)
            await new Promise<void>((resolve) => setImmediate(resolve));
      } finally {
        spawn.mockRestore();
      }
    },
  };
}

test.each(["sdk", "cli"] as const)(
  "%s default factory checks fresh and resumed discovery and merge permissions",
  async (surface) => {
    for (const role of ["discovery", "merge"] as const)
      for (const resumed of [false, true])
        for (const scenario of ["rejected", "fallback"] as const) {
          const h = await fixture(role, resumed, scenario, surface);
          try {
            await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
            const observations = await h.observations();
            expect(
              observations.filter(({ kind }) => kind === "preflight"),
            ).toMatchObject([{ cwd: h.cwd, surface }]);
            const executions = observations.filter(
              ({ kind }) => kind === "exec",
            );
            expect(executions).toHaveLength(scenario === "rejected" ? 0 : 1);
            if (executions.length)
              expect(executions[0].args.includes("resume")).toBe(resumed);
            expect(h.commands).not.toContain("complete-scan");
            if (role === "merge")
              expect(
                JSON.parse(
                  await readFile(join(h.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
                ),
              ).toMatchObject({ terminalReason: "failed", mergedScanIds: [] });
          } finally {
            await h.close();
          }
        }
  },
);

test("forwards the caller's exact cancellation reason to an active guarded child", async () => {
  const h = await fixture("discovery", false, "active", "sdk");
  const reason = new Error("synthetic caller cancellation");
  try {
    await expect(h.run(() => h.abort(reason))).rejects.toBeInstanceOf(
      ScanInterruptedError,
    );
    expect(h.signal.reason).toBe(reason);
    const execution = h.childSignals.filter(({ kind }) => kind === "exec");
    expect(execution).toHaveLength(1);
    expect(execution[0]!.signal?.reason).toBe(reason);
    expect(h.commands).not.toContain("complete-scan");
  } finally {
    await h.close();
  }
});

test.each(["standard", "custom"] as const)(
  "preserves the %s factory path",
  async (role) => {
    const h = await fixture(role, false, "rejected", "sdk");
    try {
      await expect(h.run()).rejects.toThrow(
        role === "standard"
          ? "synthetic standard execution"
          : "synthetic custom factory",
      );
      const observations = await h.observations();
      expect(
        observations.filter(({ kind }) => kind === "preflight"),
      ).toHaveLength(0);
      expect(observations.filter(({ kind }) => kind === "exec")).toHaveLength(
        role === "standard" ? 1 : 0,
      );
      expect(h.customCalls()).toBe(role === "custom" ? 1 : 0);
    } finally {
      await h.close();
    }
  },
);

test.each(["rejected", "fallback"] as const)(
  "preserves a completed scan when inherited comparison permissions are %s",
  async (scenario) => {
    const h = await fixture("comparison", false, scenario, "sdk");
    try {
      await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
      const observations = await h.observations();
      const comparison = observations.filter(
        ({ profile }) => profile === "codex_security_comparison",
      );
      expect(
        comparison.filter(({ kind }) => kind === "preflight"),
      ).toMatchObject([
        {
          cwd: h.repository,
          permissions: {
            codex_security_comparison: {
              extends: ":read-only",
              filesystem: h.inheritedPermissions.filesystem,
              network: { enabled: false },
            },
          },
        },
      ]);
      expect(comparison.filter(({ kind }) => kind === "exec")).toHaveLength(
        scenario === "rejected" ? 0 : 1,
      );
      h.abort(new Error("synthetic cancellation after completion"));
      // A later caller abort must not reach the completed main turn.
      expect(
        h.childSignals.find(({ kind }) => kind === "exec")!.signal?.aborted,
      ).toBe(false);
      if (scenario === "rejected")
        expect(
          h.childSignals.filter(({ kind }) => kind === "preflight").at(-1)!
            .signal?.aborted,
        ).toBe(false);
      expect(h.warnings).toEqual([]);
      expect(
        h.commands.filter((command) => command === "complete-scan"),
      ).toHaveLength(1);
      expect(h.commands).not.toContain("save-scan-comparison");
      expect(h.commands).not.toContain("fail-scan");
      expect(h.completedArtifacts.size).toBe(4);
      for (const [file, bytes] of h.completedArtifacts)
        expect(await readFile(join(h.scanDir, file))).toEqual(bytes);
    } finally {
      await h.close();
    }
  },
);
