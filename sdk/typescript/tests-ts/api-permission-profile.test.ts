import * as childProcess from "node:child_process";
import { chmod, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { stringify } from "smol-toml";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { DEEP_SCAN_CHECKPOINT } from "../src/deep-scan.js";
import { ScanInterruptedError } from "../src/errors.js";
import { createPermissionCheckedCodex } from "../src/permission-profile.js";
import {
  bootstrapPlugin,
  executablePathForSpawn,
  resolveCodexCommand,
  type PluginInstall,
} from "../src/runtime.js";
import { ScanPermissionError } from "../src/scan-execution.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { semanticFinding } from "./helpers/semantic-scan.js";
import { mockWorkbench, TEST_SNAPSHOT_DIGEST } from "./support/api-client.js";
import {
  createApiTestFixtures,
  copyPluginVariant,
  preparedRuntime,
} from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

type Role =
  "discovery" | "merge" | "standard" | "custom" | "comparison" | "followup";
type Scenario =
  | "rejected"
  | "fallback"
  | "active"
  | "substituted-default"
  | "substituted-profile";

async function fixture(
  role: Role,
  resumed: boolean,
  scenario: Scenario,
  surface: "sdk" | "cli",
  replaceEnvironmentDuringPreparation = false,
  selectedProfile: "selected" | "missing" | undefined = undefined,
  composedDiscovery = false,
  replaceSelectedPlugin = false,
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, role === "followup" ? "scan[ab]" : "scan");
  const codexHome = join(root, "codex-home");
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "synthetic-codex.cjs");
  const capture = join(root, "processes.jsonl");
  const projects = Object.fromEntries(
    Array.from({ length: 2_000 }, (_, index) => [
      join(root, `synthetic-project-${index}`),
      { trust_level: "untrusted" },
    ]),
  );
  const scanId =
    role === "comparison" || role === "followup"
      ? "scan_example_001"
      : "parent-permission-fixture";
  const threadId = "00000000-0000-4000-8000-000000000001";
  const childId = "child-permission-fixture";
  const childDir = join(scanDir, "artifacts/deep-scan/passes/pass-1");
  const cwd =
    role === "merge"
      ? join(scanDir, "artifacts/deep-scan/merge")
      : composedDiscovery
        ? childDir
        : scanDir;
  const inheritedPermissions = {
    filesystem: {
      [join(root, "private")]: "deny",
      ...(role === "followup"
        ? { [scanDir]: { ".": "write", private: "deny" } }
        : {}),
    },
    network: { enabled: false },
  };
  await Promise.all([
    mkdir(repository),
    mkdir(codexHome, { mode: 0o700 }),
    mkdir(scanDir, { mode: 0o700 }),
  ]);
  await writeFile(join(repository, "app.py"), "print('synthetic fixture')\n");

  await writeFile(capture, "");
  await writeFile(
    join(codexHome, "config.toml"),
    [
      'model_provider = "synthetic_secondary"',
      'forced_login_method = "chatgpt"',
      'forced_chatgpt_workspace_id = "synthetic-secondary-workspace"',
    ].join("\n"),
  );
  let selectedPlugin: PluginInstall | undefined;
  let replacementPlugin: string | undefined;
  const pluginOptions = {
    isolateSelection: true,
    codexCommand: resolveCodexCommand({}),
    environment: { CODEX_HOME: codexHome },
  };
  if (replaceSelectedPlugin) {
    await writeFile(join(codexHome, "config.toml"), "");
    const selected = await copyPluginVariant(root, "selected-a");
    replacementPlugin = await copyPluginVariant(root, "selected-b");
    selectedPlugin = await bootstrapPlugin(codexHome, selected, pluginOptions);
  }
  await writeFile(
    script,
    [
      'const fs = require("node:fs");',
      "const { parse } = require(" +
        JSON.stringify(createRequire(import.meta.url).resolve("smol-toml")) +
        ");",
      "const args = process.argv.slice(2);",
      ...(replaceSelectedPlugin
        ? [
            'if (args.includes("plugin")) {',
            '  const result = require("node:child_process").spawnSync(' +
              JSON.stringify(
                executablePathForSpawn(pluginOptions.codexCommand.command),
              ) +
              ', args, { stdio: "inherit" });',
            "  process.exit(result.status ?? 1);",
            "}",
          ]
        : []),
      "const record = (value) => fs.appendFileSync(" +
        JSON.stringify(capture) +
        ', JSON.stringify(value) + "\\n");',
      '  const config = parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME, "config.toml"), "utf8"));',
      "  const merge = (target, value) => {",
      '    for (const [key, child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {}, child) : child;',
      "    return target;",
      "  };",
      '  for (let index = 0; index < args.length; index++) if (["-c", "--config"].includes(args[index])) merge(config, parse(args[++index]));',
      'record({ kind: args.includes("mcp") ? "mcp" : args.includes("app-server") ? "preflight" : "exec", args, cwd: process.cwd(), surface: process.env.CODEX_SECURITY_SURFACE, profile: config.default_permissions, permissions: config.permissions, mcpServers: config.mcp_servers, literalSetting: config["synthetic.setting"], projects: config.projects, context: process.env.SYNTHETIC_EXECUTION_CONTEXT, workerLimit: config.features?.multi_agent_v2?.max_concurrent_threads_per_session, snapshotLimit: process.env.CODEX_SECURITY_CONFIG_PATH ? parse(fs.readFileSync(process.env.CODEX_SECURITY_CONFIG_PATH, "utf8")).features?.multi_agent_v2?.max_concurrent_threads_per_session : null, selectedProfile: config.profile ?? null, modelProvider: config.model_provider, modelProviders: config.model_providers, model: config.model, effort: config.model_reasoning_effort, forcedLogin: config.forced_login_method ?? null, forcedWorkspace: config.forced_chatgpt_workspace_id ?? null, apiKey: process.env.CODEX_API_KEY });',
      ...(replaceSelectedPlugin
        ? [
            'const servers = JSON.parse(require("node:child_process").execFileSync(' +
              JSON.stringify(
                executablePathForSpawn(pluginOptions.codexCommand.command),
              ) +
              ', ["mcp", "list", "--json", "-c", "features.plugins=true"], { encoding: "utf8" }));',
            'record({ kind: "plugin-selection", marker: servers.find(({ name }) => name === "synthetic-plugin")?.transport.args[0] });',
          ]
        : []),
      "if (config.profile !== undefined) {",
      '  const result = require("node:child_process").spawnSync(' +
        JSON.stringify(
          executablePathForSpawn(resolveCodexCommand({}).command),
        ) +
        ', ["mcp", "list", "--json"], { encoding: "utf8" });',
      '  record({ kind: "profile-validation", exitCode: result.status, stderr: result.stderr });',
      '  process.stderr.write(result.stderr ?? "");',
      "  process.exit(result.status ?? 1);",
      "}",
      'if (args.includes("mcp")) {',
      '  const result = require("node:child_process").spawnSync(' +
        JSON.stringify(
          executablePathForSpawn(resolveCodexCommand({}).command),
        ) +
        ', args, { stdio: "inherit" });',
      "  process.exit(result.status ?? 1);",
      "}",
      ...(role === "followup"
        ? [
            `if (args.includes("app-server") && process.cwd() !== ${JSON.stringify(scanDir)}) {`,
            '  const result = require("node:child_process").spawnSync(' +
              JSON.stringify(
                executablePathForSpawn(resolveCodexCommand({}).command),
              ) +
              ', [...args.slice(0, -2), "mcp", "list", "--json", "-c", "features.plugins=false"], { encoding: "utf8" });',
            '  record({ kind: "permission-validation", exitCode: result.status, stderr: result.stderr });',
            '  if (result.status !== 0) { process.stderr.write(result.stderr ?? ""); process.exit(result.status ?? 1); }',
            "}",
          ]
        : []),
      'if (args.includes("app-server")) {',
      "  const selected = config.default_permissions;",
      "  const profile = config.permissions[selected];",
      '  profile.description = "Synthetic description"; if (profile.network) profile.network.fixtureNull = null;',
      ...(scenario === "substituted-default"
        ? ['  config.default_permissions = ":read-only";']
        : []),
      ...(scenario === "substituted-profile"
        ? [
            '  for (const [path, value] of Object.entries(profile.filesystem)) if (value === "deny") delete profile.filesystem[path];',
          ]
        : []),
      '  require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {',
      "    const request = JSON.parse(line);",
      '    record({ kind: "request", method: request.method, params: request.params });',
      "    if (request.id === undefined) return;",
      '    const result = request.method === "initialize" ? {} : request.method === "config/read" ? { config } : request.method === "permissionProfile/list" ? request.params?.cursor !== "selected-page" ? { data: [{ id: "other-profile", allowed: true }], nextCursor: "selected-page" } : { data: [{ id: selected, allowed: ' +
        (role === "comparison"
          ? 'config.default_permissions !== "codex_security_comparison" || '
          : role === "followup"
            ? `config.permissions[config.default_permissions].filesystem[${JSON.stringify(scanDir)}]?.["."] !== "read" || `
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
      ...(role === "comparison" || role === "followup"
        ? [
            role === "followup"
              ? `if (config.permissions.codex_security_scan.filesystem[${JSON.stringify(scanDir)}]?.["."] !== "read") {`
              : "if (config.features.plugins !== false) {",
            "  fs.cpSync(" +
              JSON.stringify(join(PLUGIN_ROOT, "examples/completed-scan")) +
              ", process.env.CODEX_SECURITY_SCAN_DIR, { recursive: true });",
            '  fs.writeFileSync(require("node:path").join(process.env.CODEX_SECURITY_SCAN_DIR, "report.md"), "# Synthetic scan report\\n");',
            ...(role === "followup"
              ? [
                  `  fs.mkdirSync(${JSON.stringify(join(scanDir, "private"))}, { recursive: true });`,
                  `  fs.writeFileSync(${JSON.stringify(join(scanDir, "private", "evidence.txt"))}, "synthetic restricted evidence");`,
                ]
              : []),
            '  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));',
            "  process.exit(0);",
            "}",
          ]
        : []),
      ...(role === "followup" && process.platform === "linux"
        ? [
            'const output = args[args.indexOf("--cd") + 1];',
            'const overrides = args.flatMap((arg, index) => ["-c", "--config"].includes(arg) ? ["-c", args[index + 1]] : []);',
            'const checked = require("node:child_process").spawnSync(' +
              JSON.stringify(
                executablePathForSpawn(resolveCodexCommand({}).command),
              ) +
              ', ["sandbox", "-P", "codex_security_scan", "-C", output, ...overrides, "--", process.execPath, "-e", ' +
              JSON.stringify(
                [
                  'const fs = require("node:fs");',
                  `fs.writeFileSync(require("node:path").join(process.cwd(), "follow-up.txt"), "synthetic follow-up");`,
                  `for (const operation of [() => fs.chmodSync(${JSON.stringify(join(scanDir, "report.md"))}, 0o600), () => fs.writeFileSync(${JSON.stringify(join(scanDir, "report.md"))}, "forbidden update"), () => fs.readFileSync(${JSON.stringify(join(scanDir, "private", "evidence.txt"))})]) {`,
                  '  try { operation(); throw new Error("restricted scan access succeeded"); } catch (error) { if (!["EACCES", "EPERM", "EROFS"].includes(error.code)) throw error; }',
                  "}",
                ].join("\n"),
              ) +
              '], { encoding: "utf8" });',
            'record({ kind: "followup-write-check", exitCode: checked.status, stdout: checked.stdout, stderr: checked.stderr });',
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
  if (composedDiscovery && resumed) {
    await mkdir(childDir, { recursive: true, mode: 0o700 });
    await writeFile(
      join(scanDir, DEEP_SCAN_CHECKPOINT),
      JSON.stringify({
        version: 3,
        startedAt: new Date().toISOString(),
        passes: [
          { directory: "artifacts/deep-scan/passes/pass-1", scanId: childId },
        ],
        mergedScanIds: [],
        aggregate: null,
        noNewStreak: 0,
        consecutiveErrors: 0,
      }),
    );
  }
  if (role === "merge") {
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), childDir, {
      recursive: true,
    });
    await chmod(childDir, 0o700);
    await writeFile(
      join(scanDir, DEEP_SCAN_CHECKPOINT),
      JSON.stringify({
        version: 3,
        startedAt: new Date().toISOString(),
        passes: [1, 2].map((index) => ({
          directory: `artifacts/deep-scan/passes/pass-${index}`,
        })),
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
      SYNTHETIC_EXECUTION_CONTEXT: "selected-scan",
    }).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
  const commands: string[] = [];
  const recipes: JsonObject[] = [];
  const warnings: string[] = [];
  const completedArtifacts = new Map<string, Buffer<ArrayBuffer>>();
  let customCalls = 0;
  let customProjects: unknown;
  let preserveCodexHomeConfig = false;
  const registration: JsonObject = {
    scanId,
    scanDir,
    targetId: "target_sha256_example",
    targetRevision: "unversioned",
    threadId: resumed && !composedDiscovery ? threadId : null,
    recipe: { repository, target: { kind: "repository", paths: [] } },
    contract: {
      target: {
        allowedKinds: ["directory_snapshot"],
        requiredSnapshotDigest: TEST_SNAPSHOT_DIGEST,
      },
    },
  };
  const runtimeEnvironment = { ...environment };
  const client = new CodexSecurity(
    {
      pluginPath: PLUGIN_ROOT,
      codexOverrides: {
        "synthetic.setting": "literal-top-level-value",
        projects,
        mcp_servers: {
          "codex-security": { command: "synthetic-workbench", enabled: true },
          synthetic: {
            command: "synthetic-mcp",
            env: { SETTING: "inherited" },
          },
          "synthetic.literal": {
            command: "synthetic-mcp",
            env: { "SETTING.KEY": "literal-value" },
          },
        },
        ...(selectedProfile
          ? {
              profile: selectedProfile,
              profiles: {
                selected: {
                  model_provider: "synthetic.selected",
                  model: "gpt-6-astra",
                  model_reasoning_effort: "high",
                },
              },
              model_providers: {
                "synthetic.selected": {
                  name: "Synthetic selected",
                  base_url: "https://example.invalid/v1",
                  env_key: "OPENAI_API_KEY",
                  wire_api: "responses",
                },
              },
            }
          : {}),
      },
    },
    {
      environment,
      prepareRuntime: async () => ({
        ...preparedRuntime(codexHome),
        ...(selectedPlugin === undefined ? {} : { plugin: selectedPlugin }),
        configPath: join(root, "preflight.toml"),
        environment: runtimeEnvironment,
        persistentCredentialHome: true,
        preserveCodexHomeConfig,
      }),
      resolvePluginPython: async () => {
        if (replacementPlugin !== undefined) {
          await bootstrapPlugin(codexHome, replacementPlugin, pluginOptions);
          replacementPlugin = undefined;
        }
        if (replaceEnvironmentDuringPreparation) {
          environment["CODEX_CLI_PATH"] = join(root, "later-executable");
          environment["OPENAI_API_KEY"] = "synthetic-later-key";
          environment["SYNTHETIC_EXECUTION_CONTEXT"] = "another-scan";
        }
        return process.execPath;
      },
      prepareOutputDir: async (requested) => {
        await mkdir(requested ?? scanDir, { recursive: true, mode: 0o700 });
        return requested ?? scanDir;
      },
      acquireScanExecution: async () => () => {},
      repositoryRevision: async () => null,
      prepareScanArtifactRestorer: async () => ({
        async projectChild(parentScanId, sourceScanId, sourceDirectory) {
          const finding = semanticFinding({
            identity: { anchor: sourceScanId },
            locations: [{ path: "app.py", startLine: 1 }],
            provenance: {
              source: "local_plugin",
              sourceFindingIds: [`${sourceScanId}:0`],
            },
          });
          return {
            scanId: sourceScanId,
            scanDir: sourceDirectory,
            sourceFindings: [finding],
            draft: {
              scanId: parentScanId,
              findings: [finding],
              coverage: {
                completeness: "complete",
                surfaces: [],
                explicitExclusions: [],
                deferred: [],
              },
            },
          };
        },
        async prepareDirectory(path) {
          await mkdir(join(scanDir, path), { recursive: true });
        },
        async restore(path, contents) {
          await mkdir(dirname(join(scanDir, path)), { recursive: true });
          await writeFile(join(scanDir, path), contents);
        },
        async restoreMany(artifacts) {
          for (const { path, contents } of artifacts) {
            await mkdir(dirname(join(scanDir, path)), { recursive: true });
            await writeFile(join(scanDir, path), contents);
          }
        },
        async remove(path) {
          await rm(join(scanDir, path), { force: true });
        },
      }),
      runWorkbench: async (_options, args, input): Promise<JsonObject> => {
        commands.push(args[0]!);
        if (role === "comparison" || role === "followup") {
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
        if (["register-cli-scan", "get-cli-scan-resume"].includes(args[0]!)) {
          const recipe =
            input === undefined ? undefined : JSON.parse(input).recipe;
          if (recipe) recipes.push(recipe);
          return composedDiscovery &&
            (recipe?.mode === "standard" || args[2] === childId)
            ? {
                ...registration,
                scanId: childId,
                scanDir: childDir,
                threadId: resumed ? threadId : null,
              }
            : registration;
        }
        if (args[0] === "get-scan-feedback")
          return {
            scanId: args[2]!,
            targetId: registration["targetId"]!,
            falsePositives: [],
          };
        if (args[0] === "list-scans")
          return {
            scans:
              role === "merge"
                ? [1, 2].map((index) => ({
                    scanId: `scan_example_00${index}`,
                    scanDir: join(
                      scanDir,
                      `artifacts/deep-scan/passes/pass-${index}`,
                    ),
                    parentScanId: scanId,
                    targetPath: repository,
                    progress: { status: "complete" },
                  }))
                : composedDiscovery && resumed
                  ? [
                      {
                        scanId: childId,
                        scanDir: childDir,
                        parentScanId: scanId,
                        targetPath: repository,
                        continuationThreadId: threadId,
                        progress: { status: "running" },
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
            createCodex: ({ config }) => {
              customProjects = config?.["projects"];
              return {
                startThread: () => ({
                  id: null,
                  async runStreamed() {
                    customCalls++;
                    throw new Error("synthetic custom factory");
                  },
                }),
              };
            },
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
  const options: ScanOptions = {
    mode: role === "merge" || composedDiscovery ? "deep" : "standard",
    outputDir: scanDir,
    ...(role === "comparison" || role === "followup"
      ? { inheritedPermissions }
      : {}),
    ...(role === "followup" ? { postScanPrompt: "Write follow-up notes" } : {}),
    ...(role === "discovery" || role === "custom"
      ? { deepScanPass: true }
      : {}),
    ...(role === "followup" && resumed
      ? {
          registeredScan: {
            scanId,
            scanDir,
            threadId,
            handoffClaimToken: "synthetic-claim",
          },
        }
      : resumed || role === "merge"
        ? { resumeScanId: scanId }
        : {}),
    ...(role === "merge" || composedDiscovery
      ? { workers: 1, subagents: 0, maxDiscoveryRuns: 1, maxTimeHours: 1 }
      : {}),
    signal: controller.signal,
  };
  return {
    runtimeEnvironment,
    async runProtocol() {
      const sdk = createPermissionCheckedCodex({
        codexPathOverride: executablePathForSpawn(executable),
        env: environment,
        config: {
          default_permissions: "codex_security_scan",
          permissions: { codex_security_scan: inheritedPermissions },
        },
      });
      const threadOptions = { workingDirectory: cwd, skipGitRepoCheck: true };
      const thread = resumed
        ? sdk.resumeThread(threadId, threadOptions)
        : sdk.startThread(threadOptions);
      const { events } = await thread.runStreamed(
        "Synthetic permission check.",
        { signal: controller.signal },
      );
      for await (const _event of events) {
        /* Consume the real child protocol. */
      }
    },
    run: (onScanStarted?: () => void, overrides: Partial<ScanOptions> = {}) =>
      client.run(repository, {
        ...options,
        ...overrides,
        onScanStarted,
        onWarning: (message) => warnings.push(message),
      }),
    abort: (reason: Error) => controller.abort(reason),
    signal: controller.signal,
    childSignals,
    commands,
    recipes,
    projects,
    codexHome,
    async useAmbientHome() {
      preserveCodexHomeConfig = true;
      await writeFile(join(codexHome, "config.toml"), stringify({ projects }));
    },
    scanDir,
    cwd,
    repository,
    inheritedPermissions,
    warnings,
    completedArtifacts,
    customCalls: () => customCalls,
    customProjects: () => customProjects,
    observations: async (requests = false) =>
      (await readFile(capture, "utf8"))
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line))
        .filter(({ kind }) =>
          requests ? kind === "request" : kind !== "request",
        ),
    async close() {
      try {
        await client.close();
        // The Codex SDK removes child listeners during cleanup; exit state is retained.
        for (const child of children) {
          while (child.exitCode === null && child.signalCode === null)
            await new Promise<void>((resolve) => setImmediate(resolve));
        }
      } finally {
        spawn.mockRestore();
      }
    },
  };
}

test.each([
  ["discovery", "fresh"],
  ["discovery", "resumed"],
  ["merge", "fresh"],
  ["merge", "resumed"],
] as const)(
  "%s %s worker restores the selected plugin after shared setup changes",
  async (role, phase) => {
    const h = await fixture(
      role,
      phase === "resumed",
      "fallback",
      "sdk",
      false,
      undefined,
      role === "discovery",
      true,
    );
    try {
      await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
      const selections = (await h.observations()).filter(
        ({ kind }) => kind === "plugin-selection",
      );
      expect(selections.length).toBeGreaterThan(0);
      expect(selections.every(({ marker }) => marker === "selected-a")).toBe(
        true,
      );
    } finally {
      await h.close();
    }
  },
);

test.each(["sdk", "cli"] as const)(
  "%s factory preserves inherited permissions for fresh and resumed discovery and merge workers",
  async (surface) => {
    for (const role of ["discovery", "merge"] as const)
      for (const resumed of [false, true])
        for (const scenario of ["rejected", "fallback"] as const) {
          const h = await fixture(role, resumed, scenario, surface);
          h.runtimeEnvironment["OPENAI_API_KEY"] =
            "synthetic-stale-runtime-key";
          h.runtimeEnvironment["SYNTHETIC_EXECUTION_CONTEXT"] =
            "cached-runtime";
          try {
            await expect(
              h.run(undefined, {
                inheritedPermissions: h.inheritedPermissions,
              }),
            ).rejects.toBeInstanceOf(ScanPermissionError);
            const requests = await h.observations(true);
            expect(requests.map(({ method }) => method)).toEqual([
              "initialize",
              "initialized",
              "config/read",
              "permissionProfile/list",
              "permissionProfile/list",
            ]);
            expect(requests.at(-1).params).toMatchObject({
              cursor: "selected-page",
              cwd: h.cwd,
            });
            const observations = await h.observations();
            expect(
              observations.filter(({ kind }) => kind === "preflight"),
            ).toMatchObject([
              {
                cwd: h.cwd,
                surface,
                modelProvider: "openai",
                forcedLogin: null,
                forcedWorkspace: null,
              },
            ]);
            const executions = observations.filter(
              ({ kind }) => kind === "exec",
            );
            expect(executions).toHaveLength(scenario === "rejected" ? 0 : 1);
            if (executions.length) {
              expect(executions[0].args.includes("resume")).toBe(resumed);
              expect(executions[0]).toMatchObject({
                modelProvider: "openai",
                forcedLogin: null,
                forcedWorkspace: null,
              });
            }
            for (const launch of observations.filter(
              ({ kind }) => kind === "preflight" || kind === "exec",
            )) {
              expect(
                launch.permissions.codex_security_scan.filesystem,
              ).toMatchObject({
                ":root": "read",
                ...h.inheritedPermissions.filesystem,
              });
              expect(
                launch.permissions.codex_security_scan.filesystem,
              ).not.toHaveProperty(":workspace_roots");
              expect(launch.context).toBe("selected-scan");
              expect(launch.apiKey).toBe("synthetic-fixture-key");
              expect(launch.projects).toEqual(h.projects);
              expect(
                launch.args.some((arg: string) => arg.startsWith("projects=")),
              ).toBe(false);
              expect(launch.mcpServers).toEqual({
                "codex-security": { command: "node", enabled: false },
                synthetic: {
                  command: "synthetic-mcp",
                  env: { SETTING: "inherited" },
                },
                "synthetic.literal": {
                  command: "synthetic-mcp",
                  env: { "SETTING.KEY": "literal-value" },
                },
              });
            }
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

test.each(["rejected", "substituted-default", "substituted-profile"] as const)(
  "checks the paginated profile and rejects %s before executing the child",
  async (scenario) => {
    const h = await fixture("discovery", false, scenario, "sdk");
    try {
      await expect(h.runProtocol()).rejects.toBeInstanceOf(ScanPermissionError);
      const requests = await h.observations(true);
      expect(requests.map(({ method }) => method)).toEqual([
        "initialize",
        "initialized",
        "config/read",
        "permissionProfile/list",
        "permissionProfile/list",
      ]);
      expect(requests.at(-1).params).toMatchObject({
        cursor: "selected-page",
        cwd: h.cwd,
      });
      expect(
        (await h.observations()).filter(({ kind }) => kind === "exec"),
      ).toEqual([]);
      expect(h.commands).not.toContain("complete-scan");
    } finally {
      await h.close();
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
      if (role === "standard") {
        const execution = observations.find(({ kind }) => kind === "exec");
        expect(execution.projects).toEqual(h.projects);
        expect(
          execution.args.some((arg: string) => arg.startsWith("projects=")),
        ).toBe(false);
        expect(
          observations.find(({ kind }) => kind === "exec").mcpServers,
        ).toEqual({
          "codex-security": { command: "synthetic-workbench", enabled: true },
          synthetic: {
            command: "synthetic-mcp",
            env: { SETTING: "inherited" },
          },
          "synthetic.literal": {
            command: "synthetic-mcp",
            env: { "SETTING.KEY": "literal-value" },
          },
        });
      }
      expect(h.customCalls()).toBe(role === "custom" ? 1 : 0);
      if (role === "custom") expect(h.customProjects()).toEqual(h.projects);
    } finally {
      await h.close();
    }
  },
);

test.each(["managed", "ambient"] as const)(
  "ordinary scan comparison keeps large project settings in the %s home",
  async (home) => {
    const h = await fixture("comparison", false, "fallback", "sdk");
    try {
      if (home === "ambient") await h.useAmbientHome();
      const before = await readFile(join(h.codexHome, "config.toml"));
      await h.run(undefined, { inheritedPermissions: undefined });
      const observations = await h.observations();
      expect(observations.filter(({ kind }) => kind === "mcp")).toHaveLength(1);
      expect(observations.filter(({ kind }) => kind === "exec")).toHaveLength(
        2,
      );
      for (const launch of observations) {
        expect(launch.projects).toEqual(h.projects);
        expect(
          launch.args.some((arg: string) => arg.startsWith("projects=")),
        ).toBe(false);
      }
      if (home === "ambient")
        expect(await readFile(join(h.codexHome, "config.toml"))).toEqual(
          before,
        );
      expect(h.commands).toContain("complete-scan");
    } finally {
      await h.close();
    }
  },
);

test("ambient project history stays file-backed for fresh and resumed native workers", async () => {
  for (const role of ["discovery", "merge"] as const)
    for (const resumed of [false, true]) {
      const h = await fixture(role, resumed, "fallback", "sdk");
      try {
        await h.useAmbientHome();
        const before = await readFile(join(h.codexHome, "config.toml"));
        await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
        const observations = await h.observations();
        expect(observations.map(({ kind }) => kind)).toEqual([
          "preflight",
          "exec",
        ]);
        expect(observations[1].args.includes("resume")).toBe(resumed);
        for (const launch of observations) {
          expect(launch.projects).toEqual(h.projects);
          expect(
            launch.args.some((arg: string) => arg.startsWith("projects=")),
          ).toBe(false);
          expect(launch.mcpServers["codex-security"].enabled).toBe(false);
        }
        expect(await readFile(join(h.codexHome, "config.toml"))).toEqual(
          before,
        );
      } finally {
        await h.close();
      }
    }
});

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
      for (const stage of ["mcp", "preflight"])
        expect(comparison.filter(({ kind }) => kind === stage)).toMatchObject([
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

test.each([
  ["discovery", false],
  ["discovery", true],
  ["merge", false],
  ["merge", true],
] as const)(
  "keeps %s execution isolated from later environment changes (resumed: %p)",
  async (role, resumed) => {
    const h = await fixture(role, resumed, "fallback", "sdk", true);
    try {
      await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
      const observations = await h.observations();
      expect(observations.filter(({ kind }) => kind === "exec")).toHaveLength(
        1,
      );
      for (const child of observations) {
        expect(child.context).toBe("selected-scan");
        expect(child.apiKey).toBe("synthetic-fixture-key");
      }
      expect(
        observations
          .find(({ kind }) => kind === "exec")
          .args.includes("resume"),
      ).toBe(resumed);
    } finally {
      await h.close();
    }
  },
);

test.each([
  ["rejected", false],
  ["fallback", false],
  ["rejected", true],
  ["fallback", true],
] as const)(
  "sealed followup permissions reach preflight and execution (%s, resumed: %p)",
  async (scenario, resumed) => {
    const h = await fixture("followup", resumed, scenario, "sdk");
    try {
      await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
      const observations = await h.observations();
      expect(
        observations.find(({ kind }) => kind === "permission-validation"),
      ).toMatchObject({ exitCode: 0 });
      const followup = observations.filter(
        ({ permissions }) =>
          permissions?.codex_security_scan?.filesystem?.[h.scanDir]?.["."] ===
          "read",
      );
      const output = followup.find(({ kind }) => kind === "preflight").cwd;
      expect(dirname(output)).toBe(join(h.scanDir, "artifacts/follow-up"));
      for (const launch of followup) {
        expect(
          launch.kind === "preflight"
            ? launch.cwd
            : launch.args[launch.args.indexOf("--cd") + 1],
        ).toBe(output);
        expect(launch).toMatchObject({
          permissions: {
            codex_security_scan: {
              filesystem: {
                ...h.inheritedPermissions.filesystem,
                [h.scanDir]: { ".": "read", private: "deny" },
                [output]: { ".": "write" },
              },
              network: { enabled: false },
            },
          },
        });
      }
      expect(followup.filter(({ kind }) => kind === "exec")).toHaveLength(
        scenario === "rejected" ? 0 : 1,
      );
      if (scenario === "fallback" && process.platform === "linux") {
        const writeCheck = observations.find(
          ({ kind }) => kind === "followup-write-check",
        );
        if (writeCheck.exitCode === 0) {
          expect(await readFile(join(output, "follow-up.txt"), "utf8")).toBe(
            "synthetic follow-up",
          );
        } else {
          // Some Linux runners cannot create the sandbox's user/network namespace.
          expect(writeCheck.stderr).toMatch(
            /bwrap: (?:setting up uid map: Permission denied|loopback: Failed RTM_NEWADDR: Operation not permitted)/u,
          );
        }
      }
      expect(
        h.commands.filter((command) => command === "complete-scan"),
      ).toHaveLength(1);
      expect(h.commands).not.toContain("fail-scan");
      expect(h.completedArtifacts.size).toBe(4);
      for (const [file, bytes] of h.completedArtifacts)
        expect(await readFile(join(h.scanDir, file))).toEqual(bytes);
    } finally {
      await h.close();
    }
  },
);

test.each([
  ["standard", false],
  ["discovery", false],
  ["discovery", true],
  ["merge", false],
  ["merge", true],
] as const)(
  "unresolved profiles reach native validation for %s execution (resumed: %p)",
  async (role, resumed) => {
    const h = await fixture(role, resumed, "fallback", "sdk", false, "missing");
    try {
      await expect(h.run()).rejects.toThrow();
      const observations = await h.observations();
      expect(observations[0]?.kind).toBe(
        role === "standard" ? "exec" : "preflight",
      );
      expect(observations[0]?.selectedProfile).toBe("missing");
      const validation = observations.find(
        ({ kind }) => kind === "profile-validation",
      );
      expect(validation).toMatchObject({ exitCode: 1 });
      expect(validation.stderr).toContain("missing");
      expect(h.commands).not.toContain("complete-scan");
    } finally {
      await h.close();
    }
  },
);

test("selected profile launch survives shared-home settings for fresh and resumed workers", async () => {
  for (const role of ["discovery", "merge"] as const)
    for (const resumed of [false, true]) {
      const h = await fixture(
        role,
        resumed,
        "fallback",
        "sdk",
        false,
        "selected",
      );
      try {
        await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
        const observations = (await h.observations()).filter(
          ({ kind }) => kind === "preflight" || kind === "exec",
        );
        expect(observations).toHaveLength(2);
        for (const launch of observations)
          expect(launch).toMatchObject({
            literalSetting: "literal-top-level-value",
            modelProvider: "synthetic.selected",
            modelProviders: {
              "synthetic.selected": {
                base_url: "https://example.invalid/v1",
                env_key: "OPENAI_API_KEY",
              },
            },
            mcpServers: {
              "synthetic.literal": {
                command: "synthetic-mcp",
                env: { "SETTING.KEY": "literal-value" },
              },
            },
            model: "gpt-6-astra",
            effort: "high",
            forcedLogin: null,
            forcedWorkspace: null,
          });
      } finally {
        await h.close();
      }
    }
});

test.each([
  ["discovery", false],
  ["discovery", true],
  ["merge", false],
  ["merge", true],
] as const)(
  "worker %s limits agree in recipes, preflight files and subprocesses (resumed: %p)",
  async (role, resumed) => {
    const h = await fixture(
      role,
      resumed,
      "fallback",
      "sdk",
      false,
      undefined,
      role === "discovery",
    );
    try {
      await expect(h.run()).rejects.toBeInstanceOf(ScanPermissionError);
      const launches = (await h.observations()).filter(
        ({ kind }) => kind === "preflight" || kind === "exec",
      );
      expect(launches).toHaveLength(2);
      for (const launch of launches)
        expect(launch).toMatchObject({ workerLimit: 1, snapshotLimit: 1 });
      for (const recipe of h.recipes)
        expect(recipe).toMatchObject({
          config: {
            features: {
              multi_agent_v2: { max_concurrent_threads_per_session: 1 },
            },
          },
        });
      if (role === "discovery" && !resumed) expect(h.recipes).toHaveLength(2);
    } finally {
      await h.close();
    }
  },
);
