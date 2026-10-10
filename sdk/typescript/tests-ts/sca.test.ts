import { execFileSync } from "node:child_process";
import * as childProcess from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import {
  Codex,
  type CodexOptions,
  type ThreadEvent,
  type ThreadOptions,
} from "@openai/codex-sdk";
import Ajv from "ajv";
import { afterEach, expect, spyOn, test } from "bun:test";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { JsonObject } from "../src/config.js";
import { codexSecurityPrivatePaths } from "../src/auth.js";
import { createProfileCodex } from "../src/provider-profile.js";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";
import {
  ScanInterruptedError,
  ScanCostLimitExceededError,
  OutputInsideProtectedRootError,
} from "../src/index.js";
import type { OsvScanResult } from "../src/sca-osv.js";
import type { ScaResult, TriageFinding } from "../src/sca-types.js";
import {
  codexSecurityCredentialHome,
  executablePathForSpawn,
  resolveCodexCommand,
  resolvePluginPython,
  runCodexCommand,
  type runWorkbench,
} from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { create: temporaryDirectory, cleanup } = createTemporaryDirectories();
afterEach(cleanup);

function scanner(outputDir: string, matched = true): OsvScanResult {
  return {
    status: "completed",
    diagnostics: [],
    scanner: {
      name: "osv-scanner",
      version: "2.6.0",
      argv: [],
      invocations: [
        {
          argv: ["scan", "source", "--", "package-lock.json"],
          exitCode: matched ? 1 : 0,
          rawOutputPath: join(outputDir, "osv-output.json"),
          stderrPath: join(outputDir, "osv-stderr.log"),
        },
      ],
      startedAt: "2026-01-01T00:00:00Z",
      completedAt: "2026-01-01T00:00:01Z",
      exitCode: matched ? 1 : 0,
      rawOutputPath: join(outputDir, "osv-output.json"),
      stderrPath: join(outputDir, "osv-stderr.log"),
      advisoryMode: "online",
      advisorySnapshotId: null,
    },
    coverage: {
      status: "complete",
      inputs: [
        {
          path: "package-lock.json",
          sha256: "abc",
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
    matches: matched
      ? [
          {
            id: "match-1",
            componentId: "component-1",
            advisoryIds: ["SYNTHETIC-1"],
            aliases: [],
            sourceAdvisories: [
              { id: "SYNTHETIC-1", summary: "Synthetic advisory" },
            ],
            severity: null,
            fixedVersions: ["1.0.1"],
            advisoryModifiedAt: [],
          },
        ]
      : [],
  };
}
function triage(): TriageFinding {
  return {
    triage_item_id: "triage-1",
    input_id: "match-1",
    source_type: "advisory",
    title: "Synthetic package use",
    normalized_input: {
      vulnerable_component: "synthetic-package",
      claimed_source: "unknown",
      claimed_sink: "unknown",
      claimed_control: "unknown",
      affected_version_or_path: "1.0.0",
      preconditions: [],
      impact: "unknown",
      references: [],
    },
    verdict: "needs_review",
    confidence: "low",
    affected_locations: [],
    reachable_path: [],
    boundary_assessment: {
      product_surface: "unknown",
      source_trust: "unknown",
      boundary_crossed: null,
      policy_basis: "No policy",
    },
    exploitability_stack_rank: {
      rank_queue: "needs_review",
      rank: 1,
      rationale: "Missing context",
      drivers: [],
    },
    evidence: [],
    counterevidence: [],
    proof_gaps: ["No usage context"],
    recommended_next_step: "Review package use",
    fix_finding_handoff: null,
  };
}
async function fixture(
  options: {
    matched?: boolean;
    turns?: (
      | "completed"
      | "truncated"
      | "malformed"
      | "cancelled"
      | "source_changed"
      | "duplicate_id"
      | "unauthorized"
      | "forbidden"
    )[];
    dependencyInput?: {
      path: string;
      format: ScaResult["coverage"]["inputs"][number]["format"];
      ecosystem: string;
    };
    scannerStatus?: OsvScanResult["status"];
    missing?: boolean;
    error?: string;
    malformed?: boolean;
    runtimeError?: boolean;
    controller?: AbortController;
    abortAt?: "scanner" | "model";
    model?: string;
    dirtyRepository?: boolean;
    changeSourceAt?: "scanner" | "model";
    changeRevision?: boolean;
    changeRefs?: boolean;
    snapshotErrorAt?: 1 | 2;
    workbenchSnapshot?: boolean;
    mcpConfig?: string;
    mcpOverrides?: JsonObject;
    codexOverrides?: JsonObject;
    codexFactory?: (
      options: CodexOptions & {
        nativeProfile?: string;
        requestedPermissionProfile?: string;
      },
    ) => Codex | Promise<Codex>;
    linkedCodex?: boolean;
    codexLauncher?: string;
    wrappedCodex?: boolean;
    ambientOutput?: boolean;
    advisoryDetails?: string;
    homeVariable?: "HOME" | "USERPROFILE";
    configuredGitHubHome?: boolean;
    gitHubConfig?: "xdg" | "appdata" | "explicit";
  } = {},
) {
  const root = await temporaryDirectory("codex-security-sca-");
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const ambientHome = join(root, "ambient-codex-home");
  const outputDir = options.ambientOutput
    ? join(
        ambientHome,
        "state",
        "plugins",
        "codex-security",
        "dependencies",
        "repository",
        "scan",
      )
    : join(root, "sca");
  await Promise.all([
    mkdir(repository, { mode: 0o700 }),
    mkdir(codexHome, { mode: 0o700 }),
  ]);
  if (options.mcpConfig !== undefined)
    await writeFile(join(codexHome, "config.toml"), options.mcpConfig);
  let codexPath = options.codexLauncher;
  if (options.wrappedCodex) {
    codexPath = join(root, "launcher", "launch-security");
    await mkdir(dirname(codexPath));
    await writeFile(
      codexPath,
      `#!/usr/bin/env node
import { spawnSync } from "node:child_process";
const child = spawnSync(${JSON.stringify(resolveCodexCommand({}).command)}, process.argv.slice(2), { stdio: "inherit" });
process.exit(child.status ?? 1);
`,
    );
    await chmod(codexPath, 0o700);
  }
  if (options.linkedCodex) {
    const nativePath = resolveCodexCommand({}).command;
    const launcherDirectory = join(root, "linked-runtime");
    await symlink(
      dirname(nativePath),
      launcherDirectory,
      process.platform === "win32" ? "junction" : "dir",
    );
    codexPath = join(launcherDirectory, basename(nativePath));
  }
  if (options.dirtyRepository)
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
  const sourcePath = join(repository, "usage.txt");
  await writeFile(sourcePath, "synthetic initial source context");
  let snapshotCalls = 0;
  let revision = "synthetic-revision";
  const changeSource = async () => {
    if (options.changeRevision) revision = "synthetic-next-revision";
    else await writeFile(sourcePath, "synthetic changed source context");
  };
  const calls = { runtime: 0, model: 0, scanner: 0 };
  const captured: {
    codex?: CodexOptions;
    thread?: ThreadOptions;
    prompt?: string;
    evidence?: ScaResult;
  } = {};
  const turns: {
    options: ThreadOptions | undefined;
    prompt: string;
    evidence: ScaResult;
  }[] = [];
  const sourceCalls: Parameters<typeof runWorkbench>[0][] = [];
  const pythonResolutions: Parameters<typeof resolvePluginPython>[0][] = [];
  const selectedUserHome = join(root, "selected-user-home");
  const environment = {
    ...(options.homeVariable
      ? { [options.homeVariable]: selectedUserHome }
      : {}),
    ...(options.configuredGitHubHome
      ? { GH_CONFIG_DIR: join(root, "selected-gh-home") }
      : {}),
    ...(options.gitHubConfig
      ? {
          XDG_CONFIG_HOME:
            options.gitHubConfig === "appdata"
              ? undefined
              : join(root, "xdg-config"),
          AppData: join(root, "application-data"),
          ...(options.gitHubConfig === "explicit"
            ? { GH_CONFIG_DIR: join(root, "explicit-gh-config") }
            : {}),
        }
      : {}),
    PATH: process.env["PATH"] ?? "",
    ...Object.fromEntries(
      ["SystemRoot", "TEMP", "TMP"].flatMap((name) =>
        process.env[name] === undefined ? [] : [[name, process.env[name]!]],
      ),
    ),
    ...(options.ambientOutput
      ? { CODEX_HOME: ambientHome }
      : { CODEX_SECURITY_STATE_DIR: join(root, "state") }),
    OPENAI_API_KEY: "synthetic-sca-key",
    ...(codexPath === undefined ? {} : { CODEX_CLI_PATH: codexPath }),
  };
  const sourceSnapshot = async (path: string) => {
    expect(path).toBe(repository);
    if (++snapshotCalls === options.snapshotErrorAt)
      throw new Error("synthetic source snapshot unavailable");
    return {
      repository,
      revision,
      refsDigest: options.changeRefs
        ? `synthetic-refs-${snapshotCalls}`
        : "synthetic-refs",
      content: await readFile(sourcePath, "utf8"),
    };
  };
  const client = new TestClient(
    {
      codexOverrides: {
        model: options.model ?? "gpt-5.6-sol",
        model_reasoning_effort: "high",
        ...options.codexOverrides,
        ...(options.mcpOverrides === undefined
          ? {}
          : { mcp_servers: options.mcpOverrides }),
      },
    },
    {
      environment,
      repositoryRevision: async () => revision,
      ...(options.workbenchSnapshot
        ? {
            runWorkbench: async (
              workbenchOptions: Parameters<typeof runWorkbench>[0],
              args: readonly string[],
              input?: string,
            ) => {
              expect(args).toEqual(["finding-workflow"]);
              const request = JSON.parse(input!);
              expect(request.action).toBe("source");
              sourceCalls.push(workbenchOptions);
              return { source: await sourceSnapshot(request.repository) };
            },
          }
        : { sourceSnapshot }),
      runOsvScan: async (input) => {
        calls.scanner++;
        expect(input.environment).toEqual(environment);
        if (options.changeSourceAt === "scanner") await changeSource();
        if (options.abortAt === "scanner")
          options.controller!.abort("cancel after scanner");
        const result = scanner(input.outputDir, options.matched ?? true);
        if (options.turns !== undefined)
          result.matches = options.turns.map((_, index) => ({
            ...result.matches[0]!,
            id: `match-${index + 1}`,
          }));
        if (options.advisoryDetails !== undefined)
          result.matches[0]!.sourceAdvisories[0]!["details"] =
            options.advisoryDetails;
        if (options.dependencyInput) {
          const dependency = options.dependencyInput;
          Object.assign(result.coverage.inputs[0]!, {
            path: dependency.path,
            format: dependency.format,
          });
          Object.assign(result.components[0]!, {
            sourcePath: dependency.path,
            ecosystem: dependency.ecosystem,
          });
          result.scanner.invocations![0]!.argv = [
            "scan",
            "source",
            "--",
            dependency.path,
          ];
        }
        if (options.scannerStatus !== undefined) {
          result.status = options.scannerStatus;
          result.coverage.status =
            options.scannerStatus === "completed"
              ? "complete"
              : options.scannerStatus;
        }
        return result;
      },
      prepareRuntime: async () => {
        calls.runtime++;
        const saved = JSON.parse(
          await readFile(join(outputDir, "sca-result.json"), "utf8"),
        );
        expect(saved.matches).toHaveLength(options.turns?.length ?? 1);
        expect(saved.status).toBe("partial");
        expect(saved.assessments[0].status).toBe("not_started");
        if (options.runtimeError)
          throw new Error("synthetic authentication unavailable");
        return { ...preparedRuntime(codexHome), environment };
      },
      resolvePluginPython: async (input) => {
        if (!options.workbenchSnapshot) return "/managed/python";
        pythonResolutions.push(input);
        return await resolvePluginPython(input);
      },
      createCodex: (codex) => {
        captured.codex = codex;
        calls.model++;
        if (options.codexFactory !== undefined)
          return options.codexFactory(codex);
        return {
          startThread: (thread) => {
            captured.thread = thread;
            return {
              id: null,
              async runStreamed(prompt) {
                captured.prompt = String(prompt);
                captured.evidence = JSON.parse(
                  await readFile(join(outputDir, "sca-result.json"), "utf8"),
                );
                turns.push({
                  options: thread,
                  prompt: String(prompt),
                  evidence: captured.evidence!,
                });
                const turnNumber = turns.length;
                const behavior = options.turns?.[turnNumber - 1];
                const finding = {
                  ...triage(),
                  input_id: `match-${turnNumber}`,
                  triage_item_id: `triage-${behavior === "duplicate_id" ? 1 : turnNumber}`,
                };
                return {
                  events: (async function* (): AsyncGenerator<ThreadEvent> {
                    yield {
                      type: "thread.started",
                      thread_id:
                        turnNumber === 1
                          ? "sca-thread"
                          : `sca-thread-${turnNumber}`,
                    };
                    if (behavior === "cancelled") {
                      options.controller!.abort("cancel during later triage");
                      throw new Error("interrupted");
                    }
                    if (behavior === "source_changed") await changeSource();
                    if (
                      behavior === "unauthorized" ||
                      behavior === "forbidden"
                    ) {
                      yield {
                        type: "error",
                        message: `synthetic ${behavior === "unauthorized" ? "401 Unauthorized" : "403 Forbidden"}`,
                      };
                      return;
                    }
                    if (behavior === "truncated") {
                      yield {
                        type: "turn.failed",
                        error: { message: "synthetic output truncated" },
                      };
                      return;
                    }
                    if (options.abortAt === "model") {
                      options.controller!.abort("cancel during triage");
                      throw new Error("interrupted");
                    }
                    if (options.error) throw new Error(options.error);
                    if (options.changeSourceAt === "model")
                      await changeSource();
                    yield {
                      type: "item.completed",
                      item: {
                        id: "message",
                        type: "agent_message",
                        text:
                          options.malformed || behavior === "malformed"
                            ? "invalid JSON"
                            : JSON.stringify({
                                schema_version: "triage-finding/v0",
                                repository: {
                                  path: repository,
                                  revision: "synthetic-revision",
                                },
                                findings: options.missing ? [] : [finding],
                              }),
                      },
                    };
                    yield {
                      type: "turn.completed",
                      usage: {
                        input_tokens: 1000,
                        cached_input_tokens: 0,
                        cache_write_input_tokens: 0,
                        output_tokens: 1000,
                        reasoning_output_tokens: 0,
                      },
                    };
                  })(),
                };
              },
            };
          },
        };
      },
    },
  );
  return {
    client,
    repository,
    outputDir,
    calls,
    captured,
    turns,
    sourceCalls,
    pythonResolutions,
    environment,
    codexHome,
    ambientHome,
    selectedUserHome,
  };
}

test.each(["api key", "command"] as const)(
  "dependency triage snapshots %s provider configuration for each SDK child",
  async (authentication) => {
    const node = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    const provider = {
      name: "Synthetic provider",
      base_url: "https://provider.example.invalid/v1",
      wire_api: "responses",
      ...(authentication === "command"
        ? { auth: { command: "synthetic-auth", cwd: dirname(node) } }
        : { requires_openai_auth: true }),
    };
    const providerConfig = {
      model_provider: "synthetic.provider",
      model_providers: { "synthetic.provider": provider },
    };
    const initialConfig = stringifyToml({
      model_provider: providerConfig.model_provider,
    });
    const replacementConfig = stringifyToml({
      model_provider: "another-provider",
      model_providers: {
        "another-provider": {
          name: "Another provider",
          base_url: "https://another.example.invalid/v1",
          wire_api: "responses",
        },
      },
    });
    let preload: string;
    const f = await fixture({
      turns: ["completed", "completed"],
      gitHubConfig: "explicit",
      mcpConfig: initialConfig,
      codexOverrides: providerConfig,
      codexFactory: ({
        nativeProfile,
        requestedPermissionProfile,
        ...options
      }) =>
        createProfileCodex(
          {
            ...options,
            codexPathOverride: node,
            env: {
              ...options.env,
              NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
            },
          },
          nativeProfile!,
          requestedPermissionProfile,
        ),
    });
    await using security = f.client;
    const receipt = join(f.codexHome, "provider-children.jsonl");
    preload = join(f.codexHome, "provider-child.mjs");
    await writeFile(
      preload,
      `import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const receipt = ${JSON.stringify(receipt)};
const turn = existsSync(receipt) ? readFileSync(receipt, "utf8").trim().split("\\n").length + 1 : 1;
const configPath = ${JSON.stringify(join(f.codexHome, "config.toml"))};
const profileIndex = process.argv.indexOf('--profile');
const profileConfig = profileIndex === -1 ? null : readFileSync(join(process.env.CODEX_HOME, process.argv[profileIndex + 1] + '.config.toml'), 'utf8');
appendFileSync(receipt, JSON.stringify({ argv: process.argv.slice(2), home: process.env.CODEX_HOME, sharedConfig: readFileSync(configPath, "utf8"), profileConfig }) + "\\n");
// A concurrent client replaces the shared provider table before the next match.
if (turn === 1) writeFileSync(configPath, ${JSON.stringify(replacementConfig)});
const finding = { ...${JSON.stringify(triage())}, input_id: "match-" + turn, triage_item_id: "triage-" + turn };
const response = { schema_version: "triage-finding/v0", repository: { path: ${JSON.stringify(f.repository)}, revision: "synthetic-revision" }, findings: [finding] };
for (const event of [
  { type: "thread.started", thread_id: "provider-thread-" + turn },
  { type: "item.completed", item: { id: "message", type: "agent_message", text: JSON.stringify(response) } },
  { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }
]) console.log(JSON.stringify(event));
process.exit(0);
`,
    );
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    expect(result.status, JSON.stringify(result.diagnostics)).toBe("completed");
    expect(result.assessments).toHaveLength(2);
    const children = (await readFile(receipt, "utf8"))
      .trim()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as {
            argv: string[];
            home: string;
            sharedConfig: string;
            profileConfig: string;
          },
      );
    expect(children).toHaveLength(2);
    expect(children.map((child) => child.sharedConfig)).toEqual([
      initialConfig,
      replacementConfig,
    ]);
    for (const child of children) {
      expect(child.home).toBe(f.codexHome);
      const permissions = child.argv.find((argument) =>
        argument.startsWith("permissions.codex_security_dependencies="),
      );
      const profile = parseToml(permissions!)["permissions"] as Record<
        string,
        JsonObject
      >;
      const filesystem = profile["codex_security_dependencies"]![
        "filesystem"
      ] as JsonObject;
      expect(filesystem[f.environment.GH_CONFIG_DIR!]).toEqual({ ".": "deny" });
      expect(filesystem[join(f.environment.XDG_CONFIG_HOME!, "gh")]).toEqual({
        ".": "deny",
      });

      expect(child.argv).toContain('model_provider="synthetic.provider"');
      expect(parseToml(child.profileConfig)).toEqual({
        model_providers: providerConfig.model_providers,
      });
      expect(child.argv.some((arg) => /^model_providers[.=]/u.test(arg))).toBe(
        false,
      );
    }
    expect(await readFile(join(f.codexHome, "config.toml"), "utf8")).toBe(
      replacementConfig,
    );
  },
);

test.each(
  (["openai", "custom"] as const).flatMap((provider) =>
    (
      [
        "allowed",
        "disallowed",
        "fallback",
        "changed",
        "runtime-fallback",
        "later-runtime-fallback",
      ] as const
    ).map((policy) => ({ provider, policy })),
  ),
)(
  "dependency triage verifies $provider permissions before exec under $policy policy",
  async ({ provider, policy }) => {
    const root = await temporaryDirectory("sca-permission-child-");
    const node = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    const executable = join(root, "synthetic-codex.mjs");
    const receipt = join(root, "calls.jsonl");
    const id = "codex_security_dependencies";
    const fallback = `Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`${id}\` to required value \`:read-only\`.`;
    const f = await fixture({
      codexLauncher: node,
      turns:
        policy === "runtime-fallback"
          ? ["completed", "completed"]
          : policy === "later-runtime-fallback"
            ? ["completed", "completed", "completed"]
            : undefined,
      ...(provider === "custom"
        ? {
            codexOverrides: {
              model_provider: "synthetic.provider",
              model_providers: {
                "synthetic.provider": {
                  name: "Synthetic provider",
                  wire_api: "responses",
                  base_url: "https://provider.example.invalid/v1",
                  auth: {
                    command: "synthetic-auth",
                    env: { SYNTHETIC_SECRET: "synthetic-private-marker" },
                  },
                },
              },
            },
          }
        : {}),
      codexFactory: ({
        nativeProfile,
        requestedPermissionProfile,
        ...options
      }) =>
        createProfileCodex(options, nativeProfile!, requestedPermissionProfile),
    });
    await using security = f.client;
    await writeFile(
      executable,
      `
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { parse } from ${JSON.stringify(pathToFileURL(createRequire(import.meta.url).resolve("smol-toml")).href)};
const args = process.argv.slice(2);
const id = ${JSON.stringify(id)};
const policy = ${JSON.stringify(policy)};
const config = {};
for (let i = 0; i < args.length; i++) {
  if (["-c", "--config"].includes(args[i])) Object.assign(config, parse(args[++i]));
}
const record = (method) => appendFileSync(${JSON.stringify(receipt)}, JSON.stringify({
  method, args, cwd: process.cwd(), home: process.env.CODEX_HOME,
  profile: config.permissions?.[id],
  lockHeld: existsSync(join(process.env.CODEX_HOME, ".codex-security-preflight", ".codex-security-scan.lock", "owner.json")),
}) + "\\n");
if (args.includes("mcp")) { record("mcp"); console.log("[]"); process.exit(0); }
if (args.includes("app-server")) {
  for await (const line of createInterface({ input: process.stdin })) {
    const request = JSON.parse(line);
    record(request.method);
    if (request.id === undefined) continue;
    const profile = config.permissions[id];
    const result = request.method === "config/read"
      ? { config: { default_permissions: policy === "fallback" ? ":read-only" : id,
          permissions: { [id]: policy === "changed" ? { ...profile, filesystem: { ":root": "read" } } : profile } } }
      : request.method === "permissionProfile/list"
      ? { data: [{ id, allowed: policy !== "disallowed" }], nextCursor: null }
      : request.method === "configRequirements/read"
      ? { requirements: { allowedPermissionProfiles: { ":read-only": true } } }
      : {};
    console.log(JSON.stringify({ id: request.id, result }));
  }
} else {
  record("exec");
  const turn = readFileSync(${JSON.stringify(receipt)}, "utf8").trim().split("\\n").map(JSON.parse).filter((call) => call.method === "exec").length;
  for (const event of [
    { type: "thread.started", thread_id: "synthetic-permission-thread" },
    ...((policy === "runtime-fallback" || (policy === "later-runtime-fallback" && turn === 2)) ? [{ type: "item.completed", item: { type: "error", message: ${JSON.stringify(fallback)} } }] : []),
    { type: "item.completed", item: { id: "message", type: "agent_message", text: JSON.stringify({
      schema_version: "triage-finding/v0", repository: { path: ${JSON.stringify(f.repository)}, revision: "synthetic-revision" }, findings: [{ ...${JSON.stringify(triage())}, input_id: "match-" + turn, triage_item_id: "triage-" + turn }],
    }) } },
    { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } },
  ]) console.log(JSON.stringify(event));
}
`,
    );
    const originalSpawn = childProcess.spawn;
    const spawnSpy = spyOn(childProcess, "spawn").mockImplementation(((
      ...input: Parameters<typeof originalSpawn>
    ) => {
      const [command, args, options] = input;
      return command === node || command === executablePathForSpawn(node)
        ? originalSpawn(command, [executable, ...(args ?? [])], options ?? {})
        : originalSpawn(...input);
    }) as typeof originalSpawn);
    try {
      const result = await security.scanDependencies({
        repositoryPath: f.repository,
        outputDir: f.outputDir,
      });
      const calls = (await readFile(receipt, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      const preflight = calls.filter((call) => call.method === "config/read");
      expect(preflight).toHaveLength(1);
      expect(preflight[0]).toMatchObject({
        cwd: f.outputDir,
        home: f.codexHome,
        lockHeld: true,
      });
      expect(preflight[0].profile.filesystem[f.codexHome]).toEqual({
        ".": "deny",
      });
      expect(preflight[0].profile.network.enabled).toBe(false);
      for (const call of calls.filter((call) => call.method !== "exec")) {
        expect(call.args.join(" ")).not.toContain("synthetic-private-marker");
        expect(call.args.join(" ")).not.toContain("provider.example.invalid");
        if (provider === "custom")
          expect(call.args.join(" ")).toContain("synthetic.provider");
      }
      const executions = calls.filter((call) => call.method === "exec");
      if (policy === "allowed") {
        expect(result.status, JSON.stringify(result.diagnostics)).toBe(
          "completed",
        );
        expect(result.assessments[0]!.status).toBe("completed");
        expect(executions).toHaveLength(1);
        expect(executions[0].lockHeld).toBe(false);
      } else {
        expect(result.status).toBe("partial");
        expect(result.matches).toHaveLength(
          policy === "runtime-fallback"
            ? 2
            : policy === "later-runtime-fallback"
              ? 3
              : 1,
        );
        if (policy === "later-runtime-fallback") {
          expect(
            result.assessments.map((assessment) => assessment.status),
          ).toEqual(["completed", "failed", "failed"]);
        } else expect(result.assessments[0]!.status).not.toBe("completed");
        expect(result.diagnostics.join("\n")).toContain(id);
        expect(executions).toHaveLength(
          policy === "runtime-fallback"
            ? 1
            : policy === "later-runtime-fallback"
              ? 2
              : 0,
        );
        if (
          policy === "runtime-fallback" ||
          policy === "later-runtime-fallback"
        )
          expect(result.diagnostics.join("\n")).toContain(fallback);
      }
    } finally {
      spawnSpy.mockRestore();
    }
  },
);

(process.platform === "win32" ? test.skip : test).each([
  "JavaScript",
  "pnpm shim",
])(
  "dependency triage keeps the installed npm %s launcher with read-only permissions",
  async (kind) => {
    const launcher =
      kind === "JavaScript"
        ? createRequire(import.meta.url).resolve("@openai/codex/bin/codex.js")
        : join(import.meta.dir, "../node_modules/.bin/codex");
    const f = await fixture({ codexLauncher: launcher });
    await using security = f.client;
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    expect(result.status).toBe("completed");
    expect(f.captured.codex!.codexPathOverride).toBe(launcher);
    expect(f.captured.codex!.config!["default_permissions"]).toBe(
      "codex_security_dependencies",
    );
    expect(f.captured.codex!.env!["CODEX_CLI_PATH"]).toBe(launcher);

    const receipt = join(f.outputDir, "launcher-child.json");
    const preload = join(f.outputDir, "launcher-probe.mjs");
    await writeFile(
      preload,
      `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({ argv: process.argv.slice(2), launcher: process.env.CODEX_CLI_PATH }));
for (const event of [
  { type: "thread.started", thread_id: "synthetic-launcher-thread" },
  { type: "item.completed", item: { id: "message", type: "agent_message", text: "synthetic launcher response" } },
  { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }
]) console.log(JSON.stringify(event));
process.exit(0);
`,
    );
    const turn = await new Codex({
      ...f.captured.codex,
      env: {
        ...f.captured.codex!.env,
        NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
      },
    })
      .startThread(f.captured.thread)
      .run("synthetic installed launcher probe");
    expect(turn.finalResponse).toBe("synthetic launcher response");
    const child = JSON.parse(await readFile(receipt, "utf8"));
    expect(child.launcher).toBe(launcher);
    expect(
      child.argv.flatMap((value: string, index: number, argv: string[]) =>
        value === "--add-dir" ? [argv[index + 1]] : [],
      ),
    ).toEqual(f.captured.thread!.additionalDirectories);
  },
);

(process.platform === "win32" ? test.skip : test).each([
  ["HOME", false],
  ["USERPROFILE", false],
  ["HOME", true],
  ["USERPROFILE", true],
] as const)(
  "dependency triage runs a delegated native tool with private %s stores, configured GitHub home: %p",
  async (homeVariable, configuredGitHubHome) => {
    const f = await fixture({
      wrappedCodex: true,
      ambientOutput: true,
      homeVariable,
      configuredGitHubHome,
    });
    const npmFiles = [
      join(f.selectedUserHome, ".npmrc"),
      join(dirname(f.repository), "registry [user] #.npmrc"),
      join(dirname(f.repository), "lowercase-registry.npmrc"),
    ];
    const configuredStores = [
      join(dirname(f.repository), "registry-config", "git", "credentials"),
      join(dirname(f.repository), "cloud-credentials"),
      join(dirname(f.repository), "cloud-config"),
    ];
    Object.assign(f.environment, {
      NPM_CONFIG_USERCONFIG: npmFiles[1],
      npm_config_userconfig: npmFiles[2],
      XDG_CONFIG_HOME: dirname(dirname(configuredStores[0]!)),
      AWS_SHARED_CREDENTIALS_FILE: configuredStores[1],
      AWS_CONFIG_FILE: configuredStores[2],
    });
    await using security = f.client;
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    expect(result.status).toBe("completed");
    const options = f.captured.codex!;
    const launcher = f.environment.CODEX_CLI_PATH!;
    const native = resolveCodexCommand({}).command;
    expect(options.codexPathOverride).toBe(launcher);
    expect(options.env!["CODEX_CLI_PATH"]).toBe(launcher);
    expect(dirname(native)).not.toBe(dirname(launcher));
    const selectedSsh = join(f.selectedUserHome, ".ssh", "id_synthetic");
    const selectedGitHub = join(
      f.environment["GH_CONFIG_DIR"] ??
        join(f.selectedUserHome, ".config", "gh"),
      "hosts.yml",
    );
    const privateFiles = [
      ...npmFiles,
      ...configuredStores,
      ...[
        ".git-credentials",
        ".config/git/credentials",
        ".pypirc",
        ".m2/settings.xml",
        ".m2/settings-security.xml",
        ".aws/credentials",
        ".aws/config",
      ].map((relative) => join(f.selectedUserHome, relative)),
      join(f.ambientHome, "sessions", "synthetic-session.jsonl"),
      join(f.ambientHome, "archived_sessions", "synthetic-session.jsonl"),
      join(f.ambientHome, "history.jsonl"),
      selectedSsh,
      selectedGitHub,
      join(f.selectedUserHome, ".config", "gh", "hosts.yml"),
      join(f.ambientHome, "auth.json"),
      join(f.ambientHome, ".credentials.json"),
      join(f.ambientHome, "config.toml"),
      join(f.codexHome, "auth.json"),
      ...codexSecurityPrivatePaths(f.environment).filter((path) =>
        path.includes("workbench.sqlite3"),
      ),
      join(
        f.ambientHome,
        "state",
        "plugins",
        "codex-security",
        "codex-home",
        "auth.json",
      ),
    ];
    for (const path of privateFiles) {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(
        path,
        path.endsWith("config.toml")
          ? "# synthetic private configuration\n"
          : "synthetic credential",
      );
    }
    const permissions = parseToml(
      options.configOverrides!.find((value) =>
        value.startsWith("permissions.codex_security_dependencies="),
      )!,
    )["permissions"] as Record<string, JsonObject>;
    expect(permissions["codex_security_dependencies"]!["network"]).toEqual({
      enabled: false,
    });
    const filesystem = permissions["codex_security_dependencies"]![
      "filesystem"
    ] as JsonObject;
    expect(filesystem[dirname(selectedSsh)]).toEqual({ ".": "deny" });
    expect(filesystem[dirname(selectedGitHub)]).toEqual({ ".": "deny" });
    expect(filesystem[join(f.selectedUserHome, ".config", "gh")]).toEqual({
      ".": "deny",
    });
    for (const path of [
      ...npmFiles,
      ...configuredStores,
      join(homedir(), ".npmrc"),
      join(homedir(), ".git-credentials"),
      join(homedir(), ".config", "git", "credentials"),
      join(homedir(), ".pypirc"),
      join(homedir(), ".m2", "settings.xml"),
      join(homedir(), ".m2", "settings-security.xml"),
      join(homedir(), ".aws"),
      join(homedir(), ".codex", "auth.json"),
      join(homedir(), ".codex", ".credentials.json"),
      join(homedir(), ".codex", "config.toml"),
      join(homedir(), ".codex", "sessions"),
      join(homedir(), ".codex", "archived_sessions"),
      join(homedir(), ".codex", "history.jsonl"),
      codexSecurityCredentialHome({}),
    ]) {
      expect(filesystem[path]).toEqual({ ".": "deny" });
    }
    expect(filesystem[f.ambientHome]).toBeUndefined();
    expect(options.env!["NPM_CONFIG_USERCONFIG"]).toBe(npmFiles[1]);
    expect(options.env!["npm_config_userconfig"]).toBe(npmFiles[2]);

    const source = join(f.repository, "usage.txt");
    const configArgs = [
      ...options.configOverrides!.flatMap((value) => ["--config", value]),
      "--config",
      `default_permissions=${JSON.stringify(options.config!["default_permissions"])}`,
    ];
    const probe = await runCodexCommand(
      { command: launcher },
      [
        ...configArgs,
        "sandbox",
        "-P",
        "codex_security_dependencies",
        "-C",
        f.outputDir,
        "/bin/sh",
        "-c",
        'set -eu; cat "$1" >/dev/null; "$2" --version; if printf changed >"$3" 2>/dev/null; then exit 1; fi; shift 3; for private in "$@"; do if cat "$private" >/dev/null 2>&1; then exit 1; fi; done',
        "sca-permissions",
        join(f.outputDir, "sca-result.json"),
        native,
        source,
        ...privateFiles,
      ],
      options.env!,
    );
    if (
      !probe.success &&
      process.platform === "linux" &&
      probe.stderr.includes(
        "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted",
      )
    ) {
      const configProbe = await runCodexCommand(
        { command: launcher },
        [...configArgs, "features", "list"],
        options.env!,
      );
      expect(configProbe.success, configProbe.stderr).toBe(true);
      return;
    }
    expect(probe.success, probe.stderr).toBe(true);
    expect(probe.stdout).toContain("codex-cli");
    expect(await readFile(source, "utf8")).toBe(
      "synthetic initial source context",
    );
  },
);

test.each([
  "relative",
  "home",
  "environment",
  "empty-reference",
  "case-reference",
  "relative-home",
] as const)(
  "dependency triage resolves %s npm credential paths in each scan's child profile",
  async (shape) => {
    const fixtures = await Promise.all([
      fixture({ homeVariable: "HOME" }),
      fixture({ homeVariable: "HOME" }),
    ]);
    await using first = fixtures[0]!.client;
    await using second = fixtures[1]!.client;
    const configured =
      shape === "relative"
        ? " ../registry [user].npmrc "
        : shape === "empty-reference"
          ? "${HOME}/registry${NPM_SUFFIX}.npmrc"
          : shape === "case-reference"
            ? "${NPM_REFERENCE}/registry.npmrc"
            : shape === "environment"
              ? " ${HOME}/registry.npmrc "
              : " ~/registry.npmrc ";
    for (const f of fixtures) {
      Object.assign(f.environment, {
        npm_config_userconfig: configured,
        NPM_SUFFIX: "",
        npm_reference: f.selectedUserHome,
      });
      if (shape === "relative-home")
        Object.assign(f.environment, { HOME: "../relative-home" });
    }
    await Promise.all(
      [first, second].map((client, index) =>
        client.scanDependencies({
          repositoryPath: fixtures[index]!.repository,
          outputDir: fixtures[index]!.outputDir,
        }),
      ),
    );
    const expected = fixtures.map((f) =>
      shape === "relative"
        ? resolve(f.outputDir, "../registry [user].npmrc")
        : shape === "relative-home"
          ? resolve(f.outputDir, "../relative-home/registry.npmrc")
          : shape === "case-reference" && process.platform !== "win32"
            ? resolve(f.outputDir, "${NPM_REFERENCE}/registry.npmrc")
            : join(f.selectedUserHome, "registry.npmrc"),
    );
    for (const [index, f] of fixtures.entries()) {
      const options = f.captured.codex!;
      const permissions = parseToml(
        options.configOverrides!.find((value) =>
          value.startsWith("permissions.codex_security_dependencies="),
        )!,
      )["permissions"] as Record<string, JsonObject>;
      const filesystem = permissions["codex_security_dependencies"]![
        "filesystem"
      ] as JsonObject;
      expect(filesystem[expected[index]!]).toEqual({ ".": "deny" });
      expect(filesystem[expected[1 - index]!]).toBeUndefined();
      expect(options.env!["npm_config_userconfig"]).toBe(configured);
      expect(f.captured.thread!.workingDirectory).toBe(f.outputDir);
      expect(filesystem[f.repository]).toBeUndefined();
    }
  },
);

test("dependency triage distinguishes npm's home from a USERPROFILE override on POSIX", async () => {
  const f = await fixture({ homeVariable: "USERPROFILE" });
  Object.assign(f.environment, { npm_config_userconfig: "~/registry.npmrc" });
  await using security = f.client;
  await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  const options = f.captured.codex!;
  const permissions = parseToml(
    options.configOverrides!.find((value) =>
      value.startsWith("permissions.codex_security_dependencies="),
    )!,
  )["permissions"] as Record<string, JsonObject>;
  const filesystem = permissions["codex_security_dependencies"]![
    "filesystem"
  ] as JsonObject;
  const npmHome = process.platform === "win32" ? f.selectedUserHome : homedir();
  expect(filesystem[join(npmHome, "registry.npmrc")]).toEqual({ ".": "deny" });
  expect(filesystem[join(f.selectedUserHome, ".npmrc")]).toEqual({
    ".": "deny",
  });
  expect(filesystem[join(homedir(), ".npmrc")]).toEqual({ ".": "deny" });
});

test("dependency triage disables inherited MCP servers and keeps the linked native launcher", async () => {
  const mcpConfig =
    '[mcp_servers."synthetic.inherited"]\ncommand = "synthetic-inherited"\n';
  const f = await fixture({
    mcpConfig,
    mcpOverrides: {
      "synthetic.configured": {
        command: "synthetic-configured",
        enabled: true,
      },
    },
    linkedCodex: true,
  });
  await using security = f.client;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  expect(result.status).toBe("completed");
  const options = f.captured.codex!;
  expect(options.env!["CODEX_HOME"]).toBe(f.codexHome);
  expect(parseToml(options.configOverrides![0]!)).toEqual({
    mcp_servers: {
      "synthetic.inherited": { enabled: false },
      "synthetic.configured": {
        command: "synthetic-configured",
        enabled: false,
      },
    },
  });
  const effective = await runCodexCommand(
    resolveCodexCommand(f.environment),
    [
      "-C",
      f.outputDir,
      ...options.configOverrides!.flatMap((value) => ["--config", value]),
      "--config",
      `default_permissions=${JSON.stringify(options.config!["default_permissions"])}`,
      "mcp",
      "list",
      "--json",
    ],
    options.env!,
  );
  expect(effective.success, effective.stderr).toBe(true);
  expect(
    JSON.parse(effective.stdout).map(
      (server: { name: string; enabled: boolean }) => ({
        name: server.name,
        enabled: server.enabled,
      }),
    ),
  ).toEqual([
    { name: "synthetic.configured", enabled: false },
    { name: "synthetic.inherited", enabled: false },
  ]);
  expect(await readFile(join(f.codexHome, "config.toml"), "utf8")).toBe(
    mcpConfig,
  );
  const launcherPath = f.environment.CODEX_CLI_PATH!;
  const runtimeDirectory = dirname(await realpath(launcherPath));
  expect(runtimeDirectory).not.toBe(dirname(launcherPath));
  expect(f.captured.thread!.additionalDirectories).toEqual([
    f.repository,
    PLUGIN_ROOT,
  ]);

  // Exercise the pinned SDK's argument/environment boundary without a model call.
  const receipt = join(f.outputDir, "child.json");
  const preload = join(f.outputDir, "synthetic-codex.mjs");
  await writeFile(
    preload,
    `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({ argv: process.argv.slice(2), home: process.env.CODEX_HOME }));
for (const event of [
  { type: "thread.started", thread_id: "synthetic-thread" },
  { type: "item.completed", item: { id: "message", type: "agent_message", text: "synthetic response" } },
  { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }
]) console.log(JSON.stringify(event));
process.exit(0);
`,
  );
  const node = execFileSync("node", ["-p", "process.execPath"], {
    encoding: "utf8",
  }).trim();
  const turn = await new Codex({
    ...options,
    codexPathOverride: node,
    env: {
      ...options.env,
      NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
    },
  })
    .startThread(f.captured.thread)
    .run("synthetic SDK boundary probe");
  expect(turn.finalResponse).toBe("synthetic response");
  const child = JSON.parse(await readFile(receipt, "utf8"));
  expect(child.home).toBe(f.codexHome);
  for (const override of options.configOverrides!)
    expect(child.argv).toContain(override);
  expect(child.argv).toContain(
    'default_permissions="codex_security_dependencies"',
  );
  expect(
    child.argv.flatMap((value: string, index: number, argv: string[]) =>
      value === "--add-dir" ? [argv[index + 1]] : [],
    ),
  ).toEqual(f.captured.thread!.additionalDirectories);
  expect(await readFile(join(f.codexHome, "config.toml"), "utf8")).toBe(
    mcpConfig,
  );
});

test("dependency triage preserves scanner evidence when MCP configuration cannot be read", async () => {
  const f = await fixture({ mcpConfig: "[invalid TOML\n" });
  await using security = f.client;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  expect(result.status).toBe("partial");
  expect(result.matches).toHaveLength(1);
  expect(result.assessments[0]!.status).toBe("failed");
  expect(f.calls.model).toBe(0);
  expect(result.diagnostics.join("\n")).toContain(
    "Could not read MCP configuration for a read-only helper",
  );
});

test("large advisory records stay readable without exceeding Codex's input limit", async () => {
  const advisoryDetails = "Synthetic advisory detail. ".repeat(50_000);
  const f = await fixture({ advisoryDetails });
  await using security = f.client;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  expect(result.status).toBe("completed");
  expect(JSON.stringify(f.captured.evidence).length).toBeGreaterThan(1 << 20);
  expect(Array.from(f.captured.prompt!).length).toBeLessThan(1 << 20);
  expect(f.captured.prompt).toContain(
    JSON.stringify(join(f.outputDir, "sca-result.json")),
  );
  expect(f.captured.thread!.workingDirectory).toBe(f.outputDir);
  expect(f.captured.evidence!.matches).toHaveLength(1);
  expect(
    f.captured.evidence!.matches[0]!.sourceAdvisories[0]!["details"] ===
      advisoryDetails,
  ).toBe(true);
  expect(f.captured.evidence!.assessments[0]!.status).toBe("not_started");
});

test.each([
  { path: "package-lock.json", format: "npm", ecosystem: "npm" },
  { path: "uv.lock", format: "uv", ecosystem: "PyPI" },
  { path: "go.mod", format: "go", ecosystem: "Go" },
  { path: "Cargo.lock", format: "cargo", ecosystem: "crates.io" },
  { path: "gradle.lockfile", format: "gradle", ecosystem: "Maven" },
  { path: "Gemfile.lock", format: "bundler", ecosystem: "RubyGems" },
  { path: "composer.lock", format: "composer", ecosystem: "Packagist" },
  { path: "packages.lock.json", format: "nuget", ecosystem: "NuGet" },
] as const)(
  "dependency scan persists and assesses $ecosystem with schema-valid artifacts",
  async (dependencyInput) => {
    const { client, repository, outputDir, calls, captured } = await fixture({
      dependencyInput,
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("completed");
    expect(result.assessments[0]).toMatchObject({
      status: "completed",
      verdict: "needs_review",
    });
    expect(calls).toEqual({ runtime: 1, model: 1, scanner: 1 });
    expect(captured.codex!.config).toMatchObject({
      model: "gpt-5.6-sol",
      model_reasoning_effort: "high",
      default_permissions: "codex_security_dependencies",
      features: { plugins: false, apps: false },
      mcp_servers: {},
    });
    expect(captured.thread).toMatchObject({
      threadSource: "security_dependency_triage",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      additionalDirectories: [repository, PLUGIN_ROOT],
    });
    expect(captured.prompt).toContain("triage-finding");
    expect(captured.prompt).toContain(
      JSON.stringify(join(outputDir, "sca-result.json")),
    );
    expect(captured.evidence!.matches[0]!.id).toBe("match-1");
    expect(captured.evidence!.components[0]!.ecosystem).toBe(
      dependencyInput.ecosystem,
    );
    expect(captured.evidence!.components[0]!.sourcePath).toBe(
      dependencyInput.path,
    );
    expect(result.components[0]?.ecosystem).toBe(dependencyInput.ecosystem);
    expect(result.coverage.inputs[0]?.format).toBe(dependencyInput.format);
    expect(result.model.threadId).toBe("sca-thread");
    expect(typeof result.model.skillDigest).toBe("string");
    expect(result.model.costUsd).toBeGreaterThan(0);
    const ajv = new Ajv({ strict: false });
    ajv.addSchema(
      JSON.parse(
        await readFile(
          join(PLUGIN_ROOT, "schemas/triage-result.schema.json"),
          "utf8",
        ),
      ),
      "triage-result.schema.json",
    );
    const validate = ajv.compile(
      JSON.parse(
        await readFile(
          join(PLUGIN_ROOT, "schemas/sca-result.schema.json"),
          "utf8",
        ),
      ),
    );
    validate(result);
    expect(validate.errors).toBeNull();
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
    expect(await readFile(join(outputDir, "report.md"), "utf8")).toContain(
      "SYNTHETIC-1",
    );
  },
);

test("complete zero-match scan needs no authentication or model", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    matched: false,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("completed");
  expect(result.assessments).toEqual([]);
  expect(calls).toEqual({ runtime: 0, model: 0, scanner: 1 });
});

test("completed assessment cannot promote incomplete matching coverage", async () => {
  const { client, repository, outputDir } = await fixture({
    scannerStatus: "partial",
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("partial");
  expect(result.coverage.status).toBe("partial");
  expect(result.assessments[0]!.status).toBe("completed");
});

test("failed matching without assessable matches retains its failure status", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    scannerStatus: "failed",
    matched: false,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("failed");
  expect(result.coverage.status).toBe("failed");
  expect(calls).toEqual({ runtime: 0, model: 0, scanner: 1 });
});

test.each(["runtime", "model", "malformed", "missing"])(
  "%s failure retains matches and records unavailable assessment",
  async (failure) => {
    const modelError = "synthetic transport failure: token=synthetic-value";
    const { client, repository, outputDir } = await fixture({
      runtimeError: failure === "runtime",
      error: failure === "model" ? modelError : undefined,
      malformed: failure === "malformed",
      missing: failure === "missing",
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("complete");
    expect(result.matches).toHaveLength(1);
    expect(result.assessments[0]).toMatchObject({
      status: "failed",
      verdict: null,
    });
    if (failure === "model") {
      expect(result.assessments[0]!.error).toBe(modelError);
      expect(result.diagnostics.join("\n")).toContain(modelError);
    }
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test.each(["scanner", "model"] as const)(
  "cancellation at %s preserves facts and existing interruption error",
  async (abortAt) => {
    const controller = new AbortController();
    const { client, repository, outputDir } = await fixture({
      controller,
      abortAt,
    });
    await using security = client;
    try {
      await security.scanDependencies({
        repositoryPath: repository,
        outputDir,
        signal: controller.signal,
      });
      throw new Error("expected interruption");
    } catch (error) {
      expect(error).toBeInstanceOf(ScanInterruptedError);
      expect((error as ScanInterruptedError).scanDir).toBe(outputDir);
    }
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.status).toBe("partial");
    expect(saved.matches).toHaveLength(1);
    expect(saved.assessments[0]!.status).toBe("cancelled");
  },
);

test("requested cost limit interrupts while retaining completed evidence", async () => {
  const { client, repository, outputDir } = await fixture();
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      maxCostUsd: 0.000001,
    }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  const saved = JSON.parse(
    await readFile(join(outputDir, "sca-result.json"), "utf8"),
  ) as ScaResult;
  expect(saved.matches).toHaveLength(1);
  expect(saved.status).toBe("partial");
  expect(saved.model.costUsd).toBeGreaterThan(0.000001);
});

test.each(["truncated", "malformed", "duplicate_id"] as const)(
  "a later %s response preserves saved assessments and continues independent matches",
  async (failure) => {
    const { client, repository, outputDir, turns } = await fixture({
      turns: ["completed", failure, "completed"],
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("partial");
    expect(result.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
      "completed",
    ]);
    if (failure === "truncated") expect(result.model.costUsd).toBeNull();
    expect(turns).toHaveLength(3);
    expect(turns[1]!.evidence.assessments.map((item) => item.status)).toEqual([
      "completed",
      "not_started",
      "not_started",
    ]);
    expect(turns[2]!.evidence.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
      "not_started",
    ]);
    for (const [index, turn] of turns.entries()) {
      expect(turn.evidence.matches).toHaveLength(3);
      expect(turn.prompt).toContain(JSON.stringify(`match-${index + 1}`));
      expect(turn.options).toEqual(turns[0]!.options);
      expect(turn.options).toMatchObject({
        workingDirectory: outputDir,
        approvalPolicy: "never",
        networkAccessEnabled: false,
        webSearchMode: "disabled",
      });
      expect(turn.options!.additionalDirectories).toContain(repository);
      expect(turn.options!.additionalDirectories).toContain(PLUGIN_ROOT);
    }
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test.each(["unauthorized", "source_changed", "cancelled"] as const)(
  "a later %s turn preserves an earlier failed assessment and its diagnostic",
  async (failure) => {
    const controller = new AbortController();
    const { client, repository, outputDir, turns } = await fixture({
      controller,
      turns: ["malformed", failure, "completed"],
    });
    await using security = client;
    const operation = security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      signal: controller.signal,
    });
    if (failure === "cancelled")
      await expect(operation).rejects.toBeInstanceOf(ScanInterruptedError);
    else expect((await operation).status).toBe("partial");
    expect(turns).toHaveLength(2);
    const prior = turns[1]!.evidence.assessments[0]!;
    expect(prior.status).toBe("failed");
    expect(prior.error).not.toBeNull();
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.assessments[0]).toEqual(prior);
    expect(saved.assessments.slice(1).map((item) => item.status)).toEqual([
      failure === "cancelled" ? "cancelled" : "failed",
      failure === "cancelled" ? "cancelled" : "failed",
    ]);
  },
);

test("cumulative match costs stop the next thread without discarding completed assessments", async () => {
  const { client, repository, outputDir, turns } = await fixture({
    turns: ["completed", "completed", "completed"],
  });
  const perTurn = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 1000,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 1000,
    reasoning_output_tokens: 0,
  })!.estimatedUsd;
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      maxCostUsd: perTurn * 1.5,
    }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  expect(turns).toHaveLength(2);
  const saved = JSON.parse(
    await readFile(join(outputDir, "sca-result.json"), "utf8"),
  ) as ScaResult;
  expect(saved.status).toBe("partial");
  expect(saved.model.costUsd).toBeCloseTo(perTurn * 2);
  expect(saved.assessments.map((item) => item.status)).toEqual([
    "completed",
    "completed",
    "cancelled",
  ]);
});

test.each(["unauthorized", "forbidden"] as const)(
  "a later %s event stops assessment without retrying the remaining matches",
  async (failure) => {
    const { client, repository, outputDir, turns } = await fixture({
      turns: ["completed", failure, "completed"],
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(turns).toHaveLength(2);
    expect(result.status).toBe("partial");
    expect(result.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
      "failed",
    ]);
    expect(result.assessments[1]!.error).toContain(
      failure === "unauthorized" ? "401 Unauthorized" : "403 Forbidden",
    );
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test.each(["source_changed", "cancelled"] as const)(
  "a later %s turn stops remaining work and preserves assessments of the original source",
  async (failure) => {
    const controller = new AbortController();
    const { client, repository, outputDir, turns } = await fixture({
      controller,
      turns: ["completed", failure, "completed"],
    });
    await using security = client;
    const operation = security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      signal: controller.signal,
    });
    if (failure === "cancelled")
      await expect(operation).rejects.toBeInstanceOf(ScanInterruptedError);
    else expect((await operation).status).toBe("partial");
    expect(turns).toHaveLength(2);
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.matches).toHaveLength(3);
    expect(saved.status).toBe("partial");
    expect(saved.assessments.map((item) => item.status)).toEqual([
      "completed",
      failure === "cancelled" ? "cancelled" : "failed",
      failure === "cancelled" ? "cancelled" : "failed",
    ]);
    if (failure === "source_changed")
      expect(saved.diagnostics.join("\n")).toContain(
        "earlier assessments describe the original source",
      );
  },
);

test.each([
  { failure: "throw", requested: true },
  { failure: "null", requested: true },
  { failure: "throw", requested: false },
  { failure: "null", requested: false },
])(
  "final cost verification $failure enforces requested limit: $requested",
  async ({ failure, requested }) => {
    const trackingError =
      "synthetic final cost tracking failure: token=synthetic-value";
    const { client, repository, outputDir } = await fixture();
    await using security = client;
    const originalStop = ScanCostTracker.prototype.stop;
    const stop = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
      async function (this: ScanCostTracker, usage?: unknown) {
        const snapshot = await originalStop.call(this, usage);
        if (failure === "throw") throw new Error(trackingError);
        return { ...snapshot, cost: null };
      },
    );
    try {
      const operation = security.scanDependencies({
        repositoryPath: repository,
        outputDir,
        ...(requested ? { maxCostUsd: 1 } : {}),
      });
      if (requested) {
        const error = await operation.then(
          () => null,
          (error: unknown) => error,
        );
        expect(error).toBeInstanceOf(ScanInterruptedError);
        expect((error as ScanInterruptedError).cause).toMatchObject({
          message:
            failure === "throw"
              ? trackingError
              : "Could not verify the dependency assessment cost limit.",
        });
      } else {
        expect((await operation).status).toBe("completed");
      }
      const saved = JSON.parse(
        await readFile(join(outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(saved.status).toBe(requested ? "partial" : "completed");
      if (!requested) expect(saved.model.costUsd).toBeNull();
      expect(saved.matches).toHaveLength(1);
      expect(saved.assessments[0]!.status).toBe("completed");
      if (failure === "throw")
        expect(saved.diagnostics.join("\n")).toContain(trackingError);
    } finally {
      stop.mockRestore();
    }
  },
);

test("unknown model with a requested budget cannot silently assess without cost enforcement", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    model: "unknown-model",
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
    maxCostUsd: 1,
  });
  expect(result.status).toBe("partial");
  expect(calls.model).toBe(0);
  expect(result.matches).toHaveLength(1);
});

test("SCA preserves output-path protections and argument validation", async () => {
  const { client, repository, calls } = await fixture();
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir: join(repository, "output"),
    }),
  ).rejects.toBeInstanceOf(OutputInsideProtectedRootError);
  await expect(
    security.scanDependencies({ repositoryPath: repository, maxCostUsd: -1 }),
  ).rejects.toThrow("positive USD");
  expect(calls.scanner).toBe(0);
});

test("stable initially dirty source can complete dependency assessment", async () => {
  const { client, repository, outputDir } = await fixture({
    dirtyRepository: true,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.repository.dirty).toBe(true);
  expect(result.status).toBe("completed");
  expect(result.assessments[0]!.status).toBe("completed");
});

test("unrelated Git reference changes retain all dependency assessments", async () => {
  const { client, repository, outputDir, sourceCalls } = await fixture({
    changeRefs: true,
    workbenchSnapshot: true,
    turns: ["completed", "completed"],
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(sourceCalls).toHaveLength(3);
  expect(result.status).toBe("completed");
  expect(result.assessments.map(({ status }) => status)).toEqual([
    "completed",
    "completed",
  ]);
  expect(
    JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
  ).toEqual(result);
});

test.each([
  { changeSourceAt: "scanner" as const, changeRevision: false },
  { changeSourceAt: "model" as const, changeRevision: false },
  { changeSourceAt: "model" as const, changeRevision: true },
])(
  "source drift at $changeSourceAt (revision: $changeRevision) rejects stale assessments and retains OSV facts",
  async (change) => {
    const { client, repository, outputDir } = await fixture({
      ...change,
      dirtyRepository: true,
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.repository.dirty).toBe(true);
    expect(result.repository.revision).toBe("synthetic-revision");
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("complete");
    expect(result.matches).toHaveLength(1);
    expect(result.assessments[0]).toMatchObject({
      status: "failed",
      verdict: null,
    });
    expect(result.diagnostics.join("\n")).toContain("Source changed");
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test.each([1, 2] as const)(
  "source snapshot failure at capture %i preserves OSV evidence without accepting an assessment",
  async (snapshotErrorAt) => {
    const { client, repository, outputDir, calls } = await fixture({
      snapshotErrorAt,
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("partial");
    expect(result.matches).toHaveLength(1);
    expect(result.assessments[0]).toMatchObject({
      status: "failed",
      verdict: null,
    });
    expect(result.diagnostics.join("\n")).toContain(
      "synthetic source snapshot unavailable",
    );
    expect(calls.runtime).toBe(snapshotErrorAt === 1 ? 0 : 1);
    expect(calls.model).toBe(snapshotErrorAt === 1 ? 0 : 1);
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test("zero-match inventory completes even when a source snapshot is unavailable", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    matched: false,
    snapshotErrorAt: 1,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("completed");
  expect(result.assessments).toEqual([]);
  expect(calls).toEqual({ runtime: 0, model: 0, scanner: 1 });
});

test("dependency source snapshots preserve per-scan process environment, protected root, and cancellation", async () => {
  const controller = new AbortController();
  const {
    client,
    repository,
    outputDir,
    sourceCalls,
    pythonResolutions,
    environment,
  } = await fixture({ workbenchSnapshot: true });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
    signal: controller.signal,
  });
  expect(result.status).toBe("completed");
  expect(sourceCalls).toHaveLength(2);
  expect(pythonResolutions[0]).toMatchObject({
    environment,
    protectedRoot: repository,
  });
  for (const call of sourceCalls) {
    expect(call.environment).toEqual(environment);
    expect(call.signal).toBe(pythonResolutions[0]!.signal);
    expect(call.signal!.aborted).toBe(false);
  }
  controller.abort("synthetic cancellation");
  expect(sourceCalls[0]!.signal!.aborted).toBe(true);
  expect(sourceCalls[1]!.signal!.aborted).toBe(true);
});

test.each(["xdg", "explicit"] as const)(
  "dependency triage protects the effective %s GitHub credential directory",
  async (gitHubConfig) => {
    const f = await fixture({ homeVariable: "HOME", gitHubConfig });
    await using security = f.client;
    expect(
      (
        await security.scanDependencies({
          repositoryPath: f.repository,
          outputDir: f.outputDir,
        })
      ).status,
    ).toBe("completed");
    const options = f.captured.codex!;
    const permissions = parseToml(
      options.configOverrides!.find((value) =>
        value.startsWith("permissions.codex_security_dependencies="),
      )!,
    )["permissions"] as Record<string, JsonObject>;
    const filesystem = permissions["codex_security_dependencies"]![
      "filesystem"
    ] as JsonObject;
    const directory =
      gitHubConfig === "explicit"
        ? f.environment.GH_CONFIG_DIR!
        : join(f.environment.XDG_CONFIG_HOME!, "gh");
    expect(filesystem[directory]).toEqual({ ".": "deny" });
    expect(filesystem[join(homedir(), ".config", "gh")]).toEqual({
      ".": "deny",
    });
    expect(options.env!["XDG_CONFIG_HOME"]).toBe(f.environment.XDG_CONFIG_HOME);
    expect(options.env!["GH_CONFIG_DIR"]).toBe(f.environment.GH_CONFIG_DIR);
  },
);

test.skipIf(process.platform !== "win32")(
  "dependency triage protects Windows AppData GitHub stores alongside explicit configuration",
  async () => {
    const f = await fixture({
      homeVariable: "USERPROFILE",
      gitHubConfig: "appdata",
    });
    f.environment.GH_CONFIG_DIR = join(dirname(f.repository), "explicit-gh");
    await using security = f.client;
    await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    const permissions = parseToml(
      f.captured.codex!.configOverrides!.find((value) =>
        value.startsWith("permissions.codex_security_dependencies="),
      )!,
    )["permissions"] as Record<string, JsonObject>;
    expect(
      (permissions["codex_security_dependencies"]!["filesystem"] as JsonObject)[
        join(f.environment.AppData!, "GitHub CLI")
      ],
    ).toEqual({ ".": "deny" });
    const filesystem = permissions["codex_security_dependencies"]![
      "filesystem"
    ] as JsonObject;
    expect(filesystem[f.environment.GH_CONFIG_DIR!]).toEqual({ ".": "deny" });
    const hostAppData = process.env["AppData"] ?? process.env["APPDATA"];
    if (hostAppData)
      expect(filesystem[join(hostAppData, "GitHub CLI")]).toEqual({
        ".": "deny",
      });
  },
);

test.each(["completed", "malformed", "truncated"] as const)(
  "dependency triage retains originating threads after a later %s assessment",
  async (middle) => {
    const f = await fixture({ turns: ["completed", middle, "completed"] });
    await using security = f.client;
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    expect(result.assessments.map((assessment) => assessment.threadId)).toEqual(
      ["sca-thread", "sca-thread-2", "sca-thread-3"],
    );
    expect(result.assessments.map((assessment) => assessment.status)).toEqual([
      "completed",
      middle === "completed" ? "completed" : "failed",
      "completed",
    ]);
    expect(f.turns[1]!.evidence.assessments[0]!.threadId).toBe("sca-thread");
    expect(f.turns[2]!.evidence.assessments[1]!.threadId).toBe("sca-thread-2");
    const saved = JSON.parse(
      await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
    );
    expect(saved.assessments).toEqual(result.assessments);
  },
);
