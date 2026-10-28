import { requestMetadata } from "./support/request-metadata.js";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import * as childProcess from "node:child_process";
import * as filesystem from "node:fs/promises";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
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
import { FIREWORKS_CODEX_PROVIDER, type JsonObject } from "../src/config.js";
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
import type {
  DependencyScanProgress,
  ScanActivity,
  ScanCost,
  ScanTokenUsage,
} from "../src/index.js";
import * as runtime from "../src/runtime.js";
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
import { writeSession } from "./support/usage-rollout.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

import { main } from "../src/cli.js";
import {
  dependencies as cliDependencies,
  FakeSignals,
} from "./cli-fixtures.js";
import { createCliTest, selectionPrompt } from "./support/cli-run.js";
import type { DependencyScanOptions } from "../src/index.js";

type DependencyAuthChooser = (
  auth: DependencyScanOptions["auth"],
  signal: AbortSignal,
) => Promise<DependencyScanOptions["auth"]>;

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
      affected_version_or_path: "1.0.0 in package-lock.json",
      preconditions: [],
      impact: "unknown",
      references: ["SYNTHETIC-1"],
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
    chooseDependencyAuthentication?: DependencyAuthChooser;
    matched?: boolean;
    severities?: string[];
    turns?: (
      | "completed"
      | "missing_usage"
      | "truncated"
      | "malformed"
      | "cancelled"
      | "source_changed"
      | "duplicate_id"
      | "mismatched_identity"
      | "unauthorized"
      | "forbidden"
    )[];
    distinctMatches?: boolean;
    dependencyInput?: {
      path: string;
      format: ScaResult["coverage"]["inputs"][number]["format"];
      ecosystem: string;
    };
    scannerStatus?: OsvScanResult["status"];
    missing?: boolean;
    error?: string;
    malformed?: boolean;
    commandActivity?: boolean;
    runtimeError?: boolean;
    controller?: AbortController;
    abortAt?: "source" | "revision" | "scanner" | "model";
    model?: string;
    dirtyRepository?: boolean;
    changeSourceAt?: "scanner" | "model";
    changeRevision?: boolean;
    changeRefs?: boolean;
    snapshotErrorAt?: 1 | 2 | 5;
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
  let threadCount = 0;
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
    if (options.abortAt === "source")
      options.controller!.abort("cancel during source snapshot");
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
      chooseDependencyAuthentication: options.chooseDependencyAuthentication,
      repositoryRevision: async () => {
        if (options.abortAt === "revision")
          options.controller!.abort("cancel during revision lookup");
        return revision;
      },
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
        input.onProgress?.({ phase: "discovering" });
        expect(input.environment).toEqual(environment);
        if (options.changeSourceAt === "scanner") await changeSource();
        if (options.abortAt === "scanner")
          options.controller!.abort("cancel after scanner");
        const result = scanner(input.outputDir, options.matched ?? true);
        if (options.turns !== undefined)
          result.matches = options.turns.map((_, index) => ({
            ...result.matches[0]!,
            id: `match-${index + 1}`,
            severity: options.severities?.[index] ?? null,
          }));
        if (options.distinctMatches) {
          result.components = result.matches.map((_, index) => ({
            ...result.components[0]!,
            id: `component-${index + 1}`,
            name: `synthetic-package-${index + 1}`,
            version: `${index + 1}.0.0`,
            sourcePath: `package-${index + 1}/package-lock.json`,
          }));
          result.matches = result.matches.map((match, index) => ({
            ...match,
            componentId: result.components[index]!.id,
            advisoryIds: [`SYNTHETIC-${index + 1}`],
            sourceAdvisories: [{ id: `SYNTHETIC-${index + 1}` }],
          }));
          result.coverage.inputs = result.components.map((component) => ({
            ...result.coverage.inputs[0]!,
            path: component.sourcePath,
          }));
        }
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
        if (calls.runtime === 1)
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
            const threadId =
              ++threadCount === 1 ? "sca-thread" : `sca-thread-${threadCount}`;
            let threadTurns = 0;
            return {
              id: null,
              async runStreamed(prompt) {
                threadTurns++;
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
                  input_id: JSON.parse(
                    String(prompt).match(/Assess only match ("[^"\n]+")/)![1]!,
                  ),
                  triage_item_id: `triage-${behavior === "duplicate_id" ? 1 : turnNumber}`,
                };
                const suppliedMatch =
                  behavior === "mismatched_identity"
                    ? captured.evidence!.matches[0]!
                    : captured.evidence!.matches.find(
                        (match) => match.id === finding.input_id,
                      )!;
                const suppliedComponent = captured.evidence!.components.find(
                  (component) => component.id === suppliedMatch.componentId,
                )!;
                Object.assign(finding.normalized_input, {
                  vulnerable_component: suppliedComponent.name,
                  affected_version_or_path: `${suppliedComponent.version} in ${suppliedComponent.sourcePath}`,
                  references: suppliedMatch.advisoryIds,
                });
                if (behavior === "mismatched_identity")
                  finding.verdict = "not_actionable";
                return {
                  events: (async function* (): AsyncGenerator<ThreadEvent> {
                    yield {
                      type: "thread.started",
                      thread_id: threadId,
                    };
                    if (options.commandActivity) {
                      for (const status of [
                        "in_progress",
                        "completed",
                      ] as const)
                        yield {
                          type:
                            status === "in_progress"
                              ? "item.started"
                              : "item.completed",
                          item: {
                            id: "command",
                            type: "command_execution",
                            command: "rg synthetic .",
                            aggregated_output: "",
                            status,
                          },
                        };
                    }
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
                      ...(behavior === "missing_usage"
                        ? {}
                        : {
                            usage: {
                              input_tokens: 1000 * threadTurns,
                              cached_input_tokens: 0,
                              cache_write_input_tokens: 0,
                              output_tokens: 1000 * threadTurns,
                              reasoning_output_tokens: 0,
                            },
                          }),
                    } as ThreadEvent;
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

async function nativeDependencySandboxAvailable(): Promise<boolean> {
  if (process.platform === "win32") return false;
  const directories = createTemporaryDirectories();
  try {
    const root = await directories.create("sca-sandbox-capability-");
    const home = join(root, "home");
    const codexHome = join(root, "codex-home");
    await Promise.all([
      mkdir(home, { mode: 0o700 }),
      mkdir(codexHome, { mode: 0o700 }),
    ]);
    const command = resolveCodexCommand({});
    const probe = await runCodexCommand(
      command,
      [
        "--config",
        'permissions.codex_security_sandbox_test={extends=":read-only",network={enabled=false}}',
        "sandbox",
        "-P",
        "codex_security_sandbox_test",
        "-C",
        root,
        command.command,
        "--version",
      ],
      {
        PATH: process.env["PATH"],
        HOME: home,
        USERPROFILE: home,
        XDG_CONFIG_HOME: join(home, ".config"),
        CODEX_HOME: codexHome,
      },
    );
    if (probe.success) return true;
    if (
      process.platform === "linux" &&
      /bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted|app-server socket directory must be a user-owned directory with mode 0700/u.test(
        probe.stderr,
      )
    ) {
      console.warn(
        `Native credential-read enforcement skipped; sandbox unavailable: ${probe.stderr}`,
      );
      return false;
    }
    throw new Error(`Native sandbox capability probe failed: ${probe.stderr}`);
  } finally {
    await directories.cleanup();
  }
}

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

const nativeDependencyTest = (await nativeDependencySandboxAvailable())
  ? test
  : test.skip;
nativeDependencyTest.each([
  ["HOME", false, false],
  ["USERPROFILE", false, false],
  ["HOME", true, false],
  ["USERPROFILE", true, false],
  ["HOME", false, true],
  ["USERPROFILE", false, true],
] as const)(
  "dependency triage runs a delegated native tool with private %s stores, configured GitHub home: %p, relative home: %p",
  async (homeVariable, configuredGitHubHome, relativeHome) => {
    const f = await fixture({
      wrappedCodex: true,
      ambientOutput: true,
      homeVariable,
      configuredGitHubHome,
    });
    if (relativeHome) {
      Object.assign(f.environment, {
        [homeVariable]: relative(f.outputDir, f.selectedUserHome),
      });
    }
    const npmFiles = [
      join(f.selectedUserHome, ".npmrc"),
      join(dirname(f.repository), "registry [user] #.npmrc"),
      join(dirname(f.repository), "lowercase-registry.npmrc"),
    ];
    const configuredStores = [
      join(dirname(f.repository), "registry-config", "git", "credentials"),
      join(dirname(f.repository), "cloud-credentials"),
      join(dirname(f.repository), "cloud-config"),
      join(dirname(f.repository), "custom-netrc"),
      join(dirname(f.repository), "gem-data", "gem", "credentials"),
      join(dirname(f.repository), "composer-home", "auth.json"),
      join(dirname(f.repository), "gradle-home", "gradle.properties"),
      join(dirname(f.repository), "registry-config", "composer", "auth.json"),
    ];
    const cargoFiles = [
      join(f.selectedUserHome, ".cargo", "credentials.toml"),
      join(f.selectedUserHome, ".cargo", "credentials"),
      join(dirname(f.repository), "cargo-home", "credentials.toml"),
      join(dirname(f.repository), "cargo-home", "credentials"),
    ];
    const bundlerFiles = [
      join(f.selectedUserHome, ".bundle", "config"),
      join(dirname(f.repository), "bundler-home", "config"),
      join(dirname(f.repository), "bundler-config"),
    ];
    Object.assign(f.environment, {
      NPM_CONFIG_USERCONFIG: npmFiles[1],
      npm_config_userconfig: npmFiles[2],
      XDG_CONFIG_HOME: dirname(dirname(configuredStores[0]!)),
      AWS_SHARED_CREDENTIALS_FILE: configuredStores[1],
      AWS_CONFIG_FILE: configuredStores[2],
      NETRC: configuredStores[3],
      XDG_DATA_HOME: dirname(dirname(configuredStores[4]!)),
      COMPOSER_HOME: dirname(configuredStores[5]!),
      GRADLE_USER_HOME: dirname(configuredStores[6]!),
      CARGO_HOME: dirname(cargoFiles[2]!),
      BUNDLE_USER_HOME: dirname(bundlerFiles[1]!),
      BUNDLE_USER_CONFIG: bundlerFiles[2],
    });
    await using security = f.client;
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    expect(result.status, result.diagnostics.join("\n")).toBe("completed");
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
      ...cargoFiles,
      ...bundlerFiles,
      ...[
        ".git-credentials",
        ".config/git/credentials",
        ".pypirc",
        ".m2/settings.xml",
        ".m2/settings-security.xml",
        ".aws/credentials",
        ".aws/config",
        ".netrc",
        "_netrc",
        ".gem/credentials",
        ".local/share/gem/credentials",
        ".composer/auth.json",
        ".config/composer/auth.json",
        ".gradle/gradle.properties",
        ".nuget/NuGet/NuGet.Config",
        ".config/NuGet/NuGet.Config",
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
      ...cargoFiles,
      ...bundlerFiles,
      join(homedir(), ".npmrc"),
      join(homedir(), ".git-credentials"),
      join(homedir(), ".config", "git", "credentials"),
      join(homedir(), ".pypirc"),
      join(homedir(), ".m2", "settings.xml"),
      join(homedir(), ".m2", "settings-security.xml"),
      join(homedir(), ".aws"),
      join(homedir(), ".netrc"),
      join(homedir(), "_netrc"),
      join(homedir(), ".gem", "credentials"),
      join(homedir(), ".local", "share", "gem", "credentials"),
      join(homedir(), ".bundle", "config"),
      join(homedir(), ".composer", "auth.json"),
      join(homedir(), ".config", "composer", "auth.json"),
      join(homedir(), ".cargo", "credentials.toml"),
      join(homedir(), ".cargo", "credentials"),
      join(homedir(), ".gradle", "gradle.properties"),
      join(homedir(), ".nuget", "NuGet", "NuGet.Config"),
      join(homedir(), ".config", "NuGet", "NuGet.Config"),
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
        'set -eu; cat "$1" >/dev/null; "$2" --version; if printf changed >"$3" 2>/dev/null; then exit 1; fi; shift 3; failed=0; for private in "$@"; do if cat "$private" >/dev/null 2>&1; then printf "readable private fixture: %s\\n" "$private" >&2; failed=1; fi; done; exit "$failed"',
        "sca-permissions",
        join(f.outputDir, "sca-result.json"),
        native,
        source,
        ...privateFiles,
      ],
      options.env!,
    );
    expect(probe.success, probe.stderr).toBe(true);
    expect(probe.stdout).toContain("codex-cli");
    expect(await readFile(source, "utf8")).toBe(
      "synthetic initial source context",
    );
  },
);

test.each(["absolute", "relative"] as const)(
  "dependency triage isolates %s credential-store overrides across concurrent scans",
  async (pathKind) => {
    const fixtures = await Promise.all([
      fixture({ homeVariable: "HOME" }),
      fixture({ homeVariable: "USERPROFILE" }),
    ]);
    const expected = fixtures.map((f) => {
      const curlHome = join(dirname(f.repository), "curl-home");
      if (process.platform === "win32") {
        Object.assign(f.environment, {
          HOME: curlHome,
          USERPROFILE: f.selectedUserHome,
        });
      }
      const base =
        pathKind === "relative"
          ? "../private-stores"
          : join(dirname(f.repository), "private-stores");
      const overrides = {
        NETRC: join(base, "netrc"),
        XDG_CONFIG_HOME: join(base, "config"),
        XDG_DATA_HOME: join(base, "data"),
        BUNDLE_USER_HOME: join(base, "bundler"),
        BUNDLE_USER_CONFIG: join(base, "bundler-config"),
        COMPOSER_HOME: join(base, "composer"),
        CARGO_HOME: join(base, "cargo"),
        GRADLE_USER_HOME: join(base, "gradle"),
        AppData: join(base, "appdata"),
      };
      Object.assign(
        f.environment,
        Object.fromEntries(
          Object.entries(overrides).map(([name, value]) => [
            process.platform === "win32" ? name.toLowerCase() : name,
            value,
          ]),
        ),
      );
      return [
        overrides.NETRC,
        join(overrides.XDG_CONFIG_HOME, "composer", "auth.json"),
        join(overrides.XDG_DATA_HOME, "gem", "credentials"),
        join(overrides.BUNDLE_USER_HOME, "config"),
        overrides.BUNDLE_USER_CONFIG,
        join(overrides.COMPOSER_HOME, "auth.json"),
        join(overrides.CARGO_HOME, "credentials.toml"),
        join(overrides.CARGO_HOME, "credentials"),
        join(overrides.GRADLE_USER_HOME, "gradle.properties"),
        ...(process.platform === "win32"
          ? [
              join(overrides.AppData, "Composer", "auth.json"),
              join(overrides.AppData, "NuGet", "NuGet.Config"),
              join(curlHome, ".netrc"),
              join(curlHome, "_netrc"),
              join(curlHome, ".gem", "credentials"),
              join(curlHome, ".local", "share", "gem", "credentials"),
              join(curlHome, ".bundle", "config"),
            ]
          : []),
      ].map((path) => resolve(f.outputDir, path));
    });
    await Promise.all(
      fixtures.map(async (f, index) => {
        await using security = f.client;
        const result = await security.scanDependencies({
          repositoryPath: f.repository,
          outputDir: f.outputDir,
        });
        expect(result.status, result.diagnostics.join("\n")).toBe("completed");
        const permissions = parseToml(
          f.captured.codex!.configOverrides!.find((value) =>
            value.startsWith("permissions.codex_security_dependencies="),
          )!,
        )["permissions"] as Record<string, JsonObject>;
        const filesystem = permissions["codex_security_dependencies"]![
          "filesystem"
        ] as JsonObject;
        for (const path of expected[index]!)
          expect(filesystem[path]).toEqual({ ".": "deny" });
        for (const path of expected[1 - index]!)
          expect(filesystem[path]).toBeUndefined();
        for (const path of [
          ".netrc",
          "_netrc",
          ".gem/credentials",
          ".local/share/gem/credentials",
          ".bundle/config",
          ".composer/auth.json",
          ".config/composer/auth.json",
          ".cargo/credentials.toml",
          ".cargo/credentials",
          ".gradle/gradle.properties",
          ".nuget/NuGet/NuGet.Config",
          ".config/NuGet/NuGet.Config",
        ]) {
          expect(filesystem[join(f.selectedUserHome, path)]).toEqual({
            ".": "deny",
          });
        }
      }),
    );
  },
);

test("final cost recovery persists an unchanged estimate without duplicate notifications", async () => {
  const { client, repository, outputDir } = await fixture({
    turns: ["malformed"],
  });
  await using security = client;
  const costs: Readonly<ScanCost>[] = [];
  const originalRefresh = ScanCostTracker.prototype.refresh;
  const originalStop = ScanCostTracker.prototype.stop;
  let finalizing = false;
  const refresh = spyOn(
    ScanCostTracker.prototype,
    "refresh",
  ).mockImplementation(async function (this: ScanCostTracker) {
    const snapshot = await originalRefresh.call(this);
    if (!finalizing) throw new Error("synthetic temporary usage read failure");
    return snapshot;
  });
  const stop = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
    async function (this: ScanCostTracker, usage?: unknown) {
      finalizing = true;
      return originalStop.call(this, usage);
    },
  );
  try {
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      onCost: (cost) => {
        costs.push(cost);
      },
    });
    expect(costs.length).toBeGreaterThan(0);
    const expected = costs.at(-1)!.estimatedUsd;
    expect(expected).toBeGreaterThan(0);
    expect(result.model.costUsd).toBe(expected);
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.model.costUsd).toBe(expected);
    expect(saved.model.cost?.estimatedUsd).toBe(expected);
    expect(saved.model.costPending).toBe(false);
    for (let index = 1; index < costs.length; index++)
      expect(costs[index]).not.toEqual(costs[index - 1]);
  } finally {
    refresh.mockRestore();
    stop.mockRestore();
  }
  const resumed = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
    maxCostUsd: 1,
  });
  expect(resumed.status).toBe("completed");
  expect(resumed.model.costUsd).toBeGreaterThan(costs.at(-1)!.estimatedUsd);
});

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
      if (shape === "relative-home") {
        for (const suffix of [".ssh", ".config/gh"]) {
          expect(
            filesystem[resolve(f.outputDir, "../relative-home", suffix)],
          ).toEqual({ ".": "deny" });
          expect(
            filesystem[
              resolve(
                fixtures[1 - index]!.outputDir,
                "../relative-home",
                suffix,
              )
            ],
          ).toBeUndefined();
        }
      }
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
  expect(
    parseToml(
      options.configOverrides!.find((value) =>
        value.startsWith("mcp_servers="),
      )!,
    ),
  ).toEqual({
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

test("dependency observers report saved assessments, activity, usage, and total cost", async () => {
  const f = await fixture({
    turns: ["completed", "malformed", "completed"],
    commandActivity: true,
  });
  await using security = f.client;
  const progress: DependencyScanProgress[] = [];
  const persisted: ScaResult[] = [];
  const activity: ScanActivity[] = [];
  const costs: Readonly<ScanCost>[] = [];
  const usage: Readonly<ScanTokenUsage>[] = [];
  const directories: string[] = [];
  const errors: unknown[] = [];
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
    onProgress(event) {
      progress.push(event);
      if (event.phase === "assessing" && event.current === null)
        persisted.push(
          JSON.parse(
            readFileSync(join(f.outputDir, "sca-result.json"), "utf8"),
          ),
        );
    },
    onActivity: (event) => {
      activity.push(event);
    },
    onCost: (cost) => {
      costs.push(cost);
    },
    onUsage: (tokens) => {
      usage.push(tokens);
    },
    onOutputDirReady: (directory) => {
      directories.push(directory);
    },
    onObserverError: (_observer, error) => {
      errors.push(error);
    },
  });
  expect(errors).toEqual([]);
  expect(result.status).toBe("partial");
  expect(directories).toEqual([f.outputDir]);
  expect(progress[0]).toEqual({ phase: "preparing" });
  expect(progress).toContainEqual({ phase: "discovering" });
  expect(progress.at(-1)).toEqual({ phase: "saving" });
  const assessments = progress.filter((event) => event.phase === "assessing");
  expect(
    assessments.map((event) => [
      event.assessmentsCompleted,
      event.assessmentsFailed,
      event.current?.matchId ?? null,
    ]),
  ).toEqual([
    [0, 0, "match-1"],
    [1, 0, null],
    [1, 0, "match-2"],
    [1, 1, null],
    [1, 1, "match-3"],
    [2, 1, null],
  ]);
  expect(assessments.every((event) => event.assessmentsTotal === 3)).toBe(true);
  expect(assessments[0]!.current?.advisoryIds).toEqual(
    result.matches[0]!.advisoryIds,
  );
  expect(
    persisted.map((snapshot) =>
      snapshot.assessments.map((item) => item.status),
    ),
  ).toEqual([
    ["completed", "not_started", "not_started"],
    ["completed", "failed", "not_started"],
    ["completed", "failed", "completed"],
  ]);
  expect(persisted[0]!.assessments[0]!.verdict).toBe("needs_review");
  expect(
    activity
      .filter((event) => event.kind === "message")
      .map((event) => event.id),
  ).toEqual(["match-1:message", "match-2:message", "match-3:message"]);
  expect(
    activity
      .filter((event) => event.kind === "command")
      .map((event) => [event.id, event.status]),
  ).toEqual([
    ["match-1:command", "running"],
    ["match-1:command", "completed"],
    ["match-2:command", "running"],
    ["match-2:command", "completed"],
    ["match-3:command", "running"],
    ["match-3:command", "completed"],
  ]);
  expect(costs.at(-1)?.estimatedUsd).toBe(result.model.costUsd!);
  expect(costs.at(-1)!.estimatedUsd).toBeGreaterThan(0);
  for (let index = 1; index < costs.length; index++)
    expect(costs[index]).not.toEqual(costs[index - 1]);
  expect(usage.at(-1)?.input_tokens).toBe(3000);
});

test("throwing, rejecting, and pending observers do not interrupt dependency work", async () => {
  const f = await fixture();
  await using security = f.client;
  const errors: string[] = [];
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
    onProgress() {
      throw new Error("progress unavailable");
    },
    onActivity: async () => {
      throw new Error("activity unavailable");
    },
    onCost() {
      throw new Error("cost unavailable");
    },
    onOutputDirReady: async () => {
      throw new Error("output observer unavailable");
    },
    onUsage: () => new Promise<void>(() => {}),
    onObserverError(observer) {
      errors.push(observer);
      throw new Error("error observer unavailable");
    },
  });
  expect(result.status).toBe("completed");
  expect(new Set(errors)).toEqual(
    new Set(["onProgress", "onActivity", "onCost", "onOutputDirReady"]),
  );
});

test("zero-match scans finish progress without starting model observers", async () => {
  const f = await fixture({ matched: false });
  await using security = f.client;
  const events: string[] = [];
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
    onProgress: (event) => {
      events.push(event.phase);
    },
    onActivity: () => {
      events.push("activity");
    },
    onCost: () => {
      events.push("cost");
    },
    onUsage: () => {
      events.push("usage");
    },
  });
  expect(result.status).toBe("completed");
  expect(events).toEqual(["preparing", "discovering", "saving"]);
  expect(f.calls.model).toBe(0);
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
    expect(requestMetadata(captured.codex!.configOverrides)).toMatchObject({
      codex_security_command: "dependencies",
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

test("completed assessment cannot promote or continue incomplete matching coverage", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    scannerStatus: "partial",
  });
  await using security = client;
  const options = { repositoryPath: repository, outputDir };
  const result = await security.scanDependencies(options);
  expect(result.status).toBe("partial");
  expect(result.coverage.status).toBe("partial");
  expect(result.assessments[0]!.status).toBe("completed");
  const checkpoint = await readFile(join(outputDir, "sca-result.json"));
  const report = await readFile(join(outputDir, "report.md"));
  await expect(security.scanDependencies(options)).rejects.toThrow(
    "Start a new run in a new output directory to refresh matching",
  );
  expect(calls).toEqual({ runtime: 1, model: 1, scanner: 1 });
  expect(await readFile(join(outputDir, "sca-result.json"))).toEqual(
    checkpoint,
  );
  expect(await readFile(join(outputDir, "report.md"))).toEqual(report);
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

test.each(["source", "revision"] as const)(
  "cancellation during %s provenance saves an incomplete result before inventory",
  async (abortAt) => {
    const controller = new AbortController();
    const { client, repository, outputDir, calls } = await fixture({
      controller,
      abortAt,
    });
    await using security = client;
    await expect(
      security.scanDependencies({
        repositoryPath: repository,
        outputDir,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ scanDir: outputDir });
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.status).toBe("partial");
    expect(saved.coverage.status).toBe("failed");
    expect(saved.repository.path).toBe(repository);
    expect(saved.matches).toEqual([]);
    expect(saved.scanner.invocations).toEqual([]);
    expect(await readFile(join(outputDir, "report.md"), "utf8")).toContain(
      "partial",
    );
    expect(calls.scanner).toBe(0);
    expect(calls.runtime).toBe(0);
  },
);

test.each(["scanner", "model"] as const)(
  "cancellation at %s preserves facts and existing interruption error",
  async (abortAt) => {
    const controller = new AbortController();
    const progress: DependencyScanProgress[] = [];
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
        onProgress: (event) => {
          progress.push(event);
        },
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
    expect(progress.at(-1)).toEqual({ phase: "saving" });
    expect(
      progress.some(
        (event) =>
          event.phase === "assessing" && event.assessmentsCompleted > 0,
      ),
    ).toBe(false);
  },
);

test("cancellation during the final dependency artifact save retains completed assessments", async () => {
  const controller = new AbortController();
  const reason = new Error("synthetic cancellation during final artifact save");
  const { client, repository, outputDir } = await fixture();
  await using security = client;
  const originalRename = filesystem.rename;
  const rename = spyOn(filesystem, "rename").mockImplementation(
    async (source, destination) => {
      await originalRename(source, destination);
      if (String(destination) !== join(outputDir, "report.md")) return;
      const saved = JSON.parse(
        await readFile(join(outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      if (saved.status === "completed") controller.abort(reason);
    },
  );
  try {
    const error = await security
      .scanDependencies({
        repositoryPath: repository,
        outputDir,
        signal: controller.signal,
      })
      .then(
        () => null,
        (error: unknown) => error,
      );
    expect(controller.signal.aborted).toBe(true);
    expect(error).toBeInstanceOf(ScanInterruptedError);
    expect((error as ScanInterruptedError).cause).toBe(reason);
    expect((error as ScanInterruptedError).scanDir).toBe(outputDir);
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.status).toBe("partial");
    expect(saved.matches).toHaveLength(1);
    expect(saved.assessments[0]!.status).toBe("completed");
    expect(await readFile(join(outputDir, "report.md"), "utf8")).toContain(
      "partial",
    );
  } finally {
    rename.mockRestore();
  }
});

test("requested cost limit interrupts while retaining completed evidence", async () => {
  const { client, repository, outputDir } = await fixture();
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      maxCostUsd: 0.000001,
      onCost: async () => {
        throw new Error("cost observer unavailable");
      },
      onProgress: () => new Promise<void>(() => {}),
    }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  const saved = JSON.parse(
    await readFile(join(outputDir, "sca-result.json"), "utf8"),
  ) as ScaResult;
  expect(saved.matches).toHaveLength(1);
  expect(saved.status).toBe("partial");
  expect(saved.model.costUsd).toBeGreaterThan(0.000001);
});

test("a response describing another selected match fails only its own assessment", async () => {
  const { client, repository, outputDir, turns } = await fixture({
    turns: ["completed", "mismatched_identity", "completed"],
    distinctMatches: true,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("partial");
  expect(result.assessments.map(({ status }) => status)).toEqual([
    "completed",
    "failed",
    "completed",
  ]);
  expect(result.assessments[1]).toMatchObject({
    matchId: "match-2",
    verdict: null,
    triage: null,
    error:
      "Dependency triage assessment does not identify the selected package, version, source, and advisory.",
  });
  expect(result.matches).toEqual(turns[0]!.evidence.matches);
  expect(result.components).toEqual(turns[0]!.evidence.components);
  expect(
    result.assessments[0]!.triage!.normalized_input.vulnerable_component,
  ).toBe("synthetic-package-1");
  expect(
    result.assessments[2]!.triage!.normalized_input.vulnerable_component,
  ).toBe("synthetic-package-3");
  expect(turns[2]!.evidence.assessments.map(({ status }) => status)).toEqual([
    "completed",
    "failed",
    "not_started",
  ]);
  expect(
    JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
  ).toEqual(result);
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

test.each(["unchanged", "changed", "snapshot unavailable"] as const)(
  "final cost collection preserves source integrity: %s",
  async (source) => {
    const { client, repository, outputDir, codexHome, turns } = await fixture({
      ...(source === "snapshot unavailable" ? { snapshotErrorAt: 5 } : {}),
    });
    await using security = client;
    const sessions = join(codexHome, "sessions");
    await mkdir(sessions);
    const reading = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let stopping = false;
    const originalStop = ScanCostTracker.prototype.stop;
    const stop = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
      async function (this: ScanCostTracker, usage?: unknown) {
        stopping = true;
        try {
          return await originalStop.call(this, usage);
        } finally {
          stopping = false;
        }
      },
    );
    const originalReaddir = filesystem.readdir;
    const readdir = spyOn(filesystem, "readdir").mockImplementation((async (
      ...args: Parameters<typeof filesystem.readdir>
    ) => {
      if (stopping && args[0] === sessions) {
        reading.resolve();
        await release.promise;
      }
      return await originalReaddir(...args);
    }) as typeof filesystem.readdir);
    const operation = security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    try {
      await Promise.race([
        reading.promise,
        operation.then(() => {
          throw new Error("Scan finished before final cost collection.");
        }),
      ]);
      const checkpoint = JSON.parse(
        await readFile(join(outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(checkpoint.assessments[0]!.status).toBe("completed");
      if (source === "changed")
        await writeFile(
          join(repository, "usage.txt"),
          "synthetic source changed during final cost collection",
        );
      release.resolve();
      const result = await operation;
      expect(result.status).toBe(
        source === "unchanged" ? "completed" : "partial",
      );
      expect(result.repository).toEqual(checkpoint.repository);
      expect(result.coverage).toEqual(checkpoint.coverage);
      expect(result.matches).toEqual(checkpoint.matches);
      expect(result.assessments).toEqual(checkpoint.assessments);
      expect(result.model.costUsd).toBeGreaterThan(0);
      expect(turns).toHaveLength(1);
      if (source !== "unchanged")
        expect(result.diagnostics.join("\n")).toContain(
          source === "changed"
            ? "earlier assessments describe the original source"
            : "synthetic source snapshot unavailable",
        );
      expect(
        JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
      ).toEqual(result);
    } finally {
      release.resolve();
      await operation.catch(() => {});
      readdir.mockRestore();
      stop.mockRestore();
    }
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
  expect(sourceCalls).toHaveLength(6);
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
    expect(calls.runtime).toBe(0);
    expect(calls.model).toBe(0);
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
  const python = spyOn(runtime, "resolvePluginPython");
  try {
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
    expect(sourceCalls).toHaveLength(5);
    expect(pythonResolutions[0]).toMatchObject({
      environment,
      protectedRoot: repository,
    });
    expect(python).toHaveBeenCalledWith(
      expect.objectContaining({
        configuredPath: sourceCalls[0]!.python,
        environment,
        protectedRoot: repository,
      }),
    );
    for (const call of sourceCalls) {
      expect(call.environment).toEqual(environment);
      expect(call.signal).toBe(pythonResolutions[0]!.signal);
      expect(call.signal!.aborted).toBe(false);
    }
    controller.abort("synthetic cancellation");
    expect(sourceCalls[0]!.signal!.aborted).toBe(true);
    expect(sourceCalls[1]!.signal!.aborted).toBe(true);
  } finally {
    python.mockRestore();
  }
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
      [
        "sca-thread",
        "sca-thread",
        middle === "truncated" ? "sca-thread-2" : "sca-thread",
      ],
    );
    expect(result.assessments.map((assessment) => assessment.status)).toEqual([
      "completed",
      middle === "completed" ? "completed" : "failed",
      "completed",
    ]);
    expect(f.turns[1]!.evidence.assessments[0]!.threadId).toBe("sca-thread");
    expect(f.turns[2]!.evidence.assessments[1]!.threadId).toBe("sca-thread");
    const saved = JSON.parse(
      await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
    );
    expect(saved.assessments).toEqual(result.assessments);
  },
);

test("prioritizes severity, reuses a package thread, and supplies focused evidence", async () => {
  const f = await fixture({
    turns: ["completed", "completed", "completed"],
    severities: ["LOW", "CRITICAL", "HIGH"],
  });
  await using security = f.client;
  const inventories: Readonly<ScaResult>[] = [];
  let modelCallsAtInventory: number | undefined;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
    onInventory: (inventory) => {
      inventories.push(inventory);
      modelCallsAtInventory = f.calls.model;
      // Observers receive detached data and cannot alter the scan.
      inventory.matches[0]!.severity = "observer-only";
      throw new Error("synthetic inventory observer failure");
    },
  });
  expect(result.status).toBe("completed");
  expect(inventories).toHaveLength(1);
  expect(modelCallsAtInventory).toBe(0);
  expect(result.matches[0]!.severity).toBe("LOW");
  expect(
    f.turns.map((turn) =>
      JSON.parse(turn.prompt.match(/Assess only match ("[^"\n]+")/)![1]!),
    ),
  ).toEqual(["match-2", "match-3", "match-1"]);
  expect(new Set(result.assessments.map((item) => item.threadId)).size).toBe(1);
  expect(result.model.cost?.inputTokens).toBe(3000);
  expect(result.model.cost?.outputTokens).toBe(3000);
  const evidence = JSON.parse(
    await readFile(join(f.outputDir, "sca-assessment-input.json"), "utf8"),
  );
  expect(evidence.match.id).toBe("match-1");
  expect(
    evidence.earlierAssessments.map(
      (item: { matchId: string }) => item.matchId,
    ),
  ).toEqual(["match-2", "match-3"]);
  expect(evidence).not.toHaveProperty("components");
  expect(evidence).not.toHaveProperty("matches");
});

test("continues a budget-stopped run without repeating matching or completed assessments", async () => {
  const f = await fixture({ turns: ["completed", "completed", "completed"] });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const perTurn = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 1000,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 1000,
    reasoning_output_tokens: 0,
  })!.estimatedUsd;
  await expect(
    security.scanDependencies({ ...options, maxCostUsd: perTurn * 1.5 }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  const savedPath = join(f.outputDir, "sca-result.json");
  const checkpoint = await readFile(savedPath, "utf8");
  const prior: ScaResult = JSON.parse(checkpoint);
  await expect(
    security.scanDependencies({ ...options, maxCostUsd: perTurn * 1.5 }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  expect(await readFile(savedPath, "utf8")).toBe(checkpoint);
  const costs: number[] = [];
  const result = await security.scanDependencies({
    ...options,
    maxCostUsd: perTurn * 3.5,
    onCost: (cost) => {
      costs.push(cost.estimatedUsd);
    },
  });
  expect(result.status).toBe("completed");
  expect(result.assessments.slice(0, 2)).toEqual(prior.assessments.slice(0, 2));
  expect(f.calls.scanner).toBe(1);
  expect(f.turns).toHaveLength(3);
  expect(costs[0]).toBeCloseTo(perTurn * 2);
  expect(result.model.costUsd).toBeCloseTo(perTurn * 3);
  expect(result.model.cost?.inputTokens).toBe(3000);
  expect(result.model.cost?.estimatedUsdRange?.max).toBeGreaterThan(
    result.model.costUsd!,
  );
});

test.each([
  "source",
  "configuration",
  "provider",
  "endpoint",
  "environment endpoint",
] as const)(
  "refuses continuation after changed %s and preserves saved artifacts",
  async (change) => {
    const provider = {
      name: "Synthetic provider",
      base_url: "https://provider.example.invalid/v1",
      wire_api: "responses",
      requires_openai_auth: true,
    };
    const f = await fixture({
      turns: ["completed", "malformed"],
      codexOverrides:
        change === "endpoint"
          ? { openai_base_url: "https://provider.example.invalid/v1" }
          : change === "environment endpoint"
            ? {}
            : {
                model_provider: "synthetic.provider",
                model_providers: { "synthetic.provider": provider },
              },
    });
    await using security = f.client;
    if (change === "environment endpoint")
      Object.assign(f.environment, {
        OPENAI_BASE_URL: "https://provider.example.invalid/v1",
      });
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    await security.scanDependencies(options);
    if (change === "environment endpoint")
      Object.assign(f.environment, {
        OPENAI_BASE_URL: "https://changed.example.invalid/v1",
      });
    else if (change === "source")
      await writeFile(join(f.repository, "usage.txt"), "changed source");
    else if (change === "configuration")
      Object.assign(security.config.codexOverrides!, {
        model_reasoning_effort: "low",
      });
    else if (change === "endpoint")
      Object.assign(security.config.codexOverrides!, {
        openai_base_url: "https://changed.example.invalid/v1",
      });
    else
      Object.assign(security.config.codexOverrides!, {
        model_providers: {
          "synthetic.provider": {
            ...provider,
            base_url: "https://changed.example.invalid/v1",
          },
        },
      });
    const checkpoint = await readFile(
      join(f.outputDir, "sca-result.json"),
      "utf8",
    );
    await expect(security.scanDependencies(options)).rejects.toThrow(
      change === "source"
        ? "source changed"
        : "model, effort, provider, instructions, or skill changed",
    );
    expect(await readFile(join(f.outputDir, "sca-result.json"), "utf8")).toBe(
      checkpoint,
    );
    expect(f.turns).toHaveLength(2);
    expect(f.calls.scanner).toBe(1);
  },
);

test("rejects concurrent assessment of the same output directory", async () => {
  const f = await fixture();
  await using security = f.client;
  await using competitor = new TestClient({}, { environment: f.environment });
  let concurrent: Promise<unknown> | undefined;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const result = await security.scanDependencies({
    ...options,
    onInventory: () => {
      concurrent = competitor
        .scanDependencies(options)
        .catch((error: unknown) => error);
    },
  });
  expect(result.status).toBe("completed");
  expect(await concurrent).toMatchObject({
    message: "A dependency scan is already running.",
  });
  expect(f.calls.scanner).toBe(1);
});

test("finalizes an interrupted checkpoint with all assessments already saved", async () => {
  const f = await fixture({ turns: ["completed", "completed"] });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const perTurn = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 1000,
    cache_write_input_tokens: 0,
    output_tokens: 1000,
  })!.estimatedUsd;
  await expect(
    security.scanDependencies({ ...options, maxCostUsd: perTurn * 1.5 }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  const checkpoint: ScaResult = JSON.parse(
    await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
  );
  expect(checkpoint.status).toBe("partial");
  expect(
    checkpoint.assessments.every((item) => item.status === "completed"),
  ).toBe(true);
  const result = await security.scanDependencies({
    ...options,
    maxCostUsd: perTurn * 3,
  });
  expect(result.status).toBe("completed");
  expect(result.assessments).toEqual(checkpoint.assessments);
  expect(result.model.cost).toEqual(checkpoint.model.cost);
  expect(result.assessmentContext).toEqual(checkpoint.assessmentContext);
  expect(f.turns).toHaveLength(2);
  expect(f.calls).toEqual({ runtime: 1, model: 1, scanner: 1 });
});

test.each([
  "unavailable runtime",
  "changed settings",
  "missing assessment",
  "exact budget",
  "over budget",
  "zero budget",
  "NaN budget",
  "unverified cost",
  "unverified cost without limit",
  "source changed",
  "source changed before finalization",
  "cancelled before finalization",
] as const)("handles a fully assessed checkpoint with %s", async (scenario) => {
  const f = await fixture({ turns: ["completed", "completed"] });
  await using initial = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const perTurn = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 1000,
    cache_write_input_tokens: 0,
    output_tokens: 1000,
  })!.estimatedUsd;
  const unverified = scenario.startsWith("unverified cost");
  const originalStop = ScanCostTracker.prototype.stop;
  const stop = unverified
    ? spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
        async function (this: ScanCostTracker, usage?: unknown) {
          return { ...(await originalStop.call(this, usage)), cost: null };
        },
      )
    : undefined;
  try {
    await expect(
      initial.scanDependencies({
        ...options,
        maxCostUsd: perTurn * (unverified ? 3 : 1.5),
      }),
    ).rejects.toBeInstanceOf(
      unverified ? ScanInterruptedError : ScanCostLimitExceededError,
    );
  } finally {
    stop?.mockRestore();
  }
  const path = join(f.outputDir, "sca-result.json");
  let serialized = await readFile(path, "utf8");
  const checkpoint: ScaResult = JSON.parse(serialized);
  expect(checkpoint.status).toBe("partial");
  expect(checkpoint.coverage.status).toBe("complete");
  expect(
    checkpoint.assessments.every((item) => item.status === "completed"),
  ).toBe(true);
  expect(checkpoint.model.costPending).toBe(unverified);
  if (scenario === "missing assessment") {
    checkpoint.assessments.pop();
    serialized = `${JSON.stringify(checkpoint, null, 2)}\n`;
    await writeFile(path, serialized);
  }
  if (scenario === "source changed")
    await writeFile(
      join(f.repository, "usage.txt"),
      "synthetic changed source",
    );
  const controller = new AbortController();
  const calls = { runtime: 0, model: 0, scanner: 0 };
  let snapshots = 0;
  await using continuation = new TestClient(
    scenario === "changed settings"
      ? {
          codexOverrides: {
            model: "synthetic-unpriced-model",
            model_reasoning_effort: "low",
          },
        }
      : initial.config,
    {
      environment: f.environment,
      sourceSnapshot: async () => {
        if (++snapshots === 2) {
          if (scenario === "source changed before finalization")
            await writeFile(
              join(f.repository, "usage.txt"),
              "synthetic changed source before finalization",
            );
          if (scenario === "cancelled before finalization")
            controller.abort("synthetic cancellation before finalization");
        }
        return {
          repository: f.repository,
          revision: checkpoint.repository.revision,
          content: await readFile(join(f.repository, "usage.txt"), "utf8"),
        };
      },
      prepareRuntime: async () => {
        calls.runtime++;
        throw new Error("synthetic authentication unavailable");
      },
      createCodex: () => {
        calls.model++;
        throw new Error("No model work remains");
      },
      runOsvScan: async () => {
        calls.scanner++;
        throw new Error("Matching must not repeat");
      },
    },
  );
  const maxCostUsd =
    scenario === "unverified cost without limit"
      ? undefined
      : scenario === "zero budget"
        ? 0
        : scenario === "NaN budget"
          ? Number.NaN
          : perTurn *
            (scenario === "over budget"
              ? 1.5
              : scenario === "exact budget"
                ? 2
                : 3);
  const costs: Readonly<ScanCost>[] = [];
  const operation = continuation.scanDependencies({
    ...options,
    maxCostUsd,
    signal: controller.signal,
    onCost: (cost) => {
      costs.push(cost);
    },
  });
  if (scenario === "over budget")
    await expect(operation).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  else if (scenario === "zero budget" || scenario === "NaN budget")
    await expect(operation).rejects.toThrow("positive USD amount");
  else if (scenario === "unverified cost")
    await expect(operation).rejects.toThrow(
      "earlier assessment usage is unavailable",
    );
  else if (scenario.startsWith("source changed"))
    await expect(operation).rejects.toThrow("source changed");
  else if (scenario === "missing assessment") {
    const result = await operation;
    expect(result.status).toBe("partial");
    expect(result.matches).toEqual(checkpoint.matches);
    expect(result.assessments).toEqual(checkpoint.assessments);
    expect(result.diagnostics.at(-1)).toContain(
      "synthetic authentication unavailable",
    );
  } else if (scenario === "cancelled before finalization")
    await expect(operation).rejects.toBeInstanceOf(ScanInterruptedError);
  else {
    const result = await operation;
    expect(result.status).toBe("completed");
    expect(result.assessments).toEqual(checkpoint.assessments);
    expect(result.assessmentContext).toEqual(checkpoint.assessmentContext);
    expect(result.matches).toEqual(checkpoint.matches);
    expect(result.components).toEqual(checkpoint.components);
    expect(result.model).toEqual(checkpoint.model);
    if (unverified) {
      expect(result.model.costPending).toBe(true);
      expect(result.model.costUsd).toBeNull();
      expect(result.model.cost).toBeUndefined();
      expect(costs).toEqual([]);
    } else expect(costs).toEqual([checkpoint.model.cost!]);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(result);
  }
  if (
    ![
      "unavailable runtime",
      "changed settings",
      "exact budget",
      "unverified cost without limit",
    ].includes(scenario)
  )
    expect(await readFile(path, "utf8")).toBe(serialized);
  expect(calls).toEqual({
    runtime: scenario === "missing assessment" ? 1 : 0,
    model: 0,
    scanner: 0,
  });
  expect(f.calls).toEqual({ runtime: 1, model: 1, scanner: 1 });
  expect(f.turns).toHaveLength(2);
});

test("continues unfinished assessments after incomplete matching without repeating matching", async () => {
  const f = await fixture({
    scannerStatus: "partial",
    turns: ["completed", "malformed"],
  });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const initial = await security.scanDependencies(options);
  expect(initial.coverage.status).toBe("partial");
  expect(initial.assessments.map((item) => item.status)).toEqual([
    "completed",
    "failed",
  ]);
  const resumed = await security.scanDependencies(options);
  expect(resumed.status).toBe("partial");
  expect(resumed.coverage).toEqual(initial.coverage);
  expect(resumed.assessments[0]).toEqual(initial.assessments[0]);
  expect(resumed.assessments[1]!.status).toBe("completed");
  expect(f.turns).toHaveLength(3);
  expect(f.calls).toEqual({ runtime: 1, model: 2, scanner: 1 });
  const checkpoint = await readFile(join(f.outputDir, "sca-result.json"));
  await expect(security.scanDependencies(options)).rejects.toThrow(
    "Start a new run in a new output directory to refresh matching",
  );
  expect(await readFile(join(f.outputDir, "sca-result.json"))).toEqual(
    checkpoint,
  );
  expect(f.calls).toEqual({ runtime: 1, model: 2, scanner: 1 });
});

test("source drift during inventory does not create a resumable checkpoint", async () => {
  const f = await fixture({ changeSourceAt: "scanner" });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const result = await security.scanDependencies(options);
  expect(result.status).toBe("partial");
  expect(result.assessmentContext).toBeUndefined();
  expect(result.matches).toHaveLength(1);
  await writeFile(
    join(f.repository, "usage.txt"),
    "synthetic initial source context",
  );
  await expect(security.scanDependencies(options)).rejects.toThrow(
    "no source checkpoint",
  );
  expect(f.turns).toHaveLength(0);
  expect(f.calls.scanner).toBe(1);
});

test("continues saved matching after authentication becomes available", async () => {
  const fixtureOptions = { runtimeError: true };
  const f = await fixture(fixtureOptions);
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const initial = await security.scanDependencies(options);
  expect(initial.status).toBe("partial");
  expect(initial.assessmentContext?.sourceDigest).toBeString();
  expect(initial.assessmentContext?.configurationDigest).toBeNull();
  expect(f.turns).toHaveLength(0);
  const savedPath = join(f.outputDir, "sca-result.json");
  const checkpoint = await readFile(savedPath, "utf8");
  const blocked = await security.scanDependencies(options);
  expect(blocked.status).toBe("partial");
  expect(blocked.matches).toEqual(initial.matches);
  expect(blocked.assessments).toEqual(initial.assessments);
  expect(blocked.diagnostics.at(-1)).toContain(
    "synthetic authentication unavailable",
  );
  expect(await readFile(savedPath, "utf8")).toBe(checkpoint);
  fixtureOptions.runtimeError = false;
  const result = await security.scanDependencies(options);
  expect(result.status).toBe("completed");
  expect(f.calls.scanner).toBe(1);
  expect(f.turns).toHaveLength(1);
});

test("continuation setup failure returns completed assessments without changing the checkpoint", async () => {
  const f = await fixture({ turns: ["completed", "malformed"] });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const initial = await security.scanDependencies(options);
  expect(initial.status).toBe("partial");
  expect(initial.assessments[0]!.status).toBe("completed");
  const savedPath = join(f.outputDir, "sca-result.json");
  const checkpoint = await readFile(savedPath, "utf8");
  await using blockedClient = new TestClient(security.config, {
    environment: f.environment,
    sourceSnapshot: async () => ({
      repository: f.repository,
      revision: initial.repository.revision,
      content: await readFile(join(f.repository, "usage.txt"), "utf8"),
    }),
    prepareRuntime: async () => {
      throw new Error("synthetic authentication unavailable");
    },
    runOsvScan: async () => {
      throw new Error("Matching must not repeat during continuation");
    },
  });

  const blocked = await blockedClient.scanDependencies(options);
  expect(blocked.status).toBe("partial");
  expect(blocked.assessments).toEqual(initial.assessments);
  expect(blocked.matches).toEqual(initial.matches);
  expect(blocked.scanner).toEqual(initial.scanner);
  expect(blocked.model).toEqual(initial.model);
  expect(blocked.diagnostics.at(-1)).toContain(
    "synthetic authentication unavailable",
  );
  expect(await readFile(savedPath, "utf8")).toBe(checkpoint);
  expect(f.calls.scanner).toBe(1);
  expect(f.turns).toHaveLength(2);

  const completed = await security.scanDependencies(options);
  expect(completed.status).toBe("completed");
  expect(completed.assessments[0]).toEqual(initial.assessments[0]);
  expect(f.calls.scanner).toBe(1);
  expect(f.turns).toHaveLength(3);
});

test("continuation rejects linked lock directories before recovery writes", async () => {
  const f = await fixture();
  await using security = f.client;
  const external = await temporaryDirectory("synthetic-lock-target-");
  await mkdir(f.outputDir, { mode: 0o700 });
  await writeFile(join(f.outputDir, "sca-result.json"), "{}");
  await symlink(
    external,
    join(f.outputDir, ".lock"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await expect(
    security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    }),
  ).rejects.toThrow("lock must be a real directory");
  expect(await readdir(external)).toEqual([]);
  expect(f.calls.scanner).toBe(0);
});

test("historical thread cost cannot verify a later interrupted turn", async () => {
  const controller = new AbortController();
  const f = await fixture({
    controller,
    turns: ["completed", "cancelled"],
  });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const originalStop = ScanCostTracker.prototype.stop;
  const stop = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
    async function (this: ScanCostTracker, usage?: unknown) {
      const snapshot = await originalStop.call(this, usage);
      return {
        ...snapshot,
        cost: estimateScanCost("gpt-5.6-sol", {
          input_tokens: 1000,
          cache_write_input_tokens: 0,
          output_tokens: 1000,
        }),
      };
    },
  );
  try {
    await expect(
      security.scanDependencies({ ...options, signal: controller.signal }),
    ).rejects.toBeInstanceOf(ScanInterruptedError);
  } finally {
    stop.mockRestore();
  }
  const savedPath = join(f.outputDir, "sca-result.json");
  const saved = await readFile(savedPath, "utf8");
  const checkpoint: ScaResult = JSON.parse(saved);
  expect(checkpoint.model.cost?.inputTokens).toBe(1000);
  expect(checkpoint.model.costPending).toBe(true);
  await expect(
    security.scanDependencies({ ...options, maxCostUsd: 10 }),
  ).rejects.toThrow("earlier assessment usage is unavailable");
  expect(await readFile(savedPath, "utf8")).toBe(saved);
  expect(f.turns).toHaveLength(2);
});

test("an unverified reused turn stops budget-limited work before another assessment", async () => {
  const f = await fixture({ turns: ["completed", "truncated", "completed"] });
  await using security = f.client;
  const originalRefresh = ScanCostTracker.prototype.refresh;
  const refresh = spyOn(
    ScanCostTracker.prototype,
    "refresh",
  ).mockImplementation(async function (this: ScanCostTracker) {
    const snapshot = await originalRefresh.call(this);
    return {
      ...snapshot,
      cost:
        snapshot.cost ??
        estimateScanCost("gpt-5.6-sol", {
          input_tokens: 1000,
          cache_write_input_tokens: 0,
          output_tokens: 1000,
        }),
    };
  });
  try {
    const failure = await security
      .scanDependencies({
        repositoryPath: f.repository,
        outputDir: f.outputDir,
        maxCostUsd: 10,
      })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ScanInterruptedError);
    expect((failure as ScanInterruptedError).cause).toMatchObject({
      message: "Could not verify the dependency assessment cost limit.",
    });
  } finally {
    refresh.mockRestore();
  }
  const saved: ScaResult = JSON.parse(
    await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
  );
  expect(saved.model.costPending).toBe(true);
  expect(saved.assessments.map((item) => item.status)).toEqual([
    "completed",
    "failed",
    "cancelled",
  ]);
  expect(f.turns).toHaveLength(2);
});

test.each([false, true])(
  "continuation preserves unknown prior spend (pending checkpoint: %p)",
  async (pending) => {
    const f = await fixture({ turns: ["completed", "truncated"] });
    await using security = f.client;
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    await security.scanDependencies(options);
    const path = join(f.outputDir, "sca-result.json");
    if (pending) {
      const checkpoint: ScaResult = JSON.parse(await readFile(path, "utf8"));
      checkpoint.model.costPending = true;
      const priorCost = estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1000,
        output_tokens: 1000,
      })!;
      checkpoint.model.cost = { ...priorCost };
      checkpoint.model.costUsd = priorCost.estimatedUsd;
      await writeFile(path, JSON.stringify(checkpoint));
    }
    const original = await readFile(path, "utf8");
    await expect(
      security.scanDependencies({ ...options, maxCostUsd: 10 }),
    ).rejects.toThrow("earlier assessment usage is unavailable");
    expect(await readFile(path, "utf8")).toBe(original);
    const costs: unknown[] = [];
    const result = await security.scanDependencies({
      ...options,
      onCost: (cost) => {
        costs.push(cost);
      },
    });
    expect(result.status).toBe("completed");
    expect(result.model.costUsd).toBeNull();
    expect(result.model.cost).toBeUndefined();
    expect(costs).toHaveLength(0);
    expect(f.calls.scanner).toBe(1);
    expect(f.turns).toHaveLength(3);
  },
);

test.each(["built-in", "custom provider"] as const)(
  "continuation ignores an environment endpoint overridden by %s configuration",
  async (kind) => {
    const endpoint = "https://configured.example.invalid/v1";
    const f = await fixture({
      turns: ["completed", "malformed"],
      codexOverrides:
        kind === "built-in"
          ? { openai_base_url: endpoint }
          : {
              model_provider: "synthetic.provider",
              model_providers: {
                "synthetic.provider": {
                  name: "Synthetic provider",
                  base_url: endpoint,
                  wire_api: "responses",
                  requires_openai_auth: true,
                },
              },
            },
    });
    await using security = f.client;
    Object.assign(f.environment, {
      OPENAI_BASE_URL: "https://ignored.example.invalid/v1",
    });
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    const initial = await security.scanDependencies(options);
    Object.assign(f.environment, {
      OPENAI_BASE_URL: "https://changed.example.invalid/v1",
    });
    const result = await security.scanDependencies(options);
    expect(result.status, result.diagnostics.join("\n")).toBe("completed");
    expect(result.assessments[0]).toEqual(initial.assessments[0]);
    expect(f.turns).toHaveLength(3);
    expect(f.calls.scanner).toBe(1);
  },
);

test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "unreadable optional installed metadata preserves inventory and continuation",
  async () => {
    const f = await fixture({ turns: ["malformed", "completed"] });
    await using security = f.client;
    await writeFile(
      join(f.repository, "package.json"),
      JSON.stringify({
        name: "synthetic-project",
        dependencies: { "synthetic-package": "1.0.0" },
      }),
    );
    const installed = join(f.repository, "node_modules/synthetic-package");
    await mkdir(installed, { recursive: true });
    const manifest = join(installed, "package.json");
    await writeFile(
      manifest,
      JSON.stringify({ name: "synthetic-package", version: "1.0.0" }),
    );
    await chmod(manifest, 0o000);
    try {
      let observed: ScaResult | undefined;
      const options = { repositoryPath: f.repository, outputDir: f.outputDir };
      const initial = await security.scanDependencies({
        ...options,
        onInventory: (inventory) => {
          observed = inventory;
        },
      });
      expect(observed?.matches).toHaveLength(2);
      expect(initial.assessmentContext?.sourceDigest).toBeString();
      expect(initial.packageContexts?.[0]?.installedPath).toBeNull();
      const result = await security.scanDependencies(options);
      expect(result.status).toBe("completed");
      expect(f.calls.scanner).toBe(1);
    } finally {
      await chmod(manifest, 0o600);
    }
  },
);

test.each([false, true])(
  "missing usage on a completed reused turn remains unverified (budgeted: %p)",
  async (budgeted) => {
    const f = await fixture({
      turns: ["completed", "missing_usage", "completed"],
    });
    await using security = f.client;
    await writeSession(f.codexHome, "sca-thread", {
      input_tokens: 1000,
      output_tokens: 1000,
    });
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    if (budgeted) {
      const failure = await security
        .scanDependencies({ ...options, maxCostUsd: 1 })
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ScanInterruptedError);
      expect((failure as ScanInterruptedError).cause).toMatchObject({
        message: "Could not verify the dependency assessment cost limit.",
      });
    } else {
      const result = await security.scanDependencies(options);
      expect(result.status).toBe("completed");
      expect(
        result.assessments.every((item) => item.status === "completed"),
      ).toBe(true);
      expect(result.assessments[2]!.threadId).not.toBe(
        result.assessments[1]!.threadId,
      );
    }
    const checkpointPath = join(f.outputDir, "sca-result.json");
    const serialized = await readFile(checkpointPath, "utf8");
    const checkpoint: ScaResult = JSON.parse(serialized);
    expect(checkpoint.model.costPending).toBe(true);
    expect(f.turns).toHaveLength(budgeted ? 2 : 3);
    if (budgeted) {
      expect(checkpoint.model.cost?.inputTokens).toBe(1000);
      expect(checkpoint.assessments.map((item) => item.status)).toEqual([
        "completed",
        "completed",
        "cancelled",
      ]);
      await expect(
        security.scanDependencies({ ...options, maxCostUsd: 10 }),
      ).rejects.toThrow("earlier assessment usage is unavailable");
      expect(await readFile(checkpointPath, "utf8")).toBe(serialized);
      expect(f.turns).toHaveLength(2);
    }
  },
);

test("retains native rollout fallback for a first assessment without SDK usage", async () => {
  const f = await fixture({ turns: ["missing_usage"] });
  await using security = f.client;
  await writeSession(f.codexHome, "sca-thread", {
    input_tokens: 1000,
    output_tokens: 1000,
  });
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
    maxCostUsd: 1,
  });
  expect(result.status).toBe("completed");
  expect(result.model.costPending).toBe(false);
  expect(result.model.cost?.inputTokens).toBe(1000);
});

test.each([false, true])(
  "unrelated provider definitions do not invalidate continuation (initially present: %p)",
  async (initiallyPresent) => {
    const unrelated = {
      "synthetic.unused": {
        name: "Unused synthetic provider",
        base_url: "https://unused.example.invalid/v1",
        wire_api: "responses",
        requires_openai_auth: true,
      },
    };
    const f = await fixture({
      turns: ["completed", "malformed"],
      codexOverrides: initiallyPresent ? { model_providers: unrelated } : {},
    });
    await using security = f.client;
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    const initial = await security.scanDependencies(options);
    if (initiallyPresent)
      delete security.config.codexOverrides!["model_providers"];
    else security.config.codexOverrides!["model_providers"] = unrelated;
    const result = await security.scanDependencies(options);
    expect(result.status).toBe("completed");
    expect(result.assessmentContext?.configurationDigest).toBe(
      initial.assessmentContext?.configurationDigest,
    );
    expect(result.assessments[0]).toEqual(initial.assessments[0]);
    expect(f.calls.scanner).toBe(1);
    expect(f.turns).toHaveLength(3);
  },
);

test("malformed optional package metadata preserves inventory and assessment", async () => {
  const f = await fixture();
  await using security = f.client;
  await writeFile(
    join(f.repository, "package.json"),
    JSON.stringify({
      name: "synthetic-project",
      dependencies: { ["synthetic\u0000name"]: "1.0.0" },
    }),
  );
  let observed: ScaResult | undefined;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
    onInventory: (inventory) => {
      observed = inventory;
    },
  });
  expect(observed?.matches).toHaveLength(1);
  expect(result.status).toBe("completed");
  expect(result.assessments[0]!.status).toBe("completed");
  expect(result.diagnostics.join("\n")).toContain(
    "Installed dependency context unavailable:",
  );
  expect(result.assessmentContext?.sourceDigest).toBeString();
});

test.each(
  (["npm", "pnpm"] as const).flatMap((format) =>
    (
      [
        "single",
        "unresolved workspace",
        "missing workspace manifest",
        "installed workspace",
        "installed root",
      ] as const
    ).map((state) => ({ format, state })),
  ),
)(
  "dependency assessment preserves project attribution (%j)",
  async ({ format, state }) => {
    const path = format === "npm" ? "package-lock.json" : "pnpm-lock.yaml";
    const f = await fixture({
      dependencyInput: { path, format, ecosystem: "npm" },
    });
    await using security = f.client;
    const dependencies = { "synthetic-package": "1.0.0" };
    const single = state === "single";
    const root = state === "installed root" || single;
    await writeFile(
      join(f.repository, "package.json"),
      JSON.stringify({
        name: "synthetic-root",
        version: "1.0.0",
        private: false,
        dependencies: root ? dependencies : {},
      }),
    );
    if (!single && state !== "missing workspace manifest") {
      await mkdir(join(f.repository, "packages/app"), { recursive: true });
      await writeFile(
        join(f.repository, "packages/app/package.json"),
        JSON.stringify({
          name: "synthetic-app",
          version: "1.0.0",
          private: true,
          dependencies: root ? {} : dependencies,
        }),
      );
    }
    await writeFile(
      join(f.repository, path),
      format === "npm"
        ? JSON.stringify({
            lockfileVersion: 3,
            packages: { "": {}, ...(single ? {} : { "packages/app": {} }) },
          })
        : `lockfileVersion: '9.0'\nimporters:\n  .: {}\n${single ? "" : "  packages/app: {}\n"}`,
    );
    const installed =
      state === "installed root" || state === "installed workspace";
    if (installed) {
      const directory = join(f.repository, "node_modules/synthetic-package");
      await mkdir(directory, { recursive: true });
      await writeFile(
        join(directory, "package.json"),
        JSON.stringify({ name: "synthetic-package", version: "1.0.0" }),
      );
      await writeFile(
        join(directory, "index.js"),
        'throw new Error("Package code must not execute");',
      );
    }
    let inventory: ScaResult | undefined;
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
      onInventory: (value) => {
        inventory = value;
      },
    });
    expect(result.status).toBe("completed");
    expect(result.assessments[0]!.status).toBe("completed");
    expect(result.matches).toHaveLength(1);
    const evidence = JSON.parse(
      await readFile(join(f.outputDir, "sca-assessment-input.json"), "utf8"),
    );
    const context = result.packageContexts![0]!;
    expect(evidence.packageContext).toEqual(context);
    expect(f.captured.evidence!.packageContexts).toEqual(
      result.packageContexts,
    );
    expect(inventory!.packageContexts).toEqual(result.packageContexts);
    expect(f.captured.prompt).toContain("sca-assessment-input.json");
    expect(context).toMatchObject({
      manifestPath:
        single || state === "installed root"
          ? "package.json"
          : installed
            ? join("packages", "app", "package.json")
            : null,
      projectName:
        single || state === "installed root"
          ? "synthetic-root"
          : installed
            ? "synthetic-app"
            : null,
      private:
        single || state === "installed root" ? false : installed ? true : null,
      installedPath: installed
        ? join("node_modules", "synthetic-package")
        : null,
    });
    expect(context.dependencyChain.map((item) => item.name)).toEqual(
      installed
        ? [root ? "synthetic-root" : "synthetic-app", "synthetic-package"]
        : [],
    );
    expect(evidence.component.sourcePath).toBe(path);
    const report = await readFile(join(f.outputDir, "report.md"), "utf8");
    expect(report).toContain(
      installed
        ? "Observed local introduction chain:"
        : "Introduction chain and direct/transitive classification: unknown from scanner evidence.",
    );
  },
);

test.each(["native", "win32"] as const)(
  "dependency assessment resolves pnpm filename variants (%s)",
  async (platform) => {
    const name = `dependency assessment resolves pnpm filename variants (${platform})`;
    if (runTestInSubprocess(import.meta.path, name)) return;
    const inputs = await import("../src/sca-inputs.js");
    const basename = inputs.scaInputBasename;
    const comparison =
      platform === "win32"
        ? spyOn(inputs, "scaInputBasename").mockImplementation((path) => {
            const descriptor = Object.getOwnPropertyDescriptor(
              process,
              "platform",
            )!;
            Object.defineProperty(process, "platform", {
              ...descriptor,
              value: "win32",
            });
            try {
              return basename(path);
            } finally {
              Object.defineProperty(process, "platform", descriptor);
            }
          })
        : undefined;
    try {
      for (const path of ["pnpm-lock.yaml", "PNPM-LOCK.YAML"]) {
        const f = await fixture({
          dependencyInput: { path, format: "pnpm", ecosystem: "npm" },
        });
        await using security = f.client;
        for (const [directory, manifest] of [
          [".", { name: "synthetic-root", version: "1.0.0" }],
          [
            "packages/app",
            {
              name: "synthetic-app",
              version: "1.0.0",
              private: true,
              dependencies: { "synthetic-package": "1.0.0" },
            },
          ],
          [
            "node_modules/synthetic-package",
            { name: "synthetic-package", version: "1.0.0" },
          ],
        ] as const) {
          await mkdir(join(f.repository, directory), { recursive: true });
          await writeFile(
            join(f.repository, directory, "package.json"),
            JSON.stringify(manifest),
          );
        }
        await writeFile(
          join(f.repository, path),
          "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/app: {}\n",
        );
        const result = await security.scanDependencies({
          repositoryPath: f.repository,
          outputDir: f.outputDir,
        });
        expect(result.status).toBe("completed");
        expect(result.assessments[0]!.status).toBe("completed");
        const evidence = JSON.parse(
          await readFile(
            join(f.outputDir, "sca-assessment-input.json"),
            "utf8",
          ),
        );
        const context = result.packageContexts![0]!;
        expect(evidence.packageContext).toEqual(context);
        expect(evidence.component.sourcePath).toBe(path);
        expect(evidence.coverage.inputs[0]).toMatchObject({
          path,
          format: "pnpm",
        });
        expect(result.scanner.invocations![0]!.argv.at(-1)).toBe(path);
        const recognized =
          path === "pnpm-lock.yaml" ||
          platform === "win32" ||
          process.platform === "win32";
        expect(context.installedPath).toBe(
          recognized ? join("node_modules", "synthetic-package") : null,
        );
        expect(context.dependencyChain.map((item) => item.name)).toEqual(
          recognized ? ["synthetic-app", "synthetic-package"] : [],
        );
        if (recognized)
          expect(context.manifestPath).toBe(
            join("packages", "app", "package.json"),
          );
      }
    } finally {
      comparison?.mockRestore();
    }
  },
);

test.each(
  ["developer_instructions", "instructions", "compact_prompt"].flatMap((key) =>
    [false, true].map((profile) => [key, profile] as const),
  ),
)("changed %s reject continuation (profile: %p)", async (key, profile) => {
  const overrides = (instructions: string): JsonObject =>
    profile
      ? {
          profile: "synthetic-assessment",
          profiles: {
            "synthetic-assessment": { [key]: instructions },
          },
        }
      : { [key]: instructions };
  const f = await fixture({
    turns: ["completed", "malformed"],
    codexOverrides: overrides("Synthetic original assessment instructions."),
  });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const initial = await security.scanDependencies(options);
  expect(initial.assessments[0]!.status).toBe("completed");
  expect(f.captured.codex?.config?.[key]).toBe(
    "Synthetic original assessment instructions.",
  );
  const checkpoint = await readFile(
    join(f.outputDir, "sca-result.json"),
    "utf8",
  );
  Object.assign(
    security.config.codexOverrides!,
    overrides("Synthetic changed assessment instructions."),
  );
  await expect(security.scanDependencies(options)).rejects.toThrow(
    "instructions, or skill changed",
  );
  expect(await readFile(join(f.outputDir, "sca-result.json"), "utf8")).toBe(
    checkpoint,
  );
  expect(f.turns).toHaveLength(2);
  expect(f.calls.model).toBe(1);
  expect(f.calls.scanner).toBe(1);
});

test.each([
  ["model_verbosity", "low", "high"],
  ["model_context_window", 16000, 32000],
  ["model_auto_compact_token_limit", 8000, 12000],
  ["model_reasoning_summary", "detailed", "none"],
] as const)(
  "continuation binds effective %s",
  async (key, original, changed) => {
    const f = await fixture({
      turns: ["completed", "malformed"],
      codexOverrides: {
        profile: "synthetic-assessment",
        profiles: { "synthetic-assessment": { [key]: original } },
      },
    });
    await using security = f.client;
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    const initial = await security.scanDependencies(options);
    expect(initial.assessments[0]).toMatchObject({
      status: "completed",
      error: null,
    });
    expect(f.captured.codex?.config?.[key]).toBe(original);
    const checkpointPath = join(f.outputDir, "sca-result.json");
    const checkpoint = await readFile(checkpointPath, "utf8");
    const profile = (security.config.codexOverrides!["profiles"] as JsonObject)[
      "synthetic-assessment"
    ] as JsonObject;
    profile[key] = changed;
    await expect(security.scanDependencies(options)).rejects.toThrow(
      "Use the original settings or start a new run",
    );
    expect(await readFile(checkpointPath, "utf8")).toBe(checkpoint);
    expect(f.turns).toHaveLength(2);
    profile[key] = original;
    const resumed = await security.scanDependencies(options);
    expect(resumed.status).toBe("completed");
    expect(resumed.assessments[0]).toEqual(initial.assessments[0]);
    expect(f.calls.scanner).toBe(1);
  },
);

test.each([
  ["model_instructions_file", "path", "absolute"],
  ["model_instructions_file", "contents", "relative"],
  ["model_instructions_file", "missing", "home"],
  ["experimental_compact_prompt_file", "path", "relative"],
  ["experimental_compact_prompt_file", "contents", "home"],
  ["experimental_compact_prompt_file", "missing", "absolute"],
] as const)(
  "%s binds %s changes with %s paths before continuing",
  async (key, change, pathKind) => {
    const f = await fixture({
      turns: ["completed", "malformed"],
      homeVariable: process.platform === "win32" ? "USERPROFILE" : "HOME",
      codexOverrides: {
        profile: "synthetic-assessment",
        profiles: { "synthetic-assessment": {} },
      },
    });
    await using security = f.client;
    await mkdir(f.selectedUserHome, { recursive: true });
    const original = join(f.selectedUserHome, "original instructions.md");
    const changed = join(f.selectedUserHome, "changed instructions.md");
    const contents = "Synthetic original assessment instructions.";
    await writeFile(original, contents);
    await writeFile(changed, contents);
    const configuredPath = (path: string) =>
      pathKind === "home"
        ? `~/${basename(path)}`
        : pathKind === "relative"
          ? relative(f.outputDir, path)
          : path;
    const profile = (security.config.codexOverrides!["profiles"] as JsonObject)[
      "synthetic-assessment"
    ] as JsonObject;
    profile[key] = configuredPath(original);
    const options = { repositoryPath: f.repository, outputDir: f.outputDir };
    const initial = await security.scanDependencies(options);
    expect(initial.assessments[0]).toMatchObject({
      status: "completed",
      error: null,
    });
    expect(initial.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
    ]);
    expect(f.captured.codex?.config?.[key]).toBe(original);
    const checkpointPath = join(f.outputDir, "sca-result.json");
    const checkpoint = await readFile(checkpointPath, "utf8");
    if (change === "path") profile[key] = configuredPath(changed);
    else if (change === "contents")
      await writeFile(original, "Synthetic changed assessment instructions.");
    else await rm(original);
    await expect(security.scanDependencies(options)).rejects.toThrow(
      change === "missing" ? "ENOENT" : "instructions, or skill changed",
    );
    expect(await readFile(checkpointPath, "utf8")).toBe(checkpoint);
    expect(f.turns).toHaveLength(2);
    expect(f.calls.model).toBe(1);
    expect(f.calls.scanner).toBe(1);

    profile[key] = configuredPath(original);
    await writeFile(original, ` ${contents} `);
    const resumed = await security.scanDependencies(options);
    expect(resumed.status).toBe("completed");
    expect(resumed.assessmentContext?.configurationDigest).toBe(
      initial.assessmentContext?.configurationDigest,
    );
    expect(resumed.assessments[0]).toEqual(initial.assessments[0]);
    expect(f.turns).toHaveLength(3);
    expect(f.calls.scanner).toBe(1);
  },
);

test("overridden instruction defaults do not invalidate continuation", async () => {
  const instructionsRoot = await temporaryDirectory("synthetic-instructions-");
  const modelFile = join(instructionsRoot, "model.md");
  const compactFile = join(instructionsRoot, "compact.md");
  await writeFile(modelFile, "Synthetic selected model instructions.");
  await writeFile(compactFile, "Synthetic unused compaction instructions.");
  const f = await fixture({
    turns: ["completed", "malformed"],
    codexOverrides: {
      model_instructions_file: modelFile,
      instructions: "Synthetic unused model instructions.",
      compact_prompt: "Synthetic selected compaction instructions.",
      experimental_compact_prompt_file: compactFile,
    },
  });
  await using security = f.client;
  const options = { repositoryPath: f.repository, outputDir: f.outputDir };
  const initial = await security.scanDependencies(options);
  expect(initial.assessments[0]!.status).toBe("completed");
  security.config.codexOverrides!["instructions"] =
    "Synthetic changed unused model instructions.";
  await writeFile(
    compactFile,
    "Synthetic changed unused compaction instructions.",
  );
  const resumed = await security.scanDependencies(options);
  expect(resumed.status).toBe("completed");
  expect(resumed.assessmentContext?.configurationDigest).toBe(
    initial.assessmentContext?.configurationDigest,
  );
  expect(resumed.assessments[0]).toEqual(initial.assessments[0]);
  expect(f.turns).toHaveLength(3);
  expect(f.calls.scanner).toBe(1);
});

test.each([
  { label: "ChatGPT choice", choice: "chatgpt", prompts: 1 },
  { label: "API-key choice", choice: "api-key", prompts: 1 },
  {
    label: "explicit ChatGPT",
    flags: ["--auth", "chatgpt"],
    choice: "chatgpt",
    prompts: 0,
  },
  {
    label: "explicit API key",
    flags: ["--auth", "api-key"],
    choice: "api-key",
    prompts: 0,
  },
  { label: "JSON", flags: ["--json"], choice: "api-key", prompts: 0 },
  {
    label: "JSONL",
    flags: ["--format", "jsonl"],
    choice: "api-key",
    prompts: 0,
  },
  { label: "non-TTY", terminal: false, choice: "api-key", prompts: 0 },
  {
    label: "noninteractive input",
    input: false,
    choice: "api-key",
    prompts: 0,
  },
  { label: "no stored sign-in", stored: false, choice: "api-key", prompts: 0 },
  { label: "no API key", key: false, choice: "chatgpt", prompts: 0 },
  { label: "external provider", external: true, choice: "api-key", prompts: 0 },
] satisfies {
  label: string;
  choice: "chatgpt" | "api-key";
  prompts: number;
  flags?: string[];
  terminal?: boolean;
  input?: boolean;
  stored?: boolean;
  key?: boolean;
  external?: boolean;
}[])(
  "dependency CLI chooses authentication lazily: $label",
  async (scenario) => {
    let choose: DependencyAuthChooser | undefined;
    const external = "external" in scenario && scenario.external;
    const f = await fixture({
      chooseDependencyAuthentication: (auth, signal) =>
        choose?.(auth, signal) ?? Promise.resolve(auth),
      ...(external
        ? {
            codexOverrides: {
              model_provider: "fireworks",
              model_providers: { fireworks: { ...FIREWORKS_CODEX_PROVIDER } },
            },
          }
        : {}),
    });
    if ("key" in scenario && scenario.key === false)
      Reflect.deleteProperty(f.environment, "OPENAI_API_KEY");
    if (external)
      Object.assign(f.environment, {
        FIREWORKS_API_KEY: "synthetic-fireworks-key",
      });
    const originalEnvironment = { ...f.environment };
    const deps = cliDependencies({ environment: f.environment });
    deps.createDependencySecurity = (_config, chooser) => {
      choose = chooser;
      return f.client;
    };
    let probes = 0;
    let prompts = 0;
    deps.hasStoredChatGPTSignIn = async () => {
      probes++;
      const saved: ScaResult = JSON.parse(
        await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
      );
      expect(saved.matches).toHaveLength(1);
      expect(saved.assessments[0]!.status).toBe("not_started");
      expect(f.calls).toEqual({ scanner: 1, runtime: 0, model: 0 });
      return scenario.stored !== false;
    };
    deps.scanAuthenticationPrompt = selectionPrompt(
      async (_message, choices) => {
        prompts++;
        return choices.find((item) => item.value === scenario.choice)!.value;
      },
      () => scenario.input !== false,
    );
    const { stderr, runCli } = createCliTest(main, {
      stderr: !("terminal" in scenario) || scenario.terminal,
    });
    const flags = external
      ? ["--provider", "fireworks", "--model", "synthetic-model"]
      : "flags" in scenario
        ? (scenario.flags ?? [])
        : [];
    expect(
      await runCli(
        [
          "scan",
          "dependencies",
          f.repository,
          "--output-dir",
          f.outputDir,
          ...flags,
        ],
        deps,
      ),
      stderr.text(),
    ).toBe(0);
    expect(prompts).toBe(scenario.prompts);
    expect(probes).toBe(
      scenario.prompts === 1 || scenario.label === "no stored sign-in" ? 1 : 0,
    );
    expect(f.captured.codex?.apiKey).toBe(
      scenario.choice === "api-key" && !external
        ? "synthetic-sca-key"
        : undefined,
    );
    expect(f.captured.codex?.env?.["OPENAI_API_KEY"]).toBeUndefined();
    if (external)
      expect(f.captured.codex?.env?.["FIREWORKS_API_KEY"]).toBe(
        "synthetic-fireworks-key",
      );
    expect(f.environment).toEqual(originalEnvironment);
    expect(
      JSON.parse(await readFile(join(f.outputDir, "sca-result.json"), "utf8"))
        .status,
    ).toBe("completed");
  },
);

test.each([
  { label: "fully assessed", missing: false },
  { label: "missing assessment", missing: true },
])(
  "dependency CLI continuation authentication: $label checkpoint",
  async ({ missing }) => {
    let choose: DependencyAuthChooser | undefined;
    const authentication = { choices: 0, lookups: 0, prompts: 0 };
    const f = await fixture({
      turns: ["completed", "completed"],
      chooseDependencyAuthentication: (auth, signal) => {
        if (choose === undefined) return Promise.resolve(auth);
        authentication.choices++;
        return choose(auth, signal);
      },
    });
    await using security = f.client;
    const perTurn = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      cache_write_input_tokens: 0,
      output_tokens: 1000,
    })!.estimatedUsd;
    await expect(
      security.scanDependencies({
        repositoryPath: f.repository,
        outputDir: f.outputDir,
        maxCostUsd: perTurn * 1.5,
      }),
    ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
    const path = join(f.outputDir, "sca-result.json");
    const checkpoint: ScaResult = JSON.parse(await readFile(path, "utf8"));
    expect(checkpoint.status).toBe("partial");
    expect(checkpoint.coverage.status).toBe("complete");
    expect(checkpoint.model.costPending).toBe(false);
    expect(checkpoint.matches).toHaveLength(2);
    expect(checkpoint.assessments).toHaveLength(2);
    expect(
      checkpoint.assessments.every((item) => item.status === "completed"),
    ).toBe(true);
    const missingMatch = missing
      ? checkpoint.assessments.pop()!.matchId
      : undefined;
    if (missing) await writeFile(path, JSON.stringify(checkpoint));
    const previousCalls = { ...f.calls };
    expect(previousCalls).toEqual({ runtime: 1, model: 1, scanner: 1 });
    expect(f.turns).toHaveLength(2);

    const deps = cliDependencies({ environment: f.environment });
    deps.createDependencySecurity = (_config, chooser) => {
      choose = chooser;
      return security;
    };
    deps.hasStoredChatGPTSignIn = async () => {
      authentication.lookups++;
      expect(f.calls).toEqual(previousCalls);
      expect(f.turns).toHaveLength(2);
      return true;
    };
    deps.scanAuthenticationPrompt = selectionPrompt(
      async (_message, choices) => {
        authentication.prompts++;
        expect(f.calls).toEqual(previousCalls);
        return choices.find((item) => item.value === "api-key")!.value;
      },
    );
    const { stderr, runCli } = createCliTest(main, { stderr: true });
    expect(
      await runCli(
        ["scan", "dependencies", f.repository, "--output-dir", f.outputDir],
        deps,
      ),
      stderr.text(),
    ).toBe(0);
    const result: ScaResult = JSON.parse(await readFile(path, "utf8"));
    expect(result.status).toBe("completed");
    expect(result.assessments).toHaveLength(2);
    expect(result.assessments[0]).toEqual(checkpoint.assessments[0]);
    expect(
      result.assessments.every((item) => item.status === "completed"),
    ).toBe(true);
    expect(authentication).toEqual(
      missing
        ? { choices: 1, lookups: 1, prompts: 1 }
        : { choices: 0, lookups: 0, prompts: 0 },
    );
    expect(f.calls).toEqual(
      missing ? { runtime: 1, model: 2, scanner: 1 } : previousCalls,
    );
    expect(f.turns).toHaveLength(missing ? 3 : 2);
    if (missing) {
      expect(f.turns.at(-1)!.prompt).toContain(
        `Assess only match ${JSON.stringify(missingMatch)}`,
      );
      expect(f.captured.codex?.apiKey).toBe("synthetic-sca-key");
    } else {
      expect(result.assessments).toEqual(checkpoint.assessments);
      expect(result.model).toEqual(checkpoint.model);
      expect(result.assessmentContext).toEqual(checkpoint.assessmentContext);
    }
  },
);

test("dependency CLI zero-match scans do not discover or choose credentials", async () => {
  let choose: DependencyAuthChooser | undefined;
  const f = await fixture({
    matched: false,
    chooseDependencyAuthentication: (auth, signal) =>
      choose?.(auth, signal) ?? Promise.resolve(auth),
  });
  const deps = cliDependencies({ environment: f.environment });
  deps.createDependencySecurity = (_config, chooser) => {
    choose = chooser;
    return f.client;
  };
  deps.hasStoredChatGPTSignIn = async () => {
    throw new Error("Unexpected credential discovery");
  };
  deps.scanAuthenticationPrompt = selectionPrompt(async () => {
    throw new Error("Unexpected authentication prompt");
  });
  const { stderr, runCli } = createCliTest(main, { stderr: true });
  expect(
    await runCli(
      ["scan", "dependencies", f.repository, "--output-dir", f.outputDir],
      deps,
    ),
    stderr.text(),
  ).toBe(0);
  expect(f.calls).toEqual({ scanner: 1, runtime: 0, model: 0 });
});

test.each([
  "lookup error",
  "selection error",
  "lookup abort",
  "selection abort",
  "client close",
] as const)(
  "dependency CLI preserves scanner evidence after authentication %s",
  async (stage) => {
    let choose: DependencyAuthChooser | undefined;
    const f = await fixture({
      chooseDependencyAuthentication: (auth, signal) =>
        choose?.(auth, signal) ?? Promise.resolve(auth),
    });
    const signals = new FakeSignals();
    const deps = cliDependencies({ environment: f.environment, signals });
    deps.createDependencySecurity = (_config, chooser) => {
      choose = chooser;
      return f.client;
    };
    let observedSignal: AbortSignal | undefined;
    const interrupt = async (
      signal: AbortSignal | undefined,
    ): Promise<never> => {
      observedSignal = signal;
      const saved: ScaResult = JSON.parse(
        await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
      );
      expect(saved.matches).toHaveLength(1);
      expect(saved.assessments[0]!.status).toBe("not_started");
      if (stage.endsWith("error"))
        throw new Error(`Synthetic authentication ${stage}`);
      if (stage === "client close") void f.client.close();
      else signals.emit("SIGINT");
      return new Promise<never>(() => {});
    };
    deps.hasStoredChatGPTSignIn = async (signal) =>
      stage.startsWith("lookup") || stage === "client close"
        ? interrupt(signal)
        : true;
    deps.scanAuthenticationPrompt = selectionPrompt(
      async (_message, _choices, _presentation, signal) => interrupt(signal),
    );
    const { stderr, runCli } = createCliTest(main, { stderr: true });
    expect(
      await runCli(
        ["scan", "dependencies", f.repository, "--output-dir", f.outputDir],
        deps,
      ),
      stderr.text(),
    ).toBe(stage.endsWith("abort") ? 130 : 2);
    const saved: ScaResult = JSON.parse(
      await readFile(join(f.outputDir, "sca-result.json"), "utf8"),
    );
    expect(saved.matches).toHaveLength(1);
    expect(saved.components).toHaveLength(1);
    expect(saved.coverage.status).toBe("complete");
    expect(saved.assessments[0]!.status).toBe(
      stage.endsWith("error") ? "failed" : "cancelled",
    );
    expect(f.calls).toEqual({ scanner: 1, runtime: 0, model: 0 });
    if (stage.endsWith("error"))
      expect(saved.diagnostics.join("\n")).toContain(
        `Synthetic authentication ${stage}`,
      );
    else expect(observedSignal?.aborted).toBe(true);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  },
);
