import { randomUUID } from "node:crypto";
import * as childProcess from "node:child_process";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  appendFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { ThreadEvent, ThreadOptions } from "@openai/codex-sdk";
import { afterEach, expect, spyOn, test } from "bun:test";
import { build } from "esbuild";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import type { ScanSessionEvent } from "../src/cost.js";
import type { ScanCost } from "../src/cost-model.js";
import type { ScanActivity } from "../src/scan-activity.js";
import {
  prepareScanArtifactRestorer,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../src/runtime.js";
import { prepareSemanticScanDraft } from "../src/scan-semantics.js";
import {
  DEEP_SCAN_CHECKPOINT,
  ScanCostTrackingError,
} from "../src/deep-scan.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanProgress } from "../src/worker-progress.js";
import { readSavedScanLogs, type ScanLogSource } from "../src/scan-logs.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const roots: string[] = [];

type ClientArguments = ConstructorParameters<typeof CodexSecurity>;
type CapturedNativeScan = {
  client: { config: ClientArguments[0]; dependencies: ClientArguments[1] };
  options: ScanOptions;
};

// Capture only the constructor boundary; keep the adapter's runtime preparation
// and the SDK's ordinary scan execution real without process-wide module mocks.
async function nativeScanFactory() {
  const entry = new URL(
    "../../../plugins/codex-security/mcp-app/src/native-scan.ts",
    import.meta.url,
  );
  const bundle = await build({
    bundle: true,
    entryPoints: [fileURLToPath(entry)],
    define: { "import.meta.url": JSON.stringify(entry.href) },
    format: "cjs",
    platform: "node",
    write: false,
    plugins: [
      {
        name: "capture-native-client",
        setup(build) {
          build.onResolve({ filter: /sdk\/typescript\/src\/api\.js$/ }, () => ({
            path: "client",
            namespace: "fixture",
          }));
          build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
            resolveDir: fileURLToPath(new URL(".", entry)),
            contents: `export { selectedScanEnvironment } from ${JSON.stringify(fileURLToPath(new URL("../src/api.ts", import.meta.url)))};
            export class CodexSecurity { constructor(config, dependencies) { this.config = config; this.dependencies = dependencies; } }`,
          }));
        },
      },
    ],
  });
  const module = { exports: {} };
  new Function("require", "module", "exports", bundle.outputFiles[0]!.text)(
    createRequire(import.meta.url),
    module,
    module.exports,
  );
  return (
    module.exports as {
      prepareNativeScan(input: unknown): Promise<CapturedNativeScan>;
    }
  ).prepareNativeScan;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

test.each([
  { workers: 1, budget: false, provider: undefined },
  { workers: 2, budget: false, provider: undefined },
  { workers: 1, budget: true, provider: undefined },
  { workers: 1, budget: true, firstChildBudget: true },
  { workers: 1, budget: false, provider: { env_key: "OPENAI_API_KEY" } },
  {
    workers: 1,
    budget: false,
    provider: { auth: { type: "command", command: "synthetic-auth-provider" } },
  },
  { workers: 1, budget: false, native: "feedback" },
  { workers: 1, budget: false, native: "discovery" },
  { workers: 1, budget: false, native: "sealed" },
  { workers: 1, budget: false, trackingFailure: true },
  { workers: 1, budget: false, artifactFailure: "directory" },
  { workers: 1, budget: false, artifactFailure: "draft" },
  { workers: 1, budget: false, artifactFailure: "checkpoint" },
  { workers: 1, budget: false, cleanupFailure: true },
  {
    workers: 1,
    budget: false,
    artifactFailure: "publication",
    cleanupFailure: true,
  },
  { workers: 1, budget: false, logFailure: true },
  { workers: 1, budget: false, usage: "missing-merge" },
  { workers: 1, budget: false, native: "sealed", usage: "missing-merge" },
  { workers: 1, budget: false, usage: "unreported-cache" },
  { workers: 1, budget: false, usage: "missing-child" },
  { workers: 1, budget: false, usage: "missing-child", requiredCost: true },
  { workers: 1, budget: false, native: "discovery", usage: "missing-child" },
  { workers: 1, budget: false, native: "sealed", usage: "missing-child" },
] as {
  workers: number;
  budget: boolean;
  firstChildBudget?: boolean;
  trackingFailure?: boolean;
  artifactFailure?: "directory" | "draft" | "checkpoint" | "publication";
  cleanupFailure?: boolean;
  provider?: JsonObject;
  native?: "feedback" | "discovery" | "sealed";
  usage?: "missing-merge" | "missing-child" | "unreported-cache";
  requiredCost?: boolean;
  logFailure?: boolean;
}[])(
  "Deep composes sealed ordinary scans and preserves a budgeted parent: %j",
  async ({
    workers,
    budget,
    firstChildBudget,
    provider,
    native,
    trackingFailure,
    artifactFailure,
    cleanupFailure,
    usage,
    requiredCost,
    logFailure,
  }) => {
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "ordinary-composition-")),
    );
    roots.push(root);
    const repo = join(root, "repo");
    const codexHome = join(root, "codex");
    let scanDir = join(root, "scan");
    await Promise.all([mkdir(repo), mkdir(codexHome)]);
    await Promise.all(
      ["app.py", "routes.py", "models.py", "helpers.py"].map((name) =>
        writeFile(join(repo, name), "print('public synthetic fixture')\n"),
      ),
    );
    const childFindings: JsonObject[] = firstChildBudget
      ? JSON.parse(
          await readFile(
            join(pluginRoot, "examples/completed-scan/findings.json"),
            "utf8",
          ),
        ).findings.slice(0, 1)
      : [];
    for (const finding of childFindings) {
      for (const field of ["findingId", "occurrenceId", "fingerprints"])
        delete finding[field];
      finding["locations"] = [{ path: "app.py", startLine: 1, endLine: 1 }];
    }
    const version = JSON.parse(
      await readFile(join(pluginRoot, ".codex-plugin/plugin.json"), "utf8"),
    ).version;
    let runtimeVersion = version;
    const environment = {
      ...process.env,
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      CODEX_CLI_PATH: process.execPath,
      SYNTHETIC_SCAN_SETTING: "inherited",
      CODEX_SAFETY_IDENTIFIER: "ambient-identifier",
      ...(native ? { OPENAI_API_KEY: "synthetic-native-key" } : {}),
      ...(provider === undefined
        ? {}
        : {
            OPENAI_API_KEY: "synthetic-provider-key",
            CODEX_API_KEY: "synthetic-native-key",
          }),
    };
    const nativeSettings = {
      model: "gpt-6-astra",
      model_reasoning_effort: "ultra",
      forced_login_method: "chatgpt",
      cli_auth_credentials_store: "file",
      mcp_servers: {
        synthetic: {
          command: "synthetic-mcp",
          env: { FIXTURE_TOKEN: "saved-mcp-setting" },
        },
      },
      shell_environment_policy: {
        inherit: "core",
        set: { FIXTURE_SETTING: "saved-shell-setting" },
      },
    };
    let ambientConfig = stringifyToml(nativeSettings);
    const managedHome = join(
      environment.CODEX_SECURITY_STATE_DIR,
      "codex-home",
    );
    const managedAuth = JSON.stringify({ auth_mode: "chatgpt", account: "C" });
    const managedConfig = 'model = "managed-decoy"\n';
    const accountLog = join(root, "account-status.jsonl");
    const loginFixture = join(root, "login-fixture.mjs");
    const prepareNative =
      native === "discovery" ? await nativeScanFactory() : undefined;
    if (prepareNative) {
      environment.CODEX_CLI_PATH = Bun.which("node")!;
      await mkdir(managedHome, { recursive: true });
      await Promise.all([
        writeFile(
          loginFixture,
          `
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
const args = process.argv.slice(2);
if (args.at(-2) !== "login" || args.at(-1) !== "status") throw new Error("Unexpected fixture command");
if (!args.includes('cli_auth_credentials_store="file"')) throw new Error("Expected saved file credential store");
const home = process.env.CODEX_HOME;
const { account } = JSON.parse(readFileSync(join(home, "auth.json"), "utf8"));
appendFileSync(${JSON.stringify(accountLog)}, JSON.stringify({ home, account, args }) + "\\n");
console.log("Logged in using ChatGPT");
process.exit(0);
`,
        ),
        writeFile(join(codexHome, "config.toml"), ambientConfig),
        writeFile(
          join(codexHome, "auth.json"),
          JSON.stringify({ auth_mode: "chatgpt", account: "A" }),
        ),
        writeFile(join(managedHome, "auth.json"), managedAuth),
        writeFile(join(managedHome, "config.toml"), managedConfig),
      ]);
    }
    const commandOptions = { python, pluginRoot, environment };
    let registeredScan: ScanOptions["registeredScan"];
    let feedbackBefore: Buffer<ArrayBuffer> | undefined;
    if (native) {
      if (native === "feedback") {
        execFileSync(python, [
          "-c",
          `import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_test_support import create_saved_workspace, start_delivered_scan, write_completed_contract, run_workbench
state, repository, scans = map(Path, sys.argv[2:])
workspace = create_saved_workspace(state, repository)
scan = start_delivered_scan(state, '--workspace-id', workspace['id'], '--scan-root', str(scans))['results']
write_completed_contract(Path(scan['scanDir']), scan['scanId'], repository, relative_path='app.py')
completed = run_workbench(state, 'complete-scan', '--scan-id', scan['scanId'])['scan']
run_workbench(state, 'set-finding-triage', '--occurrence-id', completed['findings'][0]['occurrenceId'], '--status', 'closed', '--close-reason', 'false_positive', '--note', 'The synthetic route verifies the session.')`,
          join(pluginRoot, "tests"),
          environment.CODEX_SECURITY_STATE_DIR,
          repo,
          join(root, "prior-scans"),
        ]);
      }
      const started = await runWorkbench(commandOptions, [
        "begin-deep-scan",
        "--thread-id",
        "native-owner",
        "--target-path",
        repo,
        "--scope",
        ".",
        "--scan-root",
        join(root, "scans"),
      ]);
      const scan = started["scan"] as JsonObject;
      scanDir = scan["scanDir"] as string;
      registeredScan = {
        scanId: scan["scanId"] as string,
        scanDir,
        threadId: "native-owner",
        handoffClaimToken: scan["handoffClaimToken"] as string,
      };
      if (native === "feedback")
        feedbackBefore = await readFile(
          join(scanDir, "artifacts/01_context/false_positive_feedback.json"),
        );
    }
    let controller = new AbortController();
    let interrupted = false;
    let savedExecutionThread: string | undefined;
    let sealedArtifacts: Map<string, Buffer<ArrayBuffer>> | undefined;
    const registrations = new Map<string, JsonObject>();
    const costs: ScanCost[] = [];
    const followUpThreads: string[] = [];
    const previousFollowUp = native === "sealed" ? randomUUID() : undefined;
    const finishedFollowUps: string[] = [];
    const warnings: string[] = [];
    let childTurns = 0;
    let mergeAttempts = 0;
    let threadCount = 0;
    const progressRuns: ScanProgress[][] = [];
    let progress: ScanProgress[];
    const workerRuns: Array<{
      threads: Set<string>;
      activities: ScanActivity[];
      sessions: ScanSessionEvent[];
    }> = [];
    let workerRun: (typeof workerRuns)[number];
    const workbenches = new Map<string, WorkbenchCommandOptions>();
    const commands: Array<{ command: string; id: string | undefined }> = [];
    const turns: Array<{
      id: string;
      mode: string;
      cwd: string;
      prompt: string;
      config: unknown;
      overrides?: string[];
      executable?: string;
      environment: Record<string, string>;
      account?: string;
      resumed: boolean;
    }> = [];
    let nativeOptions: ScanOptions | undefined;
    let nativeRecipe: JsonObject | undefined;
    const makeClient = async () => {
      let prepared: CapturedNativeScan | undefined;
      if (prepareNative) {
        const nativeEnvironment: NodeJS.ProcessEnv = {
          ...environment,
          OPENAI_API_KEY: undefined,
          CODEX_API_KEY: undefined,
          CODEX_SAFETY_IDENTIFIER: undefined,
          CODEX_SECURITY_CONFIG_PATH: undefined,
          CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: undefined,
        };
        const before = Object.fromEntries(
          Object.keys(nativeEnvironment).map((key) => [key, process.env[key]]),
        );
        try {
          for (const [key, value] of Object.entries(nativeEnvironment)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
          }
          prepared = await prepareNative({
            scan: {
              ...registeredScan,
              targetPath: repo,
              userContext: "Inspect the synthetic source.",
            },
            recipe: nativeRecipe ?? {
              postScanPrompt: "Post-scan instructions once.",
            },
            savedDeepScanSettings: {
              workers,
              subagents: 3,
              stopAfterNoNew: 2,
              maxDiscoveryRuns: 4,
              maxTimeHours: 1,
            },
            threadId: registeredScan!.threadId,
            pluginRoot: PLUGIN_ROOT,
            pythonPath: python,
            parentSandbox: { filesystemDenies: [join(root, "private")] },
          });
          nativeOptions = prepared.options;
        } finally {
          for (const [key, value] of Object.entries(before)) {
            if (value === undefined) delete process.env[key];
            else process.env[key] = value;
          }
        }
      }
      return new CodexSecurity(
        prepared?.client.config ?? {
          pluginPath: pluginRoot,
          codexOverrides: {
            model: "gpt-6-astra",
            model_reasoning_effort: "ultra",
            ...(provider === undefined
              ? {}
              : {
                  model_provider: "custom",
                  cli_auth_credentials_store: "file",
                  model_providers: { custom: provider },
                }),
          },
        },
        {
          environment,
          inheritedPermissions: {
            filesystem: { [join(root, "private")]: "deny" },
            network: { enabled: false },
          },
          prepareRuntime: async () => ({
            codexHome,
            environment,
            credentialsAvailable: true,
            persistentCredentialHome: true,
            plugin: {
              pluginRoot,
              installedRoot: pluginRoot,
              marketplaceRoot: pluginRoot,
              marketplaceName: "codex-security-sdk",
              name: "codex-security",
              version: runtimeVersion,
            },
          }),
          ...prepared?.client.dependencies,
          resolvePluginPython: async () => python,
          prepareScanArtifactRestorer: async (...args) => {
            const writer = await prepareScanArtifactRestorer(...args);
            return {
              ...writer,
              async prepareDirectory(path) {
                if (artifactFailure === "directory")
                  throw new Error("Synthetic directory write failure.");
                await writer.prepareDirectory(path);
              },
              async restore(path, contents) {
                if (artifactFailure === "draft" && path.startsWith("drafts/"))
                  throw new Error("Synthetic draft write failure.");
                if (logFailure && path.endsWith("execution-threads.json"))
                  throw new Error("Synthetic session index write failure.");
                await writer.restore(path, contents);
              },
              async remove(path) {
                if (cleanupFailure && path.endsWith(".checkpoint.json"))
                  throw new Error("Synthetic staging cleanup failure.");
                await writer.remove(path);
              },
            };
          },
          runWorkbench: async (options, args, input) => {
            if (
              artifactFailure === "checkpoint" &&
              args[0] === "save-scan-artifact"
            )
              throw new Error("Synthetic checkpoint write failure.");
            if (
              artifactFailure === "publication" &&
              args[0] === "write-scan-draft"
            )
              throw new Error("Synthetic publication write failure.");
            const result = await runWorkbench(options, args, input);
            const id = args.includes("--scan-id")
              ? args[args.indexOf("--scan-id") + 1]
              : undefined;
            commands.push({ command: args[0]!, id });
            if (args[0] === "register-cli-scan") {
              const scanId = result["scanId"] as string;
              registrations.set(scanId, {
                ...result,
                mode: JSON.parse(input!).recipe.mode,
                recipe: JSON.parse(input!).recipe,
              });
              workbenches.set(scanId, options);
            }
            if (args[0] === "get-cli-scan-resume")
              workbenches.set(result["scanId"] as string, options);
            if (
              native === "sealed" &&
              !interrupted &&
              args[0] === "prepare-scan-completion" &&
              id === registeredScan!.scanId
            ) {
              await writeFile(
                join(scanDir, "artifacts/deep-scan/execution-threads.json"),
                JSON.stringify([previousFollowUp]),
              );
              const manifest = JSON.parse(
                await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
              );
              sealedArtifacts = new Map(
                await Promise.all(
                  [
                    "scan-manifest.json",
                    "report.md",
                    ...manifest.scan.artifacts.map(
                      (artifact: { path: string }) => artifact.path,
                    ),
                  ].map(
                    async (path: string) =>
                      [path, await readFile(join(scanDir, path))] as const,
                  ),
                ),
              );
              interrupted = true;
              controller.abort(
                new ScanTransportClosedError("mcp_transport_closed"),
              );
            }
            return result;
          },
          createCodex: (options) => {
            if (provider !== undefined) {
              expect(options.apiKey).toBeUndefined();
              expect(options.env?.["OPENAI_API_KEY"]).toBe(
                "synthetic-provider-key",
              );
              expect(options.env?.["CODEX_API_KEY"]).toBe(
                "synthetic-native-key",
              );
            }
            const env = options.env!;
            const id = env["CODEX_SECURITY_SCAN_ID"]!;
            const makeThread = (
              threadOptions: ThreadOptions,
              savedThreadId: string | null = null,
            ) => {
              threadCount += 1;
              const thread = {
                id: savedThreadId,
                async runStreamed(
                  prompt: string,
                  turnOptions?: { signal?: AbortSignal },
                ) {
                  const record = registrations.get(id)!;
                  const mode = record["mode"] as string;
                  if (
                    mode === "deep" &&
                    prompt !== "Post-scan instructions once."
                  ) {
                    mergeAttempts += 1;
                    const mergePath = join(
                      record["scanDir"] as string,
                      "artifacts/deep-scan/merge-inputs.json",
                    );
                    expect(
                      JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1)),
                    ).toBe(mergePath);
                    const payload = JSON.parse(
                      await readFile(mergePath, "utf8"),
                    );
                    expect(payload.scans.length).toBeGreaterThan(0);
                    for (const scan of payload.scans) {
                      expect(registrations.get(scan.childScanId)).toMatchObject(
                        { mode: "standard" },
                      );
                      expect(scan).toMatchObject({ scanId: id, findings: [] });
                    }
                  }
                  turns.push({
                    id,
                    mode,
                    cwd: threadOptions.workingDirectory!,
                    prompt,
                    config: options.config,
                    overrides: options.configOverrides,
                    executable: options.codexPathOverride,
                    environment: options.env!,
                    resumed: savedThreadId !== null,
                    ...(prepareNative
                      ? {
                          account: JSON.parse(
                            await readFile(
                              join(env["CODEX_HOME"]!, "auth.json"),
                              "utf8",
                            ),
                          ).account,
                        }
                      : {}),
                  });
                  if (prepareNative) {
                    expect(env["CODEX_HOME"]).toBe(codexHome);
                    expect(options.apiKey).toBeUndefined();
                    expect(env).not.toHaveProperty("OPENAI_API_KEY");
                    expect(env).not.toHaveProperty("CODEX_API_KEY");
                    expect(options.config).toMatchObject(nativeSettings);
                    const preflight = parseToml(
                      await readFile(
                        env["CODEX_SECURITY_CONFIG_PATH"]!,
                        "utf8",
                      ),
                    );
                    expect(preflight).not.toHaveProperty("mcp_servers");
                    expect(preflight).not.toHaveProperty(
                      "shell_environment_policy",
                    );
                    expect(preflight).toMatchObject({
                      model: nativeSettings.model,
                      model_reasoning_effort:
                        nativeSettings.model_reasoning_effort,
                      features: {
                        multi_agent_v2: {
                          enabled: true,
                          max_concurrent_threads_per_session: 4,
                        },
                      },
                    });
                    expect(
                      await readFile(join(codexHome, "config.toml"), "utf8"),
                    ).toBe(ambientConfig);
                  }
                  async function* events(): AsyncGenerator<ThreadEvent> {
                    thread.id ??= randomUUID();
                    const sessionHome = env["CODEX_HOME"]!;
                    if (trackingFailure) {
                      expect(mode).toBe("standard");
                      await writeFile(
                        join(sessionHome, "sessions"),
                        "not a directory",
                      );
                      yield { type: "thread.started", thread_id: thread.id };
                      const signal = turnOptions!.signal!;
                      if (!signal.aborted)
                        await new Promise<void>((resolve) =>
                          signal.addEventListener("abort", () => resolve(), {
                            once: true,
                          }),
                        );
                      throw signal.reason;
                    }
                    await mkdir(join(sessionHome, "sessions"), {
                      recursive: true,
                    });
                    await appendFile(
                      join(
                        sessionHome,
                        "sessions",
                        `rollout-${thread.id}.jsonl`,
                      ),
                      JSON.stringify({
                        type: "session_meta",
                        payload: {
                          id: thread.id,
                          cwd: threadOptions.workingDirectory,
                        },
                      }) + "\n",
                    );
                    if (prompt === "Post-scan instructions once.") {
                      followUpThreads.push(thread.id);
                      await writeFile(
                        join(
                          sessionHome,
                          "sessions",
                          `rollout-${thread.id}-worker.jsonl`,
                        ),
                        JSON.stringify({
                          type: "session_meta",
                          payload: {
                            id: `${thread.id}-worker`,
                            parent_thread_id: thread.id,
                          },
                        }) + "\n",
                      );
                    }
                    if (mode === "standard") {
                      const delegated = `${thread.id}-worker`;
                      workerRun.threads.add(thread.id);
                      workerRun.threads.add(delegated);
                      await writeFile(
                        join(
                          sessionHome,
                          "sessions",
                          `rollout-${delegated}.jsonl`,
                        ),
                        [
                          {
                            type: "session_meta",
                            payload: {
                              id: delegated,
                              parent_thread_id: thread.id,
                            },
                          },
                          {
                            type: "response_item",
                            payload: {
                              type: "function_call",
                              name: "exec_command",
                              call_id: "shared-command",
                              arguments: JSON.stringify({
                                cmd: "printf synthetic-worker",
                              }),
                            },
                          },
                          {
                            type: "response_item",
                            payload: {
                              type: "function_call_output",
                              call_id: "shared-command",
                              output: "synthetic-worker",
                            },
                          },
                        ]
                          .map((event) => JSON.stringify(event))
                          .join("\n") + "\n",
                      );
                    }
                    yield { type: "thread.started", thread_id: thread.id };
                    if (
                      artifactFailure === "checkpoint" &&
                      prompt === "Post-scan instructions once."
                    )
                      throw new Error("Synthetic follow-up failure.");
                    if (mode === "standard") {
                      for (const type of [
                        "item.started",
                        "item.completed",
                      ] as const)
                        yield {
                          type,
                          item: {
                            id: "shared-command",
                            type: "command_execution",
                            command: "printf synthetic-worker",
                            aggregated_output: "synthetic-worker",
                            status:
                              type === "item.started"
                                ? "in_progress"
                                : "completed",
                            exit_code: 0,
                          },
                        };
                      childTurns += 1;
                      const directory = record["scanDir"] as string;
                      if (
                        native === "discovery" &&
                        childTurns === 2 &&
                        !interrupted
                      ) {
                        interrupted = true;
                        await appendFile(
                          join(
                            sessionHome,
                            "sessions",
                            `rollout-${thread.id}.jsonl`,
                          ),
                          JSON.stringify({
                            type: "event_msg",
                            payload: {
                              type: "token_count",
                              info: {
                                total_token_usage: {
                                  input_tokens: 10,
                                  output_tokens: 3,
                                },
                              },
                            },
                          }) + "\n",
                        );
                        const error = new ScanTransportClosedError(
                          "mcp_transport_closed",
                        );
                        controller.abort(error);
                        throw error;
                      }
                      const reviewed = directory.endsWith("pass-1") ? 2 : 3;
                      for (const [phase, filesCompleted] of [
                        ["discovery", 0],
                        ["discovery", reviewed],
                        ["reporting", reviewed],
                      ] as const) {
                        const before = progress.at(-1)!.filesCompleted;
                        yield {
                          type: "item.completed",
                          item: {
                            id: `${id}-${phase}-${filesCompleted}`,
                            type: "agent_message",
                            text:
                              "CODEX_SECURITY_SCAN_PROGRESS " +
                              JSON.stringify({
                                phase,
                                filesCompleted,
                                filesTotal: 4,
                              }),
                          },
                        };
                        await new Promise<void>((resolve) =>
                          setImmediate(resolve),
                        );
                        expect(progress.at(-1)).toMatchObject({
                          phase: "discovery",
                          filesTotal: 4,
                        });
                        expect(
                          progress.at(-1)!.filesCompleted,
                        ).toBeGreaterThanOrEqual(
                          Math.max(before, filesCompleted),
                        );
                        expect(
                          progress.at(-1)!.filesCompleted,
                        ).toBeLessThanOrEqual(3);
                      }
                      const draft = {
                        scanId: id,
                        findings: childFindings,
                        coverage: {
                          completeness: "complete",
                          surfaces: [],
                          deferred: [],
                        },
                      };
                      const documents = prepareSemanticScanDraft(
                        {
                          targetContract: record["contract"] as JsonObject,
                          mode: "standard",
                          targetRevision: record["targetRevision"] as string,
                        },
                        draft,
                      );
                      const draftPath = join(
                        directory,
                        "drafts",
                        randomUUID() + ".json",
                      );
                      const checkpointPath = join(
                        directory,
                        "drafts",
                        randomUUID() + ".checkpoint.json",
                      );
                      await mkdir(join(directory, "drafts"), {
                        recursive: true,
                        mode: 0o700,
                      });
                      await writeFile(draftPath, JSON.stringify(documents));
                      await writeFile(checkpointPath, JSON.stringify(draft));
                      await runWorkbench(workbenches.get(id)!, [
                        "write-scan-draft",
                        "--scan-id",
                        id,
                        "--draft-path",
                        draftPath,
                        "--checkpoint-path",
                        checkpointPath,
                      ]);
                    }
                    yield {
                      type: "item.completed",
                      item: {
                        id: "response",
                        type: "agent_message",
                        text:
                          mode === "deep"
                            ? JSON.stringify({ scanId: id, findings: [] })
                            : "Complete",
                      },
                    };
                    if (prompt === "Post-scan instructions once.")
                      finishedFollowUps.push(thread.id);
                    yield {
                      type: "turn.completed",
                      usage:
                        (usage === "missing-merge" && mode === "deep") ||
                        (usage === "missing-child" &&
                          mode === "standard" &&
                          childTurns === 1)
                          ? null
                          : {
                              input_tokens:
                                budget &&
                                mode === "standard" &&
                                childTurns === (firstChildBudget ? 1 : 2)
                                  ? 100000
                                  : 10,
                              cached_input_tokens: 0,
                              output_tokens: 3,
                              cache_write_input_tokens: 0,
                              ...(usage === "unreported-cache"
                                ? { cache_write_input_tokens_reported: false }
                                : {}),
                              reasoning_output_tokens: 0,
                            },
                    } as ThreadEvent;
                  }
                  return { events: events() };
                },
              };
              return thread;
            };
            return {
              startThread: (threadOptions) => makeThread(threadOptions),
              resumeThread: (threadId, threadOptions) =>
                makeThread(threadOptions, threadId),
            };
          },
        },
        { surface: "sdk" },
      );
    };
    let client = await makeClient();
    const originalSpawn = childProcess.spawn;
    const loginSpawn = prepareNative
      ? spyOn(childProcess, "spawn").mockImplementation(((
          ...spawnArgs: Parameters<typeof childProcess.spawn>
        ) => {
          const [command, args, options] = spawnArgs;
          if (
            options?.env?.["CODEX_HOME"] === codexHome &&
            Array.isArray(args) &&
            args.at(-2) === "login" &&
            args.at(-1) === "status"
          ) {
            return originalSpawn(command, [loginFixture, ...args], options);
          }
          return originalSpawn(...spawnArgs);
        }) as typeof childProcess.spawn)
      : undefined;
    try {
      const scanOptions: ScanOptions = {
        mode: "deep",
        preserveProviderEnvironment: provider !== undefined,
        workers,
        subagents: 3,
        stopAfterNoNew: 2,
        maxDiscoveryRuns: 4,
        maxTimeHours: 1,
        outputDir: scanDir,
        registeredScan,
        ...(native && !prepareNative
          ? { safetyIdentifier: "saved-native-identifier" }
          : {}),
        scanPrompt: "Inspect the synthetic source.",
        ...(budget
          ? { maxCostUsd: 0.001 }
          : trackingFailure || requiredCost
            ? { maxCostUsd: 1 }
            : {}),
        postScanPrompt: "Post-scan instructions once.",
        onProgress: (update) => progress.push(update),
        onActivity: (activity) => workerRun.activities.push(activity),
        onSessionEvent: (event) => workerRun.sessions.push(event),
        onCost: (cost) => costs.push(cost),
        onWarning: (message) => {
          warnings.push(message);
          if (trackingFailure && message.startsWith("Deep Scan pass "))
            controller.abort(
              new Error("Unexpected retry after required metering failure."),
            );
          else console.error(message);
        },
      };
      const run = () => {
        progress = [];
        progressRuns.push(progress);
        workerRun = { threads: new Set(), activities: [], sessions: [] };
        workerRuns.push(workerRun);
        return client.run(repo, {
          ...scanOptions,
          ...nativeOptions,
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(
              Number(process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"] ?? "30000"),
            ),
          ]),
        });
      };
      const assertFollowUpLogs = async (scan: ScanLogSource) => {
        expect(followUpThreads).toHaveLength(1);
        if (previousFollowUp)
          expect(scan.executionThreadIds).toContain(previousFollowUp);
        const logs = await readSavedScanLogs(scan, codexHome);
        for (const id of followUpThreads) {
          expect(scan.executionThreadIds).toContain(id);
          expect(logs.sessions.map((session) => session.threadId)).toContain(
            id,
          );
          expect(logs.sessions.map((session) => session.threadId)).toContain(
            `${id}-worker`,
          );
          expect(scan.continuationThreadId).not.toBe(id);
        }
      };
      if (firstChildBudget) {
        await expect(run()).rejects.toBeInstanceOf(ScanCostLimitExceededError);
        expect(mergeAttempts).toBe(0);
        expect(turns.map((turn) => turn.mode)).toEqual(["standard"]);
        expect(registrations.size).toBe(2);
        const parent = [...registrations.values()].find(
          ({ mode }) => mode === "deep",
        )!;
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          parent["scanId"] as string,
        ]);
        expect(saved["scan"]).toMatchObject({ progress: { status: "failed" } });
        expect(
          JSON.parse(
            await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
          ),
        ).toMatchObject({
          terminalReason: "capped",
          aggregate: null,
          mergedScanIds: [],
        });
        const findings = JSON.parse(
          await readFile(join(scanDir, "findings.json"), "utf8"),
        ).findings;
        expect(findings).toHaveLength(1);
        expect(findings[0]).toMatchObject(childFindings[0]!);
        expect(
          JSON.parse(await readFile(join(scanDir, "coverage.json"), "utf8")),
        ).toMatchObject({ completeness: "partial" });
        return;
      }
      if (artifactFailure) {
        await expect(run()).rejects.toThrow(
          `Synthetic ${artifactFailure} write failure.`,
        );
        if (cleanupFailure)
          expect(warnings).toContain(
            "Could not clean up after the Codex Security scan: Synthetic staging cleanup failure.",
          );
        if (artifactFailure === "directory")
          expect([threadCount, turns.length]).toEqual([0, 0]);
        expect(
          commands.filter(({ command }) => command === "write-scan-draft"),
        ).toEqual([]);
        const parent = [...registrations.values()].find(
          ({ mode }) => mode === "deep",
        )!;
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          parent["scanId"] as string,
        ]);
        expect(saved["scan"]).toMatchObject({ progress: { status: "failed" } });
        if (artifactFailure !== "directory")
          await assertFollowUpLogs(saved["scan"] as ScanLogSource);
        if (artifactFailure === "checkpoint") {
          expect(saved["compositionCheckpoint"]).toBeNull();
          expect(
            (saved["scan"] as ScanLogSource).continuationThreadId,
          ).toBeNull();
        }
        return;
      }
      if (trackingFailure) {
        await expect(run()).rejects.toBeInstanceOf(ScanCostTrackingError);
        expect(turns).toHaveLength(1);
        expect(
          [...registrations.values()].map((record) => record["mode"]).sort(),
        ).toEqual(["deep", "standard"]);
        expect(
          JSON.parse(
            await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
          ),
        ).toMatchObject({
          terminalReason: "failed",
          mergedScanIds: [],
          consecutiveErrors: 0,
        });
        for (const scanId of registrations.keys()) {
          const saved = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            scanId,
          ]);
          expect(saved["scan"]).toMatchObject({
            progress: { status: "failed" },
          });
        }
        return;
      }
      if (requiredCost) {
        await expect(run()).rejects.toBeInstanceOf(ScanCostTrackingError);
        expect(turns).toHaveLength(1);
        const parent = [...registrations.values()].find(
          ({ mode }) => mode === "deep",
        )!;
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          parent["scanId"] as string,
        ]);
        expect(saved["scan"]).toMatchObject({ progress: { status: "failed" } });
        expect(saved["compositionCheckpoint"]).toMatchObject({
          terminalReason: "failed",
          consecutiveErrors: 0,
          noNewStreak: 0,
        });
        return;
      }
      if (native === "discovery" || native === "sealed") {
        await expect(run()).rejects.toBeInstanceOf(ScanTransportClosedError);
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          registeredScan!.scanId,
        ]);
        expect(saved["scan"]).toMatchObject({
          progress: { status: "running" },
        });
        savedExecutionThread = (saved["scan"] as JsonObject)[
          "continuationThreadId"
        ] as string;
        expect(savedExecutionThread).not.toBe(registeredScan!.threadId);
        const checkpoint = JSON.parse(
          await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
        );
        if (native === "discovery") {
          expect(checkpoint).toMatchObject({
            noNewStreak: 1,
            consecutiveErrors: 0,
          });
          expect(checkpoint.terminalReason).toBeUndefined();
          const child = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            checkpoint.passes[1].scanId,
          ]);
          expect(child["scan"]).toMatchObject({
            progress: { status: "running" },
          });
          expect(
            ((child["scan"] as JsonObject)["cost"] as JsonObject)[
              "estimatedUsd"
            ],
          ).toBeGreaterThan(0);
        } else runtimeVersion = "99.0.0";
        expect(
          commands.filter(({ command }) => command === "fail-scan"),
        ).toEqual([]);
        controller = new AbortController();
        environment.CODEX_SAFETY_IDENTIFIER = "changed-ambient-identifier";
        await client.close();
        if (prepareNative) {
          nativeRecipe = (
            await runWorkbench(commandOptions, [
              "get-scan-recipe",
              "--scan-id",
              registeredScan!.scanId,
            ])
          )["recipe"] as JsonObject;
          expect(nativeRecipe["config"]).toMatchObject(nativeSettings);
          ambientConfig = stringifyToml({
            model: "competing-ambient-model",
            model_reasoning_effort: "low",
            cli_auth_credentials_store: "keyring",
            mcp_servers: { synthetic: { command: "competing-mcp" } },
            shell_environment_policy: {
              set: { FIXTURE_SETTING: "competing-shell" },
            },
          });
          await Promise.all([
            writeFile(
              join(codexHome, "auth.json"),
              JSON.stringify({ auth_mode: "chatgpt", account: "B" }),
            ),
            writeFile(join(codexHome, "config.toml"), ambientConfig),
          ]);
        }
        client = await makeClient();
        if (native === "discovery") {
          const sessionPath = join(
            codexHome,
            "sessions",
            `rollout-${savedExecutionThread}.jsonl`,
          );
          const sessionBytes = await readFile(sessionPath);
          const checkpointPath = join(scanDir, DEEP_SCAN_CHECKPOINT);
          const checkpointBytes = await readFile(checkpointPath);
          const activityBefore = [threadCount, turns.length];
          const commandCount = commands.length;
          await rm(sessionPath);
          try {
            await expect(run()).rejects.toThrow("The original Codex session");
            expect([threadCount, turns.length]).toEqual(activityBefore);
            expect(await readFile(checkpointPath)).toEqual(checkpointBytes);
            expect(
              commands.slice(commandCount).map(({ command }) => command),
            ).toEqual(["register-cli-scan", "get-cli-scan-resume"]);
            for (const scanId of [
              registeredScan!.scanId,
              checkpoint.passes[1].scanId,
            ]) {
              const saved = await runWorkbench(commandOptions, [
                "get-scan",
                "--scan-id",
                scanId,
              ]);
              expect(saved["scan"]).toMatchObject({
                progress: { status: "running" },
              });
            }
          } finally {
            await writeFile(sessionPath, sessionBytes);
          }
        }
      }
      const result = await run();
      if (cleanupFailure)
        expect(warnings).toContain(
          "Could not clean up after the Codex Security scan: Synthetic staging cleanup failure.",
        );
      if (usage) {
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          result.manifest.scan.id,
        ]);
        const scan = saved["scan"] as JsonObject;
        expect(scan["progress"]).toMatchObject({ status: "complete" });
        expect(costs.at(-1)!.estimatedUsd).toBeGreaterThan(0);
        if (usage === "missing-merge" || usage === "missing-child") {
          expect(result.cost).toBeNull();
          expect(scan["cost"]).toBeUndefined();
          expect(scan["usage"]).toMatchObject({ coverage: "unavailable" });
        } else {
          expect(result.cost).toEqual(costs.at(-1)!);
          expect(result.cost!.cacheWriteInputTokensReported).toBe(false);
          expect(result.cost).toEqual(scan["cost"] as unknown as ScanCost);
        }
      }
      for (const observed of workerRuns) {
        const labels = new Map<string, number>();
        for (const event of observed.sessions) {
          if (!observed.threads.has(event.threadId)) {
            expect(event.worker).toBeUndefined();
            continue;
          }
          expect(event.worker).toBeGreaterThan(0);
          if (labels.has(event.threadId))
            expect(event.worker).toBe(labels.get(event.threadId));
          labels.set(event.threadId, event.worker!);
        }
        expect(new Set(labels.keys())).toEqual(observed.threads);
        expect(new Set(labels.values()).size).toBe(labels.size);
        for (const threadId of observed.threads)
          expect(
            observed.activities
              .filter(({ id }) => id === `${threadId}:shared-command`)
              .map(({ worker, status }) => ({ worker, status })),
          ).toEqual([
            { worker: labels.get(threadId), status: "running" },
            { worker: labels.get(threadId), status: "completed" },
          ]);
      }
      for (const updates of progressRuns) {
        const counts = updates.map((update) => update.filesCompleted);
        expect(counts).toEqual([...counts].sort((left, right) => left - right));
        expect(updates.every((update) => update.filesTotal === 4)).toBe(true);
        expect(Math.max(...counts)).toBeLessThanOrEqual(3);
      }
      expect(progressRuns.flat()).toContainEqual({
        phase: "discovery",
        filesCompleted: 3,
        filesTotal: 4,
      });
      if (savedExecutionThread)
        expect(result.threadId).toBe(savedExecutionThread);
      if (sealedArtifacts) {
        for (const [path, bytes] of sealedArtifacts)
          expect(await readFile(join(scanDir, path))).toEqual(bytes);
        expect(result.manifest.scan.producer.version).toBe(version);
      }
      if (feedbackBefore) {
        expect(
          await readFile(
            join(scanDir, "artifacts/01_context/false_positive_feedback.json"),
          ),
        ).toEqual(feedbackBefore);
        expect(
          turns
            .filter((turn) => turn.mode === "standard")
            .every((turn) =>
              turn.prompt.includes("false_positive_feedback.json"),
            ),
        ).toBe(true);
      }
      expect(result.findings.findings).toEqual([]);
      expect(result.coverage.completeness).toBe(
        budget ? "partial" : "complete",
      );
      const checkpoint = JSON.parse(
        await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
      );
      expect(checkpoint.terminalReason).toBe(budget ? "capped" : "saturated");
      expect(checkpoint.noNewStreak).toBe(budget ? 1 : 2);
      expect(checkpoint.passes).toHaveLength(2);
      expect(checkpoint.mergedScanIds).toHaveLength(budget ? 1 : 2);
      expect(registrations.size).toBe(3);
      if (provider !== undefined) {
        for (const registration of registrations.values()) {
          const saved = registration["recipe"] as JsonObject;
          expect(saved["preserveProviderEnvironment"]).toBe(true);
          expect(
            (saved["config"] as JsonObject)["model_providers"],
          ).toMatchObject({ custom: provider });
          expect(
            (saved["config"] as JsonObject)["cli_auth_credentials_store"],
          ).toBe("file");
        }
        expect(environment.OPENAI_API_KEY).toBe("synthetic-provider-key");
        expect(environment.CODEX_API_KEY).toBe("synthetic-native-key");
      }
      for (const turn of turns) {
        const permission = turn.overrides?.find((value) =>
          value.startsWith("permissions.codex_security_scan="),
        );
        expect(permission).toBeDefined();
        expect(parseToml(permission!)).toMatchObject({
          permissions: {
            codex_security_scan: {
              filesystem: {
                [join(root, "private")]: "deny",
                ":root": "read",
                ":workspace_roots": "write",
              },
              network: { enabled: false },
            },
          },
        });
        expect(await realpath(turn.executable!)).toBe(
          await realpath(environment.CODEX_CLI_PATH),
        );
        expect(turn.environment["SYNTHETIC_SCAN_SETTING"]).toBe("inherited");
        expect(turn.environment["CODEX_SAFETY_IDENTIFIER"]).toBe(
          native && !prepareNative ? "saved-native-identifier" : undefined,
        );
      }
      const children = turns.filter((turn) => turn.mode === "standard");
      expect(children).toHaveLength(native === "discovery" ? 3 : 2);
      expect(new Set(children.map((turn) => turn.id)).size).toBe(2);
      if (prepareNative) {
        const accounts = (await readFile(accountLog, "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(accounts[0]).toMatchObject({ home: codexHome, account: "A" });
        expect(accounts.at(-1)).toMatchObject({
          home: codexHome,
          account: "B",
        });
        for (const { args } of accounts)
          expect(args).toContain('cli_auth_credentials_store="file"');
        expect(
          accounts.every(
            ({ home, account }) =>
              home === codexHome && ["A", "B"].includes(account),
          ),
        ).toBe(true);
        expect(
          children.map(({ account, resumed }) => ({ account, resumed })),
        ).toEqual([
          { account: "A", resumed: false },
          { account: "A", resumed: false },
          { account: "B", resumed: true },
        ]);
        expect(
          turns
            .filter(
              ({ mode, prompt }) =>
                mode === "deep" && prompt !== "Post-scan instructions once.",
            )
            .map(({ account }) => account),
        ).toEqual(["A", "B"]);
        if (!usage) expect(result.cost!.estimatedUsd).toBeGreaterThan(0);
        expect(existsSync(join(codexHome, "sessions"))).toBe(true);
        expect(existsSync(join(managedHome, "sessions"))).toBe(false);
        expect(await readFile(join(managedHome, "auth.json"), "utf8")).toBe(
          managedAuth,
        );
        expect(await readFile(join(managedHome, "config.toml"), "utf8")).toBe(
          managedConfig,
        );
        expect(await readFile(join(codexHome, "config.toml"), "utf8")).toBe(
          ambientConfig,
        );
      }
      for (const child of children) {
        expect(child.prompt).toContain("Inspect the synthetic source.");
        expect(child.prompt).not.toContain("sourceFindingIds");
        expect(child.config).toMatchObject({
          model: "gpt-6-astra",
          model_reasoning_effort: "ultra",
          features: {
            multi_agent_v2: {
              enabled: true,
              max_concurrent_threads_per_session: 4,
            },
          },
        });
        const completed = checkpoint.mergedScanIds.includes(child.id);
        expect(
          commands.filter(
            (command) =>
              command.command === "complete-scan" && command.id === child.id,
          ),
        ).toHaveLength(completed ? 1 : 0);
        const record = registrations.get(child.id)!;
        const manifest = JSON.parse(
          await readFile(
            join(record["scanDir"] as string, "scan-manifest.json"),
            "utf8",
          ),
        );
        expect(manifest.scan.complete).not.toBe(false);
      }
      expect(
        commands.filter(
          (command) =>
            command.command ===
              (budget ? "complete-budget-exhausted-scan" : "complete-scan") &&
            command.id === result.manifest.scan.id,
        ),
      ).toHaveLength(1);
      expect(
        turns.filter((turn) => turn.prompt === "Post-scan instructions once."),
      ).toHaveLength(budget ? 0 : 1);
      if (logFailure) {
        expect(finishedFollowUps).toEqual(followUpThreads);
        expect(finishedFollowUps).toHaveLength(1);
        expect(warnings).toContain(
          "Could not save post-scan session: Synthetic session index write failure.",
        );
      } else if (!budget) {
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          result.manifest.scan.id,
        ]);
        const scan = saved["scan"] as ScanLogSource;
        expect(scan.continuationThreadId).toBe(result.threadId);
        await assertFollowUpLogs(scan);
      }
      if (budget) {
        expect(result.cost!.estimatedUsd).toBeGreaterThan(0.001);
        expect(result.coverage.deferred.length).toBeGreaterThan(0);
        const stopped = await runWorkbench(
          { ...workbenches.get(children[1]!.id)!, signal: undefined },
          ["get-scan", "--scan-id", children[1]!.id],
        );
        expect((stopped["scan"] as JsonObject)["cost"]).toBeDefined();
      }
      const listed = await runWorkbench(
        { ...workbenches.get(result.manifest.scan.id)!, signal: undefined },
        ["list-scans"],
      );
      const listedIds = (listed["scans"] as JsonObject[]).map(
        (scan) => scan["scanId"],
      );
      expect(listedIds).toContain(result.manifest.scan.id);
      expect(listedIds).toHaveLength(native === "feedback" ? 2 : 1);
    } finally {
      try {
        await client.close();
      } finally {
        loginSpawn?.mockRestore();
      }
    }
    if (prepareNative) {
      expect(existsSync(join(codexHome, "sessions"))).toBe(true);
      expect(
        JSON.parse(await readFile(join(codexHome, "auth.json"), "utf8")),
      ).toEqual({ auth_mode: "chatgpt", account: "B" });
      expect(await readFile(join(codexHome, "config.toml"), "utf8")).toBe(
        ambientConfig,
      );
    }
  },
);
