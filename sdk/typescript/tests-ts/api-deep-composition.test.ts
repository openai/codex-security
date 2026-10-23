import * as ownerArtifacts from "../src/scan-owner-suggestions.js";
import { restoreReplayProfile } from "../src/provider-profile.js";
import type { SemanticScan, SemanticFinding } from "../src/semantic-models.js";
import { createHash, randomUUID } from "node:crypto";
import * as childProcess from "node:child_process";
import { existsSync } from "node:fs";
import {
  appendFile,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type {
  ThreadEvent,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, expect, spyOn, test } from "bun:test";
import { build } from "esbuild";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import type { ScanSessionEvent } from "../src/cost.js";
import type { ScanActivity } from "../src/scan-activity.js";
import {
  runWorkbench,
  resolvePluginPython,
  type WorkbenchCommandOptions as RequiredWorkbenchCommandOptions,
} from "../src/runtime.js";
import { publishDraft } from "./support/scan-publication.js";
import { createApiTestFixtures } from "./support/api-events.js";
import { tokenUsageEvent } from "./support/usage-rollout.js";
import { requestMetadata } from "./support/request-metadata.js";
import { prepareSemanticScanDraft } from "../src/scan-semantics.js";
import {
  DEEP_SCAN_CHECKPOINT,
  DeepScanRecoveryError,
} from "../src/deep-scan.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
} from "../src/errors.js";
import type { ScanProgress } from "../src/worker-progress.js";
import { readSavedScanLogs, type ScanLogSource } from "../src/scan-logs.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { nodeCommand } from "./support/shell.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([false, true])(
  "inactive provider and MCP settings stay private in saved recipes (native: %p)",
  async (native) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    await Promise.all([mkdir(repository), mkdir(home, { mode: 0o700 })]);
    await writeFile(join(repository, "app.py"), "print('synthetic fixture')\n");
    const environment = {
      ...process.env,
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "external-state"),
      OPENAI_API_KEY: "synthetic-fixture-key",
    };
    const configuration = {
      model: "gpt-5.6-sol",
      model_provider: "openai",
      profiles: {
        unused: {
          model: "unselected-model",
          model_providers: {
            unused: {
              name: "Unused",
              wire_api: "responses",
              http_headers: {
                Authorization: "synthetic-inactive-provider-token",
              },
            },
          },
          mcp_servers: {
            unused: {
              url: "https://mcp.example.test",
              http_headers: { Authorization: "synthetic-inactive-mcp-token" },
            },
          },
        },
      },
    };
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    let registration: string | undefined;
    let launched = false;
    await using client = new CodexSecurity(
      { pluginPath: pluginRoot, codexOverrides: configuration },
      {
        environment,
        prepareRuntime: async () => ({
          codexHome: home,
          preserveCodexHomeConfig: true,
          environment,
          credentialsAvailable: true,
          plugin: {
            pluginRoot,
            installedRoot: pluginRoot,
            marketplaceRoot: pluginRoot,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
        }),
        resolvePluginPython: async () => python!,
        repositoryRevision: async () => null,
        resolveCodexCommand: () => ({ command: process.execPath }),
        probeCodexSandbox: async () => {},
        runWorkbench: async (options, args, input) => {
          const result = await runWorkbench(options, args, input);
          if (args[0] === "register-cli-scan")
            registration = result["scanId"] as string;
          return result;
        },
        createCodex: () => {
          launched = true;
          throw new Error("Synthetic launch boundary");
        },
      },
      { surface: "sdk" },
    );
    await expect(
      client.run(repository, {
        mode: "standard",
        outputDir: join(root, "scan"),
        ...(native
          ? {
              inheritedPermissions: {
                filesystem: { ":workspace_roots": "write" },
                network: { enabled: false },
              },
              preserveProviderEnvironment: true,
            }
          : {}),
      }),
    ).rejects.toThrow("Synthetic launch boundary");
    expect(launched).toBe(true);
    expect(registration).toBeDefined();
    const saved = await runWorkbench(
      { python: python!, pluginRoot, environment },
      ["get-scan-recipe", "--scan-id", registration!],
    );
    expect(JSON.stringify(saved)).not.toContain(
      "synthetic-inactive-provider-token",
    );
    expect(JSON.stringify(saved)).not.toContain("synthetic-inactive-mcp-token");
    const recipe = saved["recipe"] as JsonObject;
    expect(recipe).not.toHaveProperty("replayProfile");
    if (native)
      expect(recipe["config"]).toMatchObject({
        profiles: { unused: { model: "unselected-model" } },
      });
    expect(
      configuration.profiles.unused.mcp_servers.unused.http_headers
        .Authorization,
    ).toBe("synthetic-inactive-mcp-token");
  },
);

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

function testDeepCompositionCases<
  T extends {
    instructionFile?: string;
    ambientInstruction?: string;
    native?: "discovery" | "sealed";
    queuedNativeKnowledge?: boolean;
    provider?: JsonObject;
    missingReplay?: string;
  },
>(cases: T[]) {
  return (name: string, run: (scenario: T) => Promise<void>) => {
    for (const scenario of cases) {
      test(
        name.replace("%j", JSON.stringify(scenario)),
        () => run(scenario),
        scenario.instructionFile !== undefined ||
          scenario.ambientInstruction !== undefined ||
          (scenario.native === "discovery" &&
            (scenario.queuedNativeKnowledge === true ||
              (scenario.provider !== undefined &&
                scenario.missingReplay === undefined)))
          ? 120_000
          : undefined,
      );
    }
  };
}

testDeepCompositionCases([
  { budget: false, partialCheckpoint: true },
  { budget: false, partialCheckpoint: true, completedCleanup: true },
  {
    budget: false,
    partialCheckpoint: true,
    native: "discovery",
    requiredCost: true,
  },
  { budget: false },
  { budget: false, ownerOutcome: "success", ownerResume: true },
  {
    budget: false,
    ownerOutcome: "success",
    ownerResume: true,
    instructionFile: "sealed missing",
  },
  { budget: false, ownerOutcome: "failure" },
  { budget: true },
  { budget: true, firstChildBudget: true },
  { budget: false, native: "discovery" },
  ...(
    [
      "changed",
      "unchanged",
      "missing",
      "empty",
      "legacy changed",
      "postscan changed",
      "later reducer changed",
    ] as const
  ).map((instructionFile) => ({
    budget: false,
    native: "discovery",
    instructionFile,
  })),
  {
    budget: false,
    native: "discovery",
    instructionFile: "reducer changed",
    requiredCost: true,
  },
  {
    budget: false,
    native: "discovery",
    instructionFile: "new child changed",
    requiredCost: true,
  },
  ...(["relative", "profile", "home"] as const).map((instructionPathForm) => ({
    budget: false,
    native: "discovery",
    instructionFile: "changed",
    instructionPathForm,
  })),
  { budget: false, native: "discovery", instructionFile: "aggregate missing" },
  {
    budget: false,
    native: "discovery",
    instructionFile: "sealed child missing",
  },
  ...(["discovery", "reducer"] as const).flatMap((instructionBoundary) =>
    (["introduced", "unchanged", "legacy"] as const).map(
      (ambientInstruction) => ({
        budget: false,
        native: "discovery" as const,
        instructionBoundary,
        ambientInstruction,
      }),
    ),
  ),
  { budget: false, native: "discovery", queuedNativeKnowledge: true },
  {
    budget: false,
    native: "discovery",
    provider: {
      env_key: "PROVIDER_KEY",
      experimental_bearer_token: "synthetic-inline-private-provider-token",
    },
  },
  {
    budget: false,
    native: "sealed",
    provider: {
      env_key: "PROVIDER_KEY",
      experimental_bearer_token: "synthetic-inline-private-provider-token",
    },
  },
  ...(["publish", "follow-up", "wrong-claim", "unsealed"] as const).map(
    (missingReplay) => ({
      budget: false,
      native: missingReplay === "unsealed" ? "discovery" : "sealed",
      missingReplay,
      provider: {
        env_key: "PROVIDER_KEY",
        experimental_bearer_token: "synthetic-inline-private-provider-token",
      },
    }),
  ),
] as {
  budget: boolean;
  ownerOutcome?: "success" | "failure";
  ownerResume?: boolean;
  firstChildBudget?: boolean;
  partialCheckpoint?: boolean;
  completedCleanup?: boolean;
  requiredCost?: boolean;
  provider?: JsonObject;
  native?: "discovery" | "sealed";
  queuedNativeKnowledge?: boolean;
  missingReplay?: "publish" | "follow-up" | "wrong-claim" | "unsealed";
  instructionPathForm?: "relative" | "profile" | "home";
  instructionBoundary?: "discovery" | "reducer";
  ambientInstruction?: "introduced" | "unchanged" | "legacy";
  instructionFile?:
    | "changed"
    | "unchanged"
    | "missing"
    | "empty"
    | "sealed missing"
    | "legacy changed"
    | "reducer changed"
    | "new child changed"
    | "aggregate missing"
    | "postscan changed"
    | "later reducer changed"
    | "sealed child missing";
}[])(
  "Deep composes sealed ordinary scans and preserves a budgeted parent: %j",
  async ({
    budget,
    ownerOutcome,
    ownerResume,
    firstChildBudget,
    partialCheckpoint,
    completedCleanup,
    requiredCost,
    provider,
    native,
    queuedNativeKnowledge,
    missingReplay,
    instructionFile,
    instructionPathForm,
    instructionBoundary,
    ambientInstruction,
  }) => {
    const hasInstructionScenario =
      instructionFile !== undefined || ambientInstruction !== undefined;
    const legacyInstructions =
      instructionFile === "legacy changed" || ambientInstruction === "legacy";
    const instructionCostRecovery =
      instructionFile === "reducer changed" ||
      instructionFile === "new child changed" ||
      ambientInstruction !== undefined;
    const reducerInputRecovery =
      instructionFile === "reducer changed" ||
      instructionBoundary === "reducer";
    const root = await temporaryDirectory();
    const repo = join(root, "repo");
    const codexHome = join(root, "codex");
    let scanDir = join(root, "scan");
    await Promise.all([mkdir(repo), mkdir(codexHome)]);
    await Promise.all(
      ["app.py", "routes.py", "models.py", "helpers.py"].map((name) =>
        writeFile(join(repo, name), "print('public synthetic fixture')\n"),
      ),
    );
    const knowledgeDocument = join(root, "architecture.md");
    if (queuedNativeKnowledge)
      await writeFile(knowledgeDocument, "Original synthetic architecture.\n");
    let knowledgeBytes: string | undefined;
    let queuedPrepared: CapturedNativeScan | undefined;
    let preparedCount = 0;
    const childFindings: JsonObject[] = JSON.parse(
      await readFile(
        join(pluginRoot, "examples/completed-scan/findings.json"),
        "utf8",
      ),
    ).findings.slice(0, 1);
    if (instructionFile === "sealed child missing") childFindings.length = 0;
    const ownerSuggestion = {
      email: "synthetic-contributor@example.test",
      commit: "1".repeat(40),
      reason: "Synthetic ownership evidence recorded during discovery.",
    };
    for (const finding of childFindings) {
      for (const field of ["findingId", "occurrenceId", "fingerprints"])
        delete finding[field];
      finding["locations"] = [{ path: "app.py", startLine: 1, endLine: 1 }];
      if (ownerOutcome)
        finding["extensions"] = {
          ...(finding["extensions"] as JsonObject | undefined),
          ownerSuggestion,
        };
      if (partialCheckpoint)
        finding["codeEvidence"] = [
          {
            id: "source",
            label: "Reviewed source",
            path: "app.py",
            startLine: 1,
            code: "print('public synthetic fixture')",
            explanation:
              "Synthetic source evidence retained before interruption.",
          },
        ];
    }
    const pendingCandidate = partialCheckpoint
      ? {
          ...structuredClone(childFindings[0]!),
          identity: { anchor: "pending-source-review" },
          title: "Pending source review",
          validation: {
            summary: "Independent validation is pending.",
            counterEvidence: ["A caller restriction remains to be verified."],
          },
        }
      : undefined;
    const version = JSON.parse(
      await readFile(join(pluginRoot, ".codex-plugin/plugin.json"), "utf8"),
    ).version;
    let runtimeVersion = version;
    const customProvider = provider?.["env_key"] === "PROVIDER_KEY";
    const runtimeNode = nodeCommand().command;
    const environment = {
      ...process.env,
      CODEX_HOME: codexHome,
      ...(instructionPathForm === "home"
        ? { HOME: root, USERPROFILE: root }
        : {}),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      CODEX_CLI_PATH: process.execPath,
      SYNTHETIC_SCAN_SETTING: "inherited",
      ...(!native ? { CODEX_MCP_NODE_PATH: process.execPath } : {}),
      ...(queuedNativeKnowledge
        ? { CODEX_SECURITY_KNOWLEDGE_BASE: knowledgeDocument }
        : {}),
      GIT_SSH_COMMAND: "synthetic-ssh --fixture",
      GIT_CONFIG_GLOBAL: join(root, "operator.gitconfig"),
      CODEX_SAFETY_IDENTIFIER: "ambient-identifier",
      ...(customProvider ? { PROVIDER_KEY: "synthetic-provider-key" } : {}),
      ...(native ? { OPENAI_API_KEY: "synthetic-native-key" } : {}),
      ...(provider === undefined
        ? {}
        : {
            OPENAI_API_KEY: customProvider
              ? undefined
              : "synthetic-provider-key",
            CODEX_API_KEY: customProvider ? undefined : "synthetic-native-key",
          }),
    };
    const python =
      ambientInstruction === undefined
        ? (Bun.which("python3") ?? Bun.which("python"))
        : await resolvePluginPython({ environment, protectedRoot: repo });
    if (python === null) throw new Error("Python is required for this test.");
    const instructionPath = join(root, "instructions.md");
    const instructionText =
      instructionFile === "empty"
        ? ""
        : "Synthetic composed-scan model instructions.\n";
    await writeFile(instructionPath, instructionText);
    const instructionDigest = createHash("sha256")
      .update(instructionText)
      .digest("hex");
    let continuedInstructionExecution = false;
    const instructionExecutions: Array<{
      scanId: string;
      mode: string;
      resumed: boolean;
      continued: boolean;
      followUp: boolean;
      cwd: string;
      path: string | null;
      bytes?: string | null;
      error?: { code: string; message: string };
    }> = [];
    const instructionProbe = `
const { readFileSync } = require("node:fs");
const path = process.argv[1];
try {
  process.stdout.write(JSON.stringify({ cwd: process.cwd(), path, bytes: readFileSync(path, "utf8") }));
} catch (error) {
  process.stdout.write(JSON.stringify({ cwd: process.cwd(), path, error: { code: error.code, message: error.message } }));
  process.exitCode = 1;
}
`;
    // Observe actual child input and current home bytes. This synthetic child
    // models the native origin rules separately checked by config/read probes.
    const ambientInstructionProbe = `
const { readFileSync } = require("node:fs");
const { join, resolve } = require("node:path");
const config = JSON.parse(process.argv[1]);
const { parse } = require(process.argv[2]);
const home = process.env.CODEX_HOME;
const inherited = parse(readFileSync(join(home, "config.toml"), "utf8"));
const selected = config.model_instructions_file;
const raw = selected === undefined ? inherited.model_instructions_file : selected;
const file = typeof raw === "string" ? resolve(selected === undefined ? home : process.cwd(), raw) : null;
process.stdout.write(JSON.stringify({cwd:process.cwd(),path:file,bytes:file === null ? null : readFileSync(file,"utf8")}));
`;
    const inheritedSettings = {
      openai_base_url: "https://endpoint.example.test/v1",
      web_search: "cached",
      developer_instructions: "Synthetic composed-scan instructions.",
      analytics: { enabled: false },
      otel: { environment: "synthetic-composed-scan" },
      responses_api_metadata: {
        "team.tag": "synthetic-composed-scan",
        codex_security_integration: "github_action",
      },
      ...(ambientInstruction === undefined
        ? { model_instructions_file: instructionPath }
        : {}),
      experimental_compact_prompt_file: "compact.md",
      model_catalog_json: "models.json",
      sqlite_home: "sqlite",
    };
    const { responses_api_metadata: inheritedMetadata, ...inheritedConfig } =
      inheritedSettings;
    const expectedSettings = () => ({
      ...inheritedConfig,
      ...(ambientInstruction === undefined
        ? { model_instructions_file: instructionPath }
        : {}),
      experimental_compact_prompt_file: join(scanDir, "compact.md"),
      model_catalog_json: join(scanDir, "models.json"),
      sqlite_home: join(scanDir, "sqlite"),
    });
    const nativeSettings = {
      ...inheritedSettings,
      model: "gpt-6-astra",
      model_reasoning_effort: "ultra",
      service_tier: "priority",
      forced_login_method: "chatgpt",
      cli_auth_credentials_store: "file",
      projects: { [repo]: { trust_level: "trusted" } },
      ...(provider === undefined
        ? {}
        : { model_provider: "custom", model_providers: { custom: provider } }),
      mcp_servers: {
        synthetic: {
          command: "synthetic-mcp",
          env: { FIXTURE_TOKEN: "saved-mcp-setting" },
        },
        authenticated: {
          url: "https://mcp.example.test",
          http_headers: { Authorization: "Bearer synthetic-private-mcp-token" },
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
    if (native) {
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
    }
    if (instructionPathForm !== undefined) {
      const relativeInstructionPath = relative(scanDir, instructionPath);
      const decoyPath = join(root, "decoy-instructions.md");
      await writeFile(decoyPath, "Unselected synthetic instructions.\n");
      ambientConfig = stringifyToml({
        ...nativeSettings,
        model_instructions_file:
          instructionPathForm === "home"
            ? "~/instructions.md"
            : instructionPathForm === "profile"
              ? decoyPath
              : relativeInstructionPath,
        ...(instructionPathForm === "profile"
          ? {
              profile: "selected",
              profiles: {
                selected: { model_instructions_file: relativeInstructionPath },
              },
            }
          : {}),
      });
      await writeFile(join(codexHome, "config.toml"), ambientConfig);
    }
    let controller = new AbortController();
    let interrupted = false;
    let checkpointSignal: AbortSignal | undefined;
    let mergeAttempts = 0;
    let savedExecutionThread: string | undefined;
    let sealedArtifacts: Map<string, Buffer<ArrayBuffer>> | undefined;
    const registrations = new Map<string, JsonObject>();
    const followUpThreads: string[] = [];
    const previousFollowUp = native === "sealed" ? randomUUID() : undefined;
    let childTurns = 0;
    let threadCount = 0;
    const progressRuns: ScanProgress[][] = [];
    let progress: ScanProgress[];
    const workerRuns: Array<{
      threads: Set<string>;
      activities: ScanActivity[];
      sessions: ScanSessionEvent[];
    }> = [];
    let workerRun: (typeof workerRuns)[number];
    const rejectedWorkerRuns = new Set<(typeof workerRuns)[number]>();
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
          CODEX_SAFETY_IDENTIFIER:
            customProvider || nativeRecipe !== undefined
              ? environment.CODEX_SAFETY_IDENTIFIER
              : undefined,
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
          const nativeInput = {
            scan: {
              ...registeredScan,
              targetPath: repo,
              userContext: "Inspect the synthetic source.",
            },
            recipe:
              queuedNativeKnowledge ||
              (hasInstructionScenario && nativeRecipe === undefined)
                ? undefined
                : (nativeRecipe ?? {
                    postScanPrompt:
                      (missingReplay && missingReplay !== "follow-up") ||
                      instructionFile === "sealed child missing"
                        ? ""
                        : "Post-scan instructions once.",
                    cyberAccessProgram: "daybreak_blue",
                    ...(customProvider
                      ? {
                          safetyIdentifier: environment.CODEX_SAFETY_IDENTIFIER,
                        }
                      : {}),
                  }),
            savedDeepScanSettings: {
              workers: 1,
              subagents: 3,
              stopAfterNoNew: 1,
              maxDiscoveryRuns: 4,
              maxTimeHours: 1,
            },
            threadId: registeredScan!.threadId,
            pluginRoot: PLUGIN_ROOT,
            pythonPath: python,
            parentSandbox: {
              workspaceAccess: "write",
              filesystemDenies: [join(root, "private")],
            },
          };
          prepared = queuedPrepared ?? (await prepareNative(nativeInput));
          if (queuedNativeKnowledge && preparedCount++ === 0) {
            // Both native callers prepared before either SDK bound its recipe.
            queuedPrepared = await prepareNative(nativeInput);
            expect(queuedPrepared.options.resumeScanId).toBeUndefined();
          }
          nativeOptions = {
            ...prepared.options,
            ...(instructionCostRecovery
              ? { maxCostUsd: 1, requireCost: true }
              : {}),
            ...(queuedNativeKnowledge ||
            (hasInstructionScenario && nativeRecipe === undefined)
              ? {
                  postScanPrompt:
                    (missingReplay && missingReplay !== "follow-up") ||
                    instructionFile === "sealed child missing"
                      ? ""
                      : "Post-scan instructions once.",
                  cyberAccessProgram: "daybreak_blue",
                }
              : {}),
          };
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
            ...inheritedSettings,
            model: "gpt-6-astra",
            model_reasoning_effort: "ultra",
            service_tier: "priority",
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
            preserveCodexHomeConfig: true,
            environment: {
              ...environment,
              SYNTHETIC_SCAN_SETTING: "prepared default",
              CODEX_MCP_NODE_PATH: runtimeNode,
            },
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
          runWorkbench: async (options, args, input) => {
            // Older saved recipes have no instruction digest. Use the real workbench
            // to persist that historical shape before exercising public resume.
            if (
              legacyInstructions &&
              nativeRecipe === undefined &&
              args[0] === "register-cli-scan" &&
              !args.includes("--parent-scan-id")
            ) {
              const request = JSON.parse(input!);
              delete request.recipe.scanInputs.modelInstructionsFileSha256;
              input = JSON.stringify(request);
            }
            const result = await runWorkbench(options, args, input);
            const id = args.includes("--scan-id")
              ? args[args.indexOf("--scan-id") + 1]
              : undefined;
            commands.push({ command: args[0]!, id });
            if (args[0] === "register-cli-scan") {
              expect(JSON.parse(input!).parentScanRole).toBe(
                args.includes("--parent-scan-id") ? "deep_pass" : undefined,
              );
              const scanId = result["scanId"] as string;
              // A rejoining native caller keeps the original saved recipe.
              registrations.set(scanId, {
                ...result,
                mode: (result["recipe"] as JsonObject)["mode"] as string,
              });
              workbenches.set(scanId, options);
              if (
                (result["recipe"] as JsonObject)["mode"] === "deep" &&
                (!prepareNative ||
                  hasInstructionScenario ||
                  queuedNativeKnowledge)
              ) {
                expect(
                  (result["recipe"] as JsonObject)["scanInputs"],
                ).toMatchObject({
                  ...(legacyInstructions || ambientInstruction !== undefined
                    ? {}
                    : { modelInstructionsFileSha256: instructionDigest }),
                });
                if (legacyInstructions)
                  expect(
                    (result["recipe"] as JsonObject)["scanInputs"],
                  ).not.toHaveProperty("modelInstructionsFileSha256");
              }
            }
            if (
              !interrupted &&
              (instructionCostRecovery ||
                instructionFile === "aggregate missing") &&
              args[0] === "save-scan-artifact" &&
              args.includes(DEEP_SCAN_CHECKPOINT)
            ) {
              const checkpoint = JSON.parse(input!);
              if (
                reducerInputRecovery
                  ? checkpoint.passes.some(
                      (pass: { completed?: boolean }) => pass.completed,
                    ) &&
                    checkpoint.mergeStarted !== true &&
                    checkpoint.aggregate === null
                  : instructionCostRecovery
                    ? checkpoint.mergedScanIds.length === 1 &&
                      checkpoint.passes.length === 1
                    : checkpoint.terminalReason !== undefined &&
                      checkpoint.aggregate !== null
              ) {
                interrupted = true;
                controller.abort(
                  new ScanTransportClosedError("mcp_transport_closed"),
                );
              }
            }
            if (
              instructionFile === "sealed child missing" &&
              !interrupted &&
              args[0] === "prepare-scan-completion" &&
              registrations.get(id!)?.["mode"] === "standard"
            ) {
              interrupted = true;
              controller.abort(
                new ScanTransportClosedError("mcp_transport_closed"),
              );
            }
            if (
              instructionFile === "later reducer changed" &&
              continuedInstructionExecution &&
              args[0] === "complete-scan" &&
              registrations.get(id!)?.["mode"] === "standard"
            )
              await writeFile(
                instructionPath,
                "Changed synthetic model instructions.\n",
              );
            if (
              instructionFile === "postscan changed" &&
              args[0] === "complete-scan" &&
              id === registeredScan!.scanId
            ) {
              await writeFile(
                instructionPath,
                "Changed synthetic model instructions.\n",
              );
            }
            if (args[0] === "get-cli-scan-resume")
              workbenches.set(result["scanId"] as string, options);
            if (
              ownerResume &&
              !interrupted &&
              args[0] === "prepare-scan-completion" &&
              registrations.get(id!)?.["mode"] === "deep"
            ) {
              interrupted = true;
              controller.abort(
                new ScanTransportClosedError("mcp_transport_closed"),
              );
            }
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
                environment.OPENAI_API_KEY,
              );
              expect(options.env?.["CODEX_API_KEY"]).toBe(
                environment.CODEX_API_KEY,
              );
            }
            const env = options.env!;
            expect(env["SYNTHETIC_SCAN_SETTING"]).toBe("inherited");
            if (!native) expect(env["CODEX_MCP_NODE_PATH"]).toBe(runtimeNode);
            const id = env["CODEX_SECURITY_SCAN_ID"]!;
            const makeThread = (
              threadOptions: ThreadOptions,
              savedThreadId: string | null = null,
            ) => {
              threadCount += 1;
              const thread = {
                id: savedThreadId,
                async runStreamed(prompt: string, turnOptions?: TurnOptions) {
                  expect(
                    (
                      turnOptions as TurnOptions & {
                        cyberAccessProgram?: string;
                      }
                    )?.cyberAccessProgram,
                  ).toBe("daybreak_blue");
                  expect(options.config).toMatchObject({
                    service_tier: "priority",
                  });
                  if (queuedNativeKnowledge) {
                    expect(
                      await readFile(
                        join(
                          env["CODEX_SECURITY_KNOWLEDGE_BASE"]!,
                          "0-architecture.md.txt",
                        ),
                        "utf8",
                      ),
                    ).toBe("Original synthetic architecture.\n");
                    if (knowledgeBytes !== undefined)
                      expect(
                        await readFile(
                          join(scanDir, ".scan-knowledge.json"),
                          "utf8",
                        ),
                      ).toBe(knowledgeBytes);
                  }
                  const record = registrations.get(id)!;
                  const mode = record["mode"] as string;
                  if (hasInstructionScenario) {
                    if (mode === "standard" && instructionCostRecovery) {
                      const checkpoint = JSON.parse(
                        await readFile(
                          join(scanDir, DEEP_SCAN_CHECKPOINT),
                          "utf8",
                        ),
                      );
                      expect(
                        checkpoint.passes.find(
                          (pass: { scanId: string }) => pass.scanId === id,
                        ),
                      ).not.toHaveProperty("executionNotStarted");
                    }
                    const child = childProcess.spawnSync(
                      runtimeNode,
                      [
                        "-e",
                        ambientInstruction === undefined
                          ? instructionProbe
                          : ambientInstructionProbe,
                        ...(ambientInstruction === undefined
                          ? [
                              options.config![
                                "model_instructions_file"
                              ] as string,
                            ]
                          : [
                              JSON.stringify(options.config),
                              createRequire(import.meta.url).resolve(
                                "smol-toml",
                              ),
                            ]),
                      ],
                      {
                        cwd: threadOptions.workingDirectory!,
                        env: options.env,
                        encoding: "utf8",
                      },
                    );
                    expect(child.error).toBeUndefined();
                    const observed = JSON.parse(child.stdout);
                    if (ambientInstruction === undefined)
                      expect(observed.path).toBe(instructionPath);
                    if (ambientInstruction !== undefined)
                      expect(options.config).not.toHaveProperty(
                        "model_instructions_file",
                      );
                    instructionExecutions.push({
                      scanId: id,
                      mode,
                      resumed: savedThreadId !== null,
                      continued: continuedInstructionExecution,
                      followUp: prompt === "Post-scan instructions once.",
                      ...observed,
                    });
                    if (child.status !== 0)
                      throw new Error(observed.error.message);
                  }
                  let groups: Array<{
                    sourceFindingIds: string[];
                    canonicalSourceFindingId: string;
                  }> = [];
                  if (
                    mode === "deep" &&
                    prompt !== "Post-scan instructions once."
                  ) {
                    mergeAttempts += 1;
                    const saved = await runWorkbench(workbenches.get(id)!, [
                      "get-scan",
                      "--scan-id",
                      id,
                    ]);
                    // These merges feed the next discovery stop decision.
                    const pendingCheckpoint = JSON.parse(
                      await readFile(
                        join(scanDir, DEEP_SCAN_CHECKPOINT),
                        "utf8",
                      ),
                    );
                    expect(pendingCheckpoint.terminalReason).toBeUndefined();
                    expect(
                      (saved["scan"] as JsonObject)["progress"],
                    ).toMatchObject({
                      phase: "discovery",
                      status: "running",
                      independentReviews: { active: 0, consolidating: false },
                    });
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
                    expect(payload.findings.length).toBeGreaterThan(0);
                    const sourceFindingIds = payload.sources.map(
                      (source: { id: string }) => source.id,
                    );
                    for (const source of sourceFindingIds)
                      expect(
                        registrations.get(source.split(":")[0]),
                      ).toMatchObject({ mode: "standard" });
                    groups = [
                      {
                        sourceFindingIds,
                        canonicalSourceFindingId: sourceFindingIds[0],
                      },
                    ];
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
                    const {
                      model_providers: providerDefinitions,
                      responses_api_metadata,
                      projects: _privateProjects,
                      ...publicSettings
                    } = nativeSettings;
                    expect(options.config).toMatchObject({
                      ...publicSettings,
                      ...expectedSettings(),
                    });
                    expect(
                      requestMetadata(options.configOverrides),
                    ).toMatchObject(responses_api_metadata);
                    if (providerDefinitions !== undefined) {
                      expect(options.config).not.toHaveProperty(
                        "model_providers",
                      );
                      const profile = parseToml(
                        await readFile(
                          join(
                            codexHome,
                            `${options.nativeProfile}.config.toml`,
                          ),
                          "utf8",
                        ),
                      );
                      expect(profile).toMatchObject({
                        model_providers: providerDefinitions,
                      });
                    }
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
                          tokenUsageEvent({
                            input_tokens: 10,
                            output_tokens: 3,
                          }),
                        ]
                          .map((event) => JSON.stringify(event))
                          .join("\n") + "\n",
                      );
                    }
                    yield { type: "thread.started", thread_id: thread.id };
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
                        !instructionCostRecovery &&
                        instructionFile !== "aggregate missing" &&
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
                          JSON.stringify(
                            tokenUsageEvent({
                              input_tokens: 10,
                              output_tokens: 3,
                            }),
                          ) + "\n",
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
                      const draft: SemanticScan = {
                        scanId: id,
                        ...(partialCheckpoint ? { complete: false } : {}),
                        findings: childFindings as SemanticFinding[],
                        coverage: {
                          surfaces: [],
                          explicitExclusions: [],
                          deferred: partialCheckpoint
                            ? [
                                {
                                  id: "pending-candidate",
                                  candidateId: "pending-candidate",
                                  reason:
                                    "Independent source validation is pending.",
                                  candidate: pendingCandidate!,
                                },
                              ]
                            : [],
                        },
                      };
                      if (partialCheckpoint) {
                        const documents = prepareSemanticScanDraft(
                          {
                            targetContract: record["contract"] as JsonObject,
                            mode: "standard",
                            targetRevision: record["targetRevision"] as string,
                          },
                          draft,
                        );
                        checkpointSignal = turnOptions!.signal;
                        // A Deep discovery worker has no workbench MCP. Its
                        // ordinary unsealed files must survive interruption.
                        await Promise.all([
                          writeFile(
                            join(directory, "scan-manifest.json"),
                            JSON.stringify({
                              scan: { ...documents.manifest.scan, id },
                            }),
                          ),
                          writeFile(
                            join(directory, "findings.json"),
                            JSON.stringify({
                              ...documents.findings,
                              scanId: id,
                            }),
                          ),
                          writeFile(
                            join(directory, "coverage.json"),
                            JSON.stringify({
                              ...documents.coverage,
                              scanId: id,
                            }),
                          ),
                          appendFile(
                            join(
                              sessionHome,
                              "sessions",
                              `rollout-${thread.id}.jsonl`,
                            ),
                            JSON.stringify(
                              tokenUsageEvent({
                                input_tokens: 10,
                                output_tokens: 3,
                              }),
                            ) + "\n",
                          ),
                        ]);
                        if (completedCleanup) {
                          try {
                            yield {
                              type: "turn.completed",
                              usage: {
                                input_tokens: 10,
                                cached_input_tokens: 0,
                                cache_write_input_tokens: 0,
                                output_tokens: 3,
                                reasoning_output_tokens: 0,
                              },
                            };
                          } finally {
                            controller.abort(
                              new Error("Synthetic user cancellation"),
                            );
                          }
                          return;
                        }
                        if (native) {
                          // Native cancellation records the stop before draining SDK work.
                          await runWorkbench(commandOptions, [
                            "cancel-scan",
                            "--scan-id",
                            registeredScan!.scanId,
                            "--defer-publication",
                            "--thread-id",
                            registeredScan!.threadId,
                          ]);
                        }
                        controller.abort(
                          new Error("Synthetic user cancellation"),
                        );
                        throw controller.signal.reason;
                      }
                      await publishDraft(
                        (args) => runWorkbench(workbenches.get(id)!, [...args]),
                        record,
                        "standard",
                        draft,
                      );
                    }
                    yield {
                      type: "item.completed",
                      item: {
                        id: "response",
                        type: "agent_message",
                        text:
                          mode === "deep"
                            ? JSON.stringify({ scanId: id, groups })
                            : "Complete",
                      },
                    };
                    yield {
                      type: "turn.completed",
                      usage: {
                        input_tokens:
                          budget &&
                          mode === "standard" &&
                          childTurns === (firstChildBudget ? 1 : 2)
                            ? 100000
                            : 10,
                        cached_input_tokens: 0,
                        output_tokens: 3,
                        cache_write_input_tokens: 0,
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
    const deepProgressUpdates: Array<
      Parameters<NonNullable<ScanOptions["onDeepProgress"]>>[0]
    > = [];
    const progressObserverErrors: unknown[] = [];
    const progressObserverFailure = new Error(
      "synthetic progress observer failure",
    );
    const ownerSpy = ownerOutcome
      ? spyOn(ownerArtifacts, "writeScanOwnerSuggestions").mockImplementation(
          async (_repository, result, writer, options) => {
            expect(result.coverage.mode).toBe("deep_repository");
            expect(result.findings.findings).toHaveLength(1);
            expect(
              options.config?.codexOverrides?.["responses_api_metadata"],
            ).toMatchObject({ codex_security_scan_mode: "deep" });
            expect(options.codex).toBeUndefined();
            expect(options.createCodex).toBeUndefined();
            expect(
              result.findings.findings[0]!.extensions?.["ownerSuggestion"],
            ).toEqual(ownerSuggestion);
            if (ownerOutcome === "failure")
              throw new Error("Synthetic composed owner failure");
            await writer.restore("owner-suggestions.json", Buffer.from("{}\n"));
            return join(result.scanDir, "owner-suggestions.json");
          },
        )
      : undefined;
    try {
      const scanOptions: ScanOptions = {
        mode: "deep",
        ownerSuggestions: ownerOutcome ? true : undefined,
        cyberAccessProgram: "daybreak_blue",
        preserveProviderEnvironment: provider !== undefined,
        workers: 1,
        subagents: 3,
        stopAfterNoNew: 1,
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
          : requiredCost
            ? { maxCostUsd: 1 }
            : {}),
        postScanPrompt:
          (missingReplay && missingReplay !== "follow-up") ||
          instructionFile === "sealed child missing"
            ? ""
            : "Post-scan instructions once.",
        onDeepProgress: (update) => {
          deepProgressUpdates.push(update);
          throw progressObserverFailure;
        },
        onObserverError: (observer, error) => {
          if (observer === "onDeepProgress") progressObserverErrors.push(error);
        },
        onProgress: (update) => progress.push(update),
        onActivity: (activity) => workerRun.activities.push(activity),
        onSessionEvent: (event) => workerRun.sessions.push(event),
      };
      const run = () => {
        progress = [];
        progressRuns.push(progress);
        workerRun = { threads: new Set(), activities: [], sessions: [] };
        workerRuns.push(workerRun);
        return client.run(repo, {
          ...scanOptions,
          ...nativeOptions,
          ...(instructionCostRecovery
            ? { maxCostUsd: 1, requireCost: true }
            : {}),
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
      if (firstChildBudget || partialCheckpoint) {
        await expect(run()).rejects.toBeInstanceOf(
          partialCheckpoint ? ScanInterruptedError : ScanCostLimitExceededError,
        );
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
        expect(saved["scan"]).toMatchObject({
          progress: { status: partialCheckpoint ? "canceled" : "failed" },
        });
        const child = [...registrations.values()].find(
          ({ mode }) => mode === "standard",
        )!;
        const savedChild = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          child["scanId"] as string,
        ]);
        const childCost = (savedChild["scan"] as JsonObject)["cost"];
        expect(childCost).toBeDefined();
        expect((saved["scan"] as JsonObject)["cost"]).toEqual(childCost);
        expect(
          JSON.parse(
            await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
          ),
        ).toMatchObject({
          ...(native
            ? {}
            : { terminalReason: partialCheckpoint ? "canceled" : "capped" }),
          aggregate: null,
          mergedScanIds: [],
        });
        const findings = JSON.parse(
          await readFile(join(scanDir, "findings.json"), "utf8"),
        ).findings;
        expect(findings).toHaveLength(1);
        expect(findings[0]).toMatchObject(childFindings[0]!);
        const coverage = JSON.parse(
          await readFile(join(scanDir, "coverage.json"), "utf8"),
        );
        expect(coverage).not.toHaveProperty("completeness");
        if (partialCheckpoint) {
          expect(controller.signal.aborted).toBe(true);
          expect(checkpointSignal!.aborted).toBe(!completedCleanup);
          expect(
            commands.filter(
              ({ command }) =>
                command === "complete-scan" || command === "write-scan-draft",
            ),
          ).toEqual([]);
          expect((childCost as JsonObject)["estimatedUsd"]).toBeGreaterThan(0);
          expect(findings[0].provenance.sourceFindings).toHaveLength(1);
          expect(findings[0].provenance.sourceFindings[0]).toMatchObject({
            id: `${child["scanId"]}:0`,
            finding: childFindings[0],
          });
          expect(coverage.deferred).toContainEqual(
            expect.objectContaining({
              id: `${child["scanId"]}/pending-candidate`,
              candidateId: expect.stringMatching(
                new RegExp(`^${child["scanId"]}:`),
              ),
              sourceCandidateId: "pending-candidate",
              reason: "Independent source validation is pending.",
              candidate: pendingCandidate,
            }),
          );
          // Check the model-facing file contract, not exact instruction wording.
          for (const field of [
            "scan.complete",
            "coverage.deferred",
            "candidateId",
          ])
            expect(turns[0]!.prompt).toContain(field);
        }
        return;
      }
      if (
        instructionCostRecovery ||
        instructionFile === "aggregate missing" ||
        instructionFile === "sealed child missing"
      ) {
        await expect(run()).rejects.toBeInstanceOf(ScanTransportClosedError);
        const scanId = registeredScan!.scanId;
        const checkpointPath = join(scanDir, DEEP_SCAN_CHECKPOINT);
        const interruptedCheckpoint = JSON.parse(
          await readFile(checkpointPath, "utf8"),
        );
        const before = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          scanId,
        ]);
        expect(before["scan"]).toMatchObject({
          progress: { status: "running" },
        });
        expect(
          instructionExecutions.every(
            (sample) =>
              sample.bytes ===
              (ambientInstruction === undefined ? instructionText : null),
          ),
        ).toBe(true);
        expect(interruptedCheckpoint.passes.length).toBeGreaterThan(0);
        const acceptedChildCosts = new Map<string, unknown>();
        for (const pass of interruptedCheckpoint.passes) {
          if (pass.scanId === undefined) continue;
          const child = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            pass.scanId,
          ]);
          expect(child["scan"]).toMatchObject({
            progress: {
              status:
                instructionFile === "sealed child missing"
                  ? "running"
                  : "complete",
            },
          });
          acceptedChildCosts.set(
            pass.scanId,
            (child["scan"] as JsonObject)["cost"],
          );
          expect(
            ((child["scan"] as JsonObject)["cost"] as JsonObject)[
              "estimatedUsd"
            ],
          ).toBeGreaterThan(0);
          if (instructionFile === "sealed child missing") {
            const manifest = JSON.parse(
              await readFile(
                join(
                  (child["scan"] as JsonObject)["scanDir"] as string,
                  "scan-manifest.json",
                ),
                "utf8",
              ),
            );
            expect(manifest.scan.sealedAt).toBeDefined();
          }
        }
        if (instructionCostRecovery) {
          if (reducerInputRecovery) {
            expect(interruptedCheckpoint).toMatchObject({
              aggregate: null,
              mergedScanIds: [],
            });
            expect(interruptedCheckpoint.mergeStarted).not.toBe(true);
            expect(
              existsSync(
                join(scanDir, "artifacts/deep-scan/merge-inputs.json"),
              ),
            ).toBe(false);
            expect(turns.map(({ mode }) => mode)).toEqual(["standard"]);
            expect(
              (before["scan"] as JsonObject)["continuationThreadId"],
            ).toBeNull();
          } else {
            expect(interruptedCheckpoint.passes).toHaveLength(2);
            expect(interruptedCheckpoint.passes[1].scanId).toBeUndefined();
            expect(interruptedCheckpoint.mergedScanIds).toEqual([
              interruptedCheckpoint.passes[0].scanId,
            ]);
            expect(interruptedCheckpoint.aggregate).not.toBeNull();
            expect(turns.map(({ mode }) => mode)).toEqual(["standard", "deep"]);
          }
          if (ambientInstruction !== undefined) {
            if (ambientInstruction !== "unchanged") {
              ambientConfig = stringifyToml({
                ...nativeSettings,
                model_instructions_file: relative(codexHome, instructionPath),
              });
              await writeFile(join(codexHome, "config.toml"), ambientConfig);
            }
          } else {
            await writeFile(
              instructionPath,
              "Changed synthetic model instructions.\n",
            );
          }
        } else {
          if (instructionFile === "aggregate missing") {
            expect(interruptedCheckpoint.aggregate).not.toBeNull();
            expect(interruptedCheckpoint.terminalReason).toBeDefined();
            const manifest = JSON.parse(
              await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
            );
            expect(manifest.scan.sealedAt).toBeUndefined();
          }
          await rm(instructionPath);
        }
        controller = new AbortController();
        await client.close();
        nativeRecipe = (
          await runWorkbench(commandOptions, [
            "get-scan-recipe",
            "--scan-id",
            scanId,
          ])
        )["recipe"] as JsonObject;
        if (instructionFile === "aggregate missing")
          nativeRecipe["postScanPrompt"] = "";
        continuedInstructionExecution = true;
        client = await makeClient();
        const countBefore = instructionExecutions.length;
        const commandsBefore = commands.length;
        let rejectedChildId: string | undefined;
        if (
          instructionCostRecovery &&
          (ambientInstruction === undefined ||
            ambientInstruction === "introduced")
        ) {
          await expect(run()).rejects.toBeInstanceOf(DeepScanRecoveryError);
          expect(instructionExecutions).toHaveLength(countBefore);
          const rejectedCheckpoint = JSON.parse(
            await readFile(checkpointPath, "utf8"),
          );
          if (reducerInputRecovery) {
            expect(rejectedCheckpoint).toMatchObject({
              aggregate: null,
              mergedScanIds: [],
            });
            expect(rejectedCheckpoint.mergeStarted).toBe(
              interruptedCheckpoint.mergeStarted,
            );
            expect(
              existsSync(
                join(scanDir, "artifacts/deep-scan/merge-inputs.json"),
              ),
            ).toBe(false);
            await expect(run()).rejects.toBeInstanceOf(DeepScanRecoveryError);
            expect(instructionExecutions).toHaveLength(countBefore);
            const repeatedCheckpoint = JSON.parse(
              await readFile(checkpointPath, "utf8"),
            );
            expect(repeatedCheckpoint.mergeStarted).toBe(
              interruptedCheckpoint.mergeStarted,
            );
            expect(repeatedCheckpoint.aggregate).toBeNull();
            expect(repeatedCheckpoint.mergedScanIds).toEqual([]);
            expect(
              existsSync(
                join(scanDir, "artifacts/deep-scan/merge-inputs.json"),
              ),
            ).toBe(false);
          } else {
            expect(rejectedCheckpoint.passes).toHaveLength(2);
            expect(rejectedCheckpoint.aggregate).toEqual(
              interruptedCheckpoint.aggregate,
            );
            expect(rejectedCheckpoint.mergedScanIds).toEqual(
              interruptedCheckpoint.mergedScanIds,
            );
            rejectedChildId = rejectedCheckpoint.passes[1].scanId;
            expect(rejectedChildId).toBeDefined();
            expect(rejectedCheckpoint.passes[1].executionNotStarted).toBe(true);
            const rejectedChild = await runWorkbench(commandOptions, [
              "get-scan",
              "--scan-id",
              rejectedChildId!,
            ]);
            expect(rejectedChild["scan"]).toMatchObject({
              progress: { status: "running" },
              continuationThreadId: null,
            });
            await expect(run()).rejects.toBeInstanceOf(DeepScanRecoveryError);
            expect(instructionExecutions).toHaveLength(countBefore);
            const repeatedCheckpoint = JSON.parse(
              await readFile(checkpointPath, "utf8"),
            );
            expect(repeatedCheckpoint.passes[1]).toMatchObject({
              scanId: rejectedChildId,
              executionNotStarted: true,
            });
            expect(repeatedCheckpoint.aggregate).toEqual(
              interruptedCheckpoint.aggregate,
            );
          }
          const blocked = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            scanId,
          ]);
          expect(blocked["scan"]).toMatchObject({
            progress: { status: "running" },
          });
          expect(
            commands
              .slice(commandsBefore)
              .filter(
                ({ command }) =>
                  command === "fail-scan" || command === "cancel-scan",
              ),
          ).toEqual([]);
          if (ambientInstruction === "introduced") {
            ambientConfig = stringifyToml(nativeSettings);
            await writeFile(join(codexHome, "config.toml"), ambientConfig);
          } else await writeFile(instructionPath, instructionText);
        }
        const result = await run();
        expect(result.manifest.scan.id).toBe(scanId);
        if (instructionCostRecovery)
          expect(result.cost!.estimatedUsd).toBeGreaterThan(0);
        for (const [childId, cost] of acceptedChildCosts) {
          const savedChild = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            childId,
          ]);
          expect(savedChild["scan"]).toMatchObject({
            progress: { status: "complete" },
            cost,
          });
        }
        if (rejectedChildId !== undefined) {
          const restoredChild = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            rejectedChildId,
          ]);
          expect(restoredChild["scan"]).toMatchObject({
            progress: { status: "complete" },
          });
          const finalCheckpoint = JSON.parse(
            await readFile(checkpointPath, "utf8"),
          );
          expect(
            finalCheckpoint.passes.find(
              (pass: { scanId: string }) => pass.scanId === rejectedChildId,
            ),
          ).not.toHaveProperty("executionNotStarted");
        }
        if (
          instructionFile === "aggregate missing" ||
          instructionFile === "sealed child missing"
        ) {
          expect(instructionExecutions).toHaveLength(countBefore);
          expect(existsSync(instructionPath)).toBe(false);
        } else {
          expect(instructionExecutions.length).toBeGreaterThan(countBefore);
          expect(
            instructionExecutions
              .slice(countBefore)
              .every(
                (sample) =>
                  sample.bytes ===
                  (ambientInstruction === undefined ||
                  ambientInstruction === "legacy"
                    ? instructionText
                    : null),
              ),
          ).toBe(true);
          expect(instructionExecutions[countBefore]!.mode).toBe(
            reducerInputRecovery ? "deep" : "standard",
          );
        }
        const recipe = (
          await runWorkbench(commandOptions, [
            "get-scan-recipe",
            "--scan-id",
            scanId,
          ])
        )["recipe"] as JsonObject;
        if (ambientInstruction === "legacy")
          expect(recipe["scanInputs"]).not.toHaveProperty(
            "modelInstructionsFileSha256",
          );
        else
          expect(recipe["scanInputs"]).toMatchObject({
            modelInstructionsFileSha256:
              ambientInstruction === undefined ? instructionDigest : null,
          });
        if (ambientInstruction !== undefined)
          expect(recipe["config"]).not.toHaveProperty(
            "model_instructions_file",
          );
        const complete = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          scanId,
        ]);
        expect(complete["scan"]).toMatchObject({
          progress: { status: "complete" },
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
            noNewStreak: 0,
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
        if (queuedNativeKnowledge)
          knowledgeBytes = await readFile(
            join(scanDir, ".scan-knowledge.json"),
            "utf8",
          );
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
          expect(
            await restoreReplayProfile(
              nativeRecipe["config"] as JsonObject,
              nativeRecipe["replayProfile"],
              environment,
            ),
          ).toMatchObject({
            ...nativeSettings,
            model_instructions_file:
              instructionPathForm === "home"
                ? "~/instructions.md"
                : instructionPathForm === undefined
                  ? instructionPath
                  : relative(scanDir, instructionPath),
          });
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
        if (missingReplay) {
          const resumed = await runWorkbench(commandOptions, [
            "begin-deep-scan",
            "--scan-id",
            registeredScan!.scanId,
            "--thread-id",
            registeredScan!.threadId,
            "--claim-token",
            registeredScan!.handoffClaimToken!,
          ]);
          const recipe = resumed["recipe"] as JsonObject;
          const reference = recipe["replayProfile"] as JsonObject;
          expect(reference["home"]).toBe("ambient");
          expect(typeof reference["name"]).toBe("string");
          const privatePath = join(
            codexHome,
            `${reference["name"]}.config.toml`,
          );
          expect(await readFile(privatePath, "utf8")).toContain(
            "synthetic-inline-private-provider-token",
          );
          const stored = await runWorkbench(commandOptions, [
            "get-cli-scan-resume",
            "--scan-id",
            registeredScan!.scanId,
            "--claim-token",
            registeredScan!.handoffClaimToken!,
          ]);
          expect(typeof stored["sealedProducerVersion"]).toBe(
            missingReplay === "unsealed" ? "undefined" : "string",
          );
          await rm(privatePath);
          const captured = Object.fromEntries(
            Object.keys(environment).map((key) => [key, process.env[key]]),
          );
          const count = turns.length;
          try {
            for (const [key, value] of Object.entries(environment)) {
              if (value === undefined) delete process.env[key];
              else process.env[key] = value;
            }
            const prepare = await nativeScanFactory();
            const preparation = prepare({
              scan: {
                ...(resumed["scan"] as JsonObject),
                ...(missingReplay === "wrong-claim"
                  ? { handoffClaimToken: randomUUID() }
                  : {}),
              },
              recipe,
              threadId: registeredScan!.threadId,
              pluginRoot,
              pythonPath: python,
              stateDirectory: environment.CODEX_SECURITY_STATE_DIR,
              parentSandbox: {
                workspaceAccess: "write",
                filesystemDenies: [join(root, "private")],
              },
            });
            if (missingReplay === "follow-up" || missingReplay === "unsealed") {
              await expect(preparation).rejects.toThrow("ENOENT");
            } else {
              const prepared = await preparation;
              await using resumedClient = new CodexSecurity(
                prepared.client.config,
                {
                  ...prepared.client.dependencies,
                  environment:
                    prepared.client.dependencies?.environment ?? environment,
                  prepareRuntime: async () => {
                    throw new Error("Publication must not prepare a runtime");
                  },
                  createCodex: () => {
                    throw new Error(
                      "Publication must not create a model client",
                    );
                  },
                },
                { surface: "sdk" },
              );
              const recovery = resumedClient.run(repo, prepared.options);
              if (missingReplay === "wrong-claim")
                await expect(recovery).rejects.toThrow(
                  /owned by another continuation/iu,
                );
              else {
                const restored = await recovery;
                expect(restored.findings.findings).toHaveLength(1);
                expect(restored.threadId).toBe(savedExecutionThread);
              }
            }
          } finally {
            for (const [key, value] of Object.entries(captured)) {
              if (value === undefined) delete process.env[key];
              else process.env[key] = value;
            }
          }
          expect(turns).toHaveLength(count);
          expect(
            (
              await runWorkbench(commandOptions, [
                "get-scan",
                "--scan-id",
                registeredScan!.scanId,
              ])
            )["scan"],
          ).toMatchObject({
            progress: {
              status: missingReplay === "publish" ? "complete" : "running",
            },
          });
          if (sealedArtifacts)
            for (const [path, bytes] of sealedArtifacts)
              expect(await readFile(join(scanDir, path))).toEqual(bytes);
          return;
        }
        if (
          instructionFile === "changed" ||
          instructionFile === "legacy changed"
        )
          await writeFile(
            instructionPath,
            "Changed synthetic model instructions.\n",
          );
        else if (instructionFile === "missing" || instructionFile === "empty")
          await rm(instructionPath);
        if (instructionFile !== undefined) continuedInstructionExecution = true;
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
          await rm(sessionPath);
          try {
            await expect(run()).rejects.toThrow("The original Codex session");
            expect([threadCount, turns.length]).toEqual(activityBefore);
            expect(await readFile(checkpointPath)).toEqual(checkpointBytes);
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
      let completedTurnsBeforeOwnerResume: number | undefined;
      if (ownerResume) {
        await expect(run()).rejects.toBeInstanceOf(ScanTransportClosedError);
        expect(ownerSpy).not.toHaveBeenCalled();
        const parent = [...registrations.values()].find(
          ({ mode }) => mode === "deep",
        )!;
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          parent["scanId"] as string,
        ]);
        expect(saved["scan"]).toMatchObject({
          progress: { status: "running" },
        });
        // Resume the sealed result after losing the completion transport, without a follow-up turn.
        scanOptions.resumeScanId = parent["scanId"] as string;
        scanOptions.postScanPrompt = "";
        controller = new AbortController();
        completedTurnsBeforeOwnerResume = turns.length;
        if (instructionFile === "sealed missing") {
          await rm(instructionPath);
          continuedInstructionExecution = true;
        }
      }
      if (
        instructionFile === "changed" ||
        instructionFile === "missing" ||
        instructionFile === "empty" ||
        instructionFile === "later reducer changed"
      ) {
        const scanId = registeredScan!.scanId;
        const checkpointPath = join(scanDir, DEEP_SCAN_CHECKPOINT);
        const checkpointBefore = JSON.parse(
          await readFile(checkpointPath, "utf8"),
        );
        const childrenBefore = await Promise.all(
          checkpointBefore.passes.map(async (pass: { scanId: string }) => {
            const saved = await runWorkbench(commandOptions, [
              "get-scan",
              "--scan-id",
              pass.scanId,
            ]);
            return saved["scan"] as JsonObject;
          }),
        );
        const executionsBefore = instructionExecutions.length;
        const commandsBefore = commands.length;
        let rejection: unknown;
        try {
          await run();
        } catch (error) {
          rejection = error;
        }
        expect(rejection).toBeInstanceOf(DeepScanRecoveryError);
        rejectedWorkerRuns.add(workerRuns.at(-1)!);
        if (instructionFile === "missing" || instructionFile === "empty") {
          expect((rejection as Error).message).toContain("ENOENT");
          expect((rejection as Error).message).toContain(instructionPath);
          expect((rejection as Error).cause).toMatchObject({
            code: "ENOENT",
            path: instructionPath,
          });
        }
        expect(instructionExecutions).toHaveLength(
          executionsBefore +
            (instructionFile === "later reducer changed" ? 1 : 0),
        );
        if (instructionFile === "later reducer changed")
          expect(instructionExecutions.at(-1)).toMatchObject({
            mode: "standard",
            resumed: true,
            bytes: instructionText,
          });
        expect(
          commands
            .slice(commandsBefore)
            .filter(
              ({ command }) =>
                command === "fail-scan" || command === "cancel-scan",
            ),
        ).toEqual([]);
        const parent = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          scanId,
        ]);
        expect(parent["scan"]).toMatchObject({
          continuationThreadId: savedExecutionThread,
          progress: { status: "running" },
        });
        const checkpointAfter = JSON.parse(
          await readFile(checkpointPath, "utf8"),
        );
        if (instructionFile === "later reducer changed") {
          expect(checkpointAfter.passes).toEqual(
            checkpointBefore.passes.map((pass: JsonObject) => ({
              ...pass,
              completed: true,
            })),
          );
        } else expect(checkpointAfter.passes).toEqual(checkpointBefore.passes);
        expect(checkpointAfter.mergedScanIds).toEqual(
          checkpointBefore.mergedScanIds,
        );
        expect(checkpointAfter.terminalReason).toBeUndefined();
        expect(checkpointAfter.aggregate).toEqual(checkpointBefore.aggregate);
        expect(checkpointAfter.mergeFailures).toBe(
          checkpointBefore.mergeFailures,
        );
        expect(checkpointAfter.consecutiveErrors).toBe(
          checkpointBefore.consecutiveErrors,
        );
        for (const child of childrenBefore) {
          const saved = await runWorkbench(commandOptions, [
            "get-scan",
            "--scan-id",
            child["scanId"] as string,
          ]);
          if (instructionFile === "later reducer changed")
            expect(saved["scan"]).toMatchObject({
              progress: { status: "complete" },
            });
          else
            expect((saved["scan"] as JsonObject)["progress"]).toEqual(
              child["progress"],
            );
        }
        const savedRecipe = await runWorkbench(commandOptions, [
          "get-scan-recipe",
          "--scan-id",
          scanId,
        ]);
        expect(
          (savedRecipe["recipe"] as JsonObject)["scanInputs"],
        ).toMatchObject({
          modelInstructionsFileSha256: instructionDigest,
        });
        await writeFile(instructionPath, instructionText);
      }
      const result = await run();
      if (instructionFile !== undefined && registeredScan)
        expect(result.manifest.scan.id).toBe(registeredScan.scanId);
      if (instructionFile !== undefined) {
        const initial = instructionExecutions.filter(
          (sample) => !sample.continued,
        );
        const continued = instructionExecutions.filter(
          (sample) => sample.continued,
        );
        expect(initial.length).toBeGreaterThan(0);
        expect(
          initial.every((sample) => sample.bytes === instructionText),
        ).toBe(true);
        if (instructionFile === "sealed missing")
          expect(continued).toHaveLength(0);
        else {
          expect(
            continued.some(
              (sample) => sample.mode === "standard" && sample.resumed,
            ),
          ).toBe(true);
          expect(
            continued.some(
              (sample) =>
                sample.mode === "deep" && sample.resumed && !sample.followUp,
            ),
          ).toBe(true);
          expect(
            continued.every(
              (sample) =>
                sample.bytes ===
                (instructionFile === "legacy changed" ||
                (instructionFile === "postscan changed" && sample.followUp)
                  ? "Changed synthetic model instructions.\n"
                  : instructionText),
            ),
          ).toBe(true);
        }
      }
      if (
        !prepareNative ||
        instructionFile !== undefined ||
        queuedNativeKnowledge
      ) {
        const savedRecipe = await runWorkbench(commandOptions, [
          "get-scan-recipe",
          "--scan-id",
          result.manifest.scan.id,
        ]);
        expect(
          (savedRecipe["recipe"] as JsonObject)["scanInputs"],
        ).toMatchObject({
          ...(instructionFile === "legacy changed"
            ? {}
            : { modelInstructionsFileSha256: instructionDigest }),
        });
        if (instructionFile === "legacy changed")
          expect(
            (savedRecipe["recipe"] as JsonObject)["scanInputs"],
          ).not.toHaveProperty("modelInstructionsFileSha256");
      }
      if (completedTurnsBeforeOwnerResume !== undefined)
        expect(turns).toHaveLength(completedTurnsBeforeOwnerResume);
      if (ownerOutcome) {
        expect(ownerSpy).toHaveBeenCalledTimes(1);
        expect(result.ownerSuggestionsPath).toBe(
          ownerOutcome === "success"
            ? join(scanDir, "owner-suggestions.json")
            : undefined,
        );
        expect(result.ownerSuggestionsError).toBe(
          ownerOutcome === "failure"
            ? "Synthetic composed owner failure"
            : undefined,
        );
        for (const registration of registrations.values()) {
          const recipe = registration["recipe"] as JsonObject;
          expect(recipe["ownerSuggestions"]).toBe(true);
        }
      }
      const knownWorkerThreads = new Set(
        workerRuns.flatMap(({ threads }) => [...threads]),
      );
      for (const observed of workerRuns) {
        const labels = new Map<string, number>();
        for (const event of observed.sessions) {
          if (!observed.threads.has(event.threadId)) {
            if (
              rejectedWorkerRuns.has(observed) &&
              event.worker !== undefined
            ) {
              // Recovering a prior child's cost replays its existing session events
              // even when validation rejects before another child executes.
              expect(knownWorkerThreads.has(event.threadId)).toBe(true);
              expect(event.worker).toBeGreaterThan(0);
            } else expect(event.worker).toBeUndefined();
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
      expect(deepProgressUpdates.length).toBeGreaterThan(0);
      expect(progressObserverErrors).toEqual(
        deepProgressUpdates.map(() => progressObserverFailure),
      );
      for (const updates of progressRuns) {
        const counts = updates.map((update) => update.filesCompleted);
        expect(counts).toEqual([...counts].sort((left, right) => left - right));
        expect(updates.every((update) => update.filesTotal === 4)).toBe(true);
        expect(Math.max(...counts)).toBeLessThanOrEqual(3);
      }
      expect(progressRuns.flat()).toContainEqual(
        expect.objectContaining({
          phase: "discovery",
          filesCompleted: 3,
          filesTotal: 4,
        }),
      );
      if (savedExecutionThread)
        expect(result.threadId).toBe(savedExecutionThread);
      if (sealedArtifacts) {
        for (const [path, bytes] of sealedArtifacts)
          expect(await readFile(join(scanDir, path))).toEqual(bytes);
        expect(result.manifest.scan.producer.version).toBe(version);
      }
      if (!budget)
        expect(progressRuns.flat()).toContainEqual(
          expect.objectContaining({ phase: "reporting" }),
        );
      expect(result.findings.findings).toHaveLength(budget ? 2 : 1);
      expect(result.coverage).not.toHaveProperty("completeness");
      const checkpoint = JSON.parse(
        await readFile(join(scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
      );
      expect(checkpoint.terminalReason).toBe(budget ? "capped" : "saturated");
      expect(checkpoint.noNewStreak).toBe(budget ? 0 : 1);
      expect(checkpoint.passes).toHaveLength(2);
      expect(checkpoint.mergedScanIds).toHaveLength(budget ? 1 : 2);
      expect(registrations.size).toBe(3);
      if (prepareNative) {
        for (const registration of registrations.values()) {
          const saved = registration["recipe"] as JsonObject;
          expect(JSON.stringify(saved)).not.toContain(
            "synthetic-private-mcp-token",
          );
          expect(saved["config"]).not.toHaveProperty("mcp_servers");
          expect(
            (
              await restoreReplayProfile(
                saved["config"] as JsonObject,
                saved["replayProfile"],
                environment,
              )
            )["mcp_servers"],
          ).toMatchObject(nativeSettings.mcp_servers);
        }
      }
      if (provider !== undefined) {
        for (const registration of registrations.values()) {
          const saved = registration["recipe"] as JsonObject;
          expect(JSON.stringify(saved)).not.toContain(
            "synthetic-inline-private-provider-token",
          );
          expect(saved["preserveProviderEnvironment"]).toBe(true);
          expect(saved["config"]).not.toHaveProperty("model_providers");
          const restored = await restoreReplayProfile(
            saved["config"] as JsonObject,
            saved["replayProfile"],
            environment,
          );
          expect(restored["model_providers"]).toMatchObject({
            custom: provider,
          });
          expect(
            (saved["config"] as JsonObject)["cli_auth_credentials_store"],
          ).toBe("file");
        }
        expect(environment.OPENAI_API_KEY).toBe(
          customProvider ? undefined : "synthetic-provider-key",
        );
        expect(environment.CODEX_API_KEY).toBe(
          customProvider ? undefined : "synthetic-native-key",
        );
      }
      for (const turn of turns) {
        expect(turn.config).toMatchObject(expectedSettings());
        expect(turn.config).not.toHaveProperty("projects");
        expect(
          turn.overrides?.filter((value) => /^projects[.=]/.test(value)),
        ).toEqual([]);
        expect(requestMetadata(turn.overrides)).toMatchObject(
          inheritedMetadata,
        );
        expect(turn.environment["CODEX_SQLITE_HOME"]).toBe(
          join(scanDir, "sqlite"),
        );
        const servers = (turn.config as JsonObject | undefined)?.[
          "mcp_servers"
        ] as JsonObject | undefined;
        expect(servers?.["codex-security"]).toEqual({
          command: "node",
          enabled: false,
        });
        if (prepareNative) {
          expect(servers?.["synthetic"]).toEqual(
            nativeSettings.mcp_servers.synthetic,
          );
          expect(servers?.["authenticated"]).toEqual(
            nativeSettings.mcp_servers.authenticated,
          );
        }
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
        expect(turn.environment["CODEX_SECURITY_GIT"]).toMatch(
          /git(?:\.exe)?$/iu,
        );
        expect(turn.environment["GIT_SSH_COMMAND"]).toBe(
          environment.GIT_SSH_COMMAND,
        );
        expect(turn.environment["GIT_CONFIG_GLOBAL"]).toBe(
          environment.GIT_CONFIG_GLOBAL,
        );
        expect(turn.environment["CODEX_SAFETY_IDENTIFIER"]).toBe(
          native && !prepareNative
            ? "saved-native-identifier"
            : customProvider
              ? "ambient-identifier"
              : undefined,
        );
        if (customProvider) {
          expect(turn.environment["PROVIDER_KEY"]).toBe(
            "synthetic-provider-key",
          );
          expect(turn.environment).not.toHaveProperty("OPENAI_API_KEY");
          expect(turn.environment).not.toHaveProperty("CODEX_API_KEY");
        }
      }
      const children = turns.filter((turn) => turn.mode === "standard");
      const configByChild = new Map(
        children.map((turn) => [
          turn.id,
          turn.environment["CODEX_SECURITY_CONFIG_PATH"],
        ]),
      );
      if (prepareNative) {
        for (const config of configByChild.values())
          expect(config).toBeDefined();
        expect(new Set(configByChild.values()).size).toBe(configByChild.size);
      }
      expect(children).toHaveLength(native === "discovery" ? 3 : 2);
      expect(new Set(children.map((turn) => turn.id)).size).toBe(2);
      if (prepareNative) {
        if (customProvider) {
          expect(existsSync(accountLog)).toBe(false);
          expect(nativeRecipe!["safetyIdentifier"]).toBe("ambient-identifier");
        } else {
          expect(nativeRecipe).not.toHaveProperty("safetyIdentifier");
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
        }
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
        expect(result.cost!.estimatedUsd).toBeGreaterThan(0);
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
        expect(child.prompt.includes("extensions.ownerSuggestion")).toBe(
          ownerOutcome !== undefined,
        );
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
      ).toHaveLength(budget || ownerResume ? 0 : 1);
      if (!budget && !ownerResume) {
        const saved = await runWorkbench(commandOptions, [
          "get-scan",
          "--scan-id",
          result.manifest.scan.id,
        ]);
        const scan = saved["scan"] as ScanLogSource;
        expect(scan.continuationThreadId).toBe(result.threadId!);
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
      expect(listedIds).toHaveLength(1);
    } finally {
      try {
        await client.close();
      } finally {
        loginSpawn?.mockRestore();
        ownerSpy?.mockRestore();
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

type WorkbenchCommandOptions = Omit<
  RequiredWorkbenchCommandOptions,
  "python"
> & { python?: string };
