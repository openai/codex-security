import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { readJson } from "./support/json.ts";
import { assertFlagPair } from "./assertions.ts";
import type { CodexSdkWorkerExecutor as WorkerExecutor } from "../src/deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";

export async function testWorkerSelectedProfileFiles<Profile>({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  deniedWorkerPermissionProfile,
  trustedParentSandboxWithDenials,
  workerPermissionProfileOverride,
  assertConfigOverrides,
  assertReadOnlyWorkerPolicy,
  assertWorkerSubagentPolicy,
  restoreEnv,
}: {
  CodexSdkWorkerExecutor: typeof WorkerExecutor;
  fakeCodexFixture: (
    profile: Profile,
    allowed: boolean,
    account: { account: null; requiresOpenaiAuth: boolean },
  ) => Promise<{ root: string; executablePath: string }>;
  deniedWorkerPermissionProfile: Profile;
  trustedParentSandboxWithDenials: DeepWorkerParentSandbox;
  workerPermissionProfileOverride: (
    args: readonly string[],
  ) => string | undefined;
  assertConfigOverrides: (
    args: readonly string[],
    values: Record<string, string | string[] | number | boolean | undefined>,
  ) => void;
  assertReadOnlyWorkerPolicy: (args: readonly string[]) => void;
  assertWorkerSubagentPolicy: (
    args: readonly string[],
    subagents: number,
    codeMode?: { enabled: boolean; excluded_tool_namespaces: string[] },
  ) => void;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  const cases: [string, string | undefined, boolean?][] = [
    ["", undefined],
    ['model_reasoning_summary = "none"\n', "none"],
    ['model_reasoning_summary = "auto"\n', "auto"],
    [
      'model = "native-model"\nmodel_reasoning_summary = "concise"\n',
      "concise",
    ],
    [
      'model_reasoning_summary = "none"\nprofile = "selected"\n[profiles.selected]\nmodel_reasoning_summary = "concise"\n',
      "concise",
    ],
    [
      'model_reasoning_summary = "none"\nprofile = "selected"\n[profiles.selected]\nmodel = "fixture-model"\n[profiles.other]\nmodel_reasoning_summary = "detailed"\n',
      "none",
    ],
    [
      'model_reasoning_summary = "concise"\n[features]\nshell_tool = false\nunified_exec = false\n',
      "concise",
      true,
    ],
    [
      'model_reasoning_summary = "concise"\nmodel_instructions_file = "profile-instructions.md"\nmodel_verbosity = "high"\nweb_search = "disabled"\n[features]\nshell_tool = false\nunified_exec = false\n',
      "concise",
      true,
    ],
    [
      'model_reasoning_summary = "concise"\nmodel_instructions_file = "profile-instructions.md"\nmodel_catalog_json = "profile-catalog.json"\nexperimental_compact_prompt_file = "profile-compact.md"\nmodel_verbosity = "high"\nweb_search = "disabled"\n',
      "concise",
    ],
    [
      'model_reasoning_summary = "concise"\n[features.code_mode]\nenabled = true\nexcluded_tool_namespaces = ["synthetic_tools"]\n',
      "concise",
    ],
    [
      'model_reasoning_summary = "concise"\nmodel_instructions_file = "relative-instructions.md"\nmodel_verbosity = "high"\nweb_search = "disabled"\n',
      "concise",
    ],
  ];
  const saved = [
    "PYTHON",
    "PATH",
    "CODEX_SECURITY_GIT",
    "GIT_SSH_COMMAND",
    "GIT_CONFIG_GLOBAL",
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_SCAN_DIR",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "SYNTHETIC_GATEWAY_KEY",
  ].map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  try {
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_API_KEY;
    for (const [configuration, expected, commandAuth] of cases) {
      const fixture = await fakeCodexFixture(
        deniedWorkerPermissionProfile,
        true,
        { account: null, requiresOpenaiAuth: false },
      );
      const python = path.join(fixture.root, "selected venv", "bin", "python");
      const helperPython = path.join(
        fixture.root,
        "helper venv",
        "bin",
        "python",
      );
      process.env.PYTHON = python;
      const gitEnvironment = {
        PATH: path.join(fixture.root, "selected tools"),
        CODEX_SECURITY_GIT: path.join(fixture.root, "selected tools", "git"),
        GIT_SSH_COMMAND: "synthetic-ssh --fixture",
        GIT_CONFIG_GLOBAL: path.join(fixture.root, "operator.gitconfig"),
      };
      Object.assign(process.env, gitEnvironment);
      const configPath = path.join(fixture.root, "active scan config.toml");
      const codexHome = path.join(fixture.root, "scan home");
      const promptPath = path.join(fixture.root, "prompt.md");
      await mkdir(codexHome);
      await writeFile(
        path.join(codexHome, "config.toml"),
        `model = "fixture-inherited-model"
model_reasoning_effort = "medium"
model_provider = "synthetic"
[model_providers.synthetic]
name = "Synthetic gateway"
base_url = "https://gateway.example.test/v1"
wire_api = "responses"
${commandAuth ? "" : 'env_key = "SYNTHETIC_GATEWAY_KEY"'}${
          commandAuth
            ? `
[model_providers.synthetic.auth]
command = "./synthetic-auth"
cwd = ${JSON.stringify(path.join(codexHome, "helpers"))}
refresh_interval_ms = 2000
[otel.exporter.otlp-http.tls]
ca-certificate = ${JSON.stringify(path.join(codexHome, "tls", "ca.pem"))}
client-certificate = ${JSON.stringify(path.join(codexHome, "tls", "client.pem"))}
client-private-key = ${JSON.stringify(path.join(codexHome, "tls", "client.key"))}`
            : ""
        }`,
      );
      await writeFile(configPath, configuration!);
      await writeFile(
        promptPath,
        commandAuth
          ? "CAPTURE_SYNTHETIC_CODEX_CONFIG"
          : "synthetic worker configuration fixture",
      );
      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.CODEX_HOME = codexHome;
      process.env.CODEX_SECURITY_CONFIG_PATH = configPath;
      process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = path.join(
        fixture.root,
        "deep settings.toml",
      );
      await writeFile(
        process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH!,
        "[worker_runtime]\n",
      );
      const launches: {
        command?: string;
        args: readonly string[];
        environment?: NodeJS.ProcessEnv;
        markerPath: string;
      }[] = [];
      childProcess.spawn = ((
        command: string,
        args: readonly string[],
        options: SpawnOptions,
      ) => {
        const markerPath = path.join(
          fixture.root,
          `invocation-${launches.length}.json`,
        );
        const environment = {
          ...options!.env,
          FAKE_CODEX_MARKER: markerPath,
          FAKE_CODEX_PREFLIGHT_MARKER: markerPath,
        };
        launches.push({ command, args, environment, markerPath });
        return originalSpawn(
          command,
          command === process.execPath ||
            command === path.toNamespacedPath(process.execPath)
            ? [fixture.executablePath, ...args]
            : args,
          { ...options, env: environment },
        );
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const settings = [
        { model: "gpt-5.6-sol", reasoningEffort: "xhigh" },
        { model: "gpt-6-astra", reasoningEffort: "ultra" },
        { model: "gpt-6.1-sol", reasoningEffort: "max" },
        { model: "gpt-6-sol", reasoningEffort: "high" },
        { model: "fixture-future-model", reasoningEffort: "future-effort" },
        // Omitted settings preserve the model and effort in the Codex home.
        {},
      ];
      const instructions = configuration.includes("model_instructions_file");
      const relative = configuration.includes("relative-instructions.md");
      const modelFiles = configuration.includes("model_catalog_json");
      const codeMode = configuration.includes("[features.code_mode]");
      const scanRoot = path.join(fixture.root, "parent-scan");
      const workerDirectory = path.join(scanRoot, "artifacts");
      await mkdir(workerDirectory, { recursive: true });
      process.env.CODEX_SECURITY_SCAN_DIR = scanRoot;
      await Promise.all(
        settings.map(async (_, index) => {
          await writeFile(
            path.join(fixture.root, `instructions-${index}.md`),
            `synthetic instructions ${index}`,
          );
        }),
      );
      const scanConfigPaths = await Promise.all(
        settings.map(async (_, index) => {
          if (!instructions && !codeMode) return configPath;
          const selected = path.join(fixture.root, `scan-${index}.toml`);
          await writeFile(
            selected,
            configuration
              .replace(
                '"profile-instructions.md"',
                JSON.stringify(
                  path.join(fixture.root, `instructions-${index}.md`),
                ),
              )
              .replace(
                '"relative-instructions.md"',
                JSON.stringify(`../instructions-${index}.md`),
              )
              .replace(
                '"profile-catalog.json"',
                JSON.stringify(
                  path.join(fixture.root, `catalog-${index}.json`),
                ),
              )
              .replace(
                '"profile-compact.md"',
                JSON.stringify(path.join(fixture.root, `compact-${index}.md`)),
              )
              .replace(
                '["synthetic_tools"]',
                JSON.stringify([`synthetic_tools_${index}`]),
              )
              .replace("enabled = true", `enabled = ${index % 2 === 0}`)
              .replace(
                'model_verbosity = "high"',
                `model_verbosity = ${JSON.stringify(index % 2 === 0 ? "high" : "low")}`,
              )
              .replace(
                'web_search = "disabled"',
                `web_search = ${JSON.stringify(index % 2 === 0 ? "disabled" : "cached")}`,
              ),
          );
          return selected;
        }),
      );
      const providerKeys = settings.map((_, index) =>
        index < 2 ? `synthetic-gateway-key-${index}` : undefined,
      );
      const executors = settings.map(
        (modelSettings) =>
          new CodexSdkWorkerExecutor({
            ...modelSettings,
            parentSandbox: trustedParentSandboxWithDenials,
            artifactContext: {
              pluginRoot: fixture.root,
              repoRoot: fixture.root,
              scanId: `fixture-scan-${modelSettings.model ?? "inherited"}`,
              pythonCommand: helperPython,
            },
          }),
      );
      // A running coordinator retains its settings if the source file changes.
      for (const kind of ["discovery", "dedup"] as const) {
        for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
          launches.length = 0;
          await Promise.all(
            executors.map((executor, index) => {
              // Each concurrent launch snapshots its own scan environment.
              process.env.CODEX_SECURITY_CONFIG_PATH = scanConfigPaths[index];
              if (providerKeys[index] === undefined) {
                delete process.env.SYNTHETIC_GATEWAY_KEY;
              } else {
                process.env.SYNTHETIC_GATEWAY_KEY = providerKeys[index];
              }
              return executor.run({
                kind,
                promptPath,
                workingDirectory: workerDirectory,
                subagents: 0,
                resumeThreadId,
                artifactContext: {
                  root: fixture.root,
                  layout: kind === "dedup" ? "reducer" : "worker",
                  ...(kind === "dedup"
                    ? {
                        deepReducer: {
                          scanRoot: fixture.root,
                          claimedWorkers: [],
                        },
                      }
                    : {}),
                },
                signal: new AbortController().signal,
              });
            }),
          );
          const workerLaunches = launches.filter(
            ({ args }) => args[0] === "exec",
          );
          assert.equal(workerLaunches.length, settings.length);
          for (const [
            index,
            { model, reasoningEffort },
          ] of settings.entries()) {
            const workerLaunch = workerLaunches.find(({ args }) =>
              model === undefined
                ? !args.includes("--model")
                : args[args.indexOf("--model") + 1] === model,
            );
            assert.ok(workerLaunch, `missing worker launch for ${model}`);
            assert.equal(
              workerLaunch.command,
              process.platform === "win32"
                ? path.toNamespacedPath(process.execPath)
                : process.execPath,
            );
            assert.equal(
              workerLaunch.environment!.CODEX_CLI_PATH,
              process.execPath,
            );
            assert.equal(
              workerLaunch.environment!.CODEX_HOME,
              await realpath(codexHome),
            );
            assert.equal(
              workerLaunch.environment!.CODEX_SECURITY_CONFIG_PATH,
              scanConfigPaths[index],
            );
            assert.equal(
              workerLaunch.environment!.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
              process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
            );
            assert.deepEqual(
              JSON.parse(
                JSON.stringify(
                  parseToml(workerPermissionProfileOverride(workerLaunch.args)!)
                    .permissions,
                ),
              ),
              {
                codex_security_deep_scan_worker: deniedWorkerPermissionProfile,
              },
            );
            const invocation = await readJson(workerLaunch.markerPath);
            assert.equal(invocation.providerKey, providerKeys[index]);
            assertFlagPair(invocation.argv, "--cd", workerDirectory);
            if (relative) {
              const argument = (invocation.argv as string[]).find((value) =>
                value.startsWith("model_instructions_file="),
              );
              assert.ok(argument);
              const selected = JSON.parse(
                argument.slice("model_instructions_file=".length),
              );
              assert.equal(
                await readFile(path.resolve(workerDirectory, selected), "utf8"),
                `synthetic instructions ${index}`,
              );
            }
            if (commandAuth) {
              assert.equal(
                invocation.codexConfig,
                await readFile(path.join(codexHome, "config.toml"), "utf8"),
              );
            }
            assert.equal(workerLaunch.environment!.CODEX_API_KEY, undefined);
            assert.equal(
              process.env.SYNTHETIC_GATEWAY_KEY,
              providerKeys.at(-1),
            );
            assertConfigOverrides(invocation.argv, {
              model_reasoning_summary: expected,
              model_catalog_json: modelFiles
                ? path.join(fixture.root, `catalog-${index}.json`)
                : undefined,
              experimental_compact_prompt_file: modelFiles
                ? path.join(fixture.root, `compact-${index}.md`)
                : undefined,
              model_instructions_file: instructions
                ? path.join(fixture.root, `instructions-${index}.md`)
                : undefined,
              model_verbosity: instructions
                ? index % 2 === 0
                  ? "high"
                  : "low"
                : undefined,
              web_search: instructions
                ? index % 2 === 0
                  ? "disabled"
                  : "cached"
                : undefined,

              "features.shell_tool": commandAuth ? false : undefined,
              "features.unified_exec": commandAuth ? false : undefined,
            });
            assert.deepEqual(
              invocation.argv.filter((arg: string) =>
                arg.startsWith("model_reasoning_effort="),
              ),
              reasoningEffort === undefined
                ? []
                : [`model_reasoning_effort=${JSON.stringify(reasoningEffort)}`],
            );
            if (model === undefined) {
              assert.equal(invocation.argv.includes("--model"), false);
            } else {
              assertFlagPair(invocation.argv, "--model", model);
            }
            if (configuration.includes('model = "native-model"')) {
              assert.equal(
                invocation.argv.some((arg: string) =>
                  arg.startsWith("profile="),
                ),
                false,
              );
            }
            assert.equal(
              invocation.argv.includes("resume"),
              resumeThreadId !== undefined,
            );
            assert.equal(invocation.configPath, scanConfigPaths[index]);
            assert.deepEqual(invocation.gitEnvironment, gitEnvironment);
            for (const [name, value] of Object.entries(gitEnvironment)) {
              assert.equal(process.env[name], value);
            }
            assert.equal(invocation.python, python);
            assertConfigOverrides(invocation.argv, {
              "mcp_servers.cs_artifacts.env.CODEX_SECURITY_PYTHON_COMMAND":
                helperPython,
            });
            assert.equal(process.env.PYTHON, python);
            assert.equal(
              invocation.deepConfigPath,
              process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
            );
            assertReadOnlyWorkerPolicy(invocation.argv);
            assertWorkerSubagentPolicy(
              invocation.argv,
              0,
              codeMode
                ? {
                    enabled: index % 2 === 0,
                    excluded_tool_namespaces: [`synthetic_tools_${index}`],
                  }
                : undefined,
            );
          }
          for (const launch of launches.filter(({ args }) =>
            args.includes("app-server"),
          )) {
            const preflight = await readJson(launch.markerPath);
            assert.deepEqual(preflight.gitEnvironment, gitEnvironment);
            assert.equal(
              workerPermissionProfileOverride(launch.args),
              workerPermissionProfileOverride(workerLaunches[0].args),
            );
          }
          for (const selected of new Set(scanConfigPaths)) {
            await writeFile(selected, 'model_reasoning_summary = "detailed"\n');
          }
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}
