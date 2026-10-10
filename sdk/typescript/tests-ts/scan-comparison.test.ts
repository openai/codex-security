import { modelResponseText } from "./support/model-response-text.js";
import { once } from "node:events";
import * as childProcess from "node:child_process";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import {
  copyFile,
  chmod,
  mkdir,
  readFile,
  readdir,
  realpath,
  symlink,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, relative, win32 } from "node:path";
import { pathToFileURL } from "node:url";
import { parse, stringify, type TomlTable } from "smol-toml";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import * as runtimeCommands from "../src/runtime.js";
import {
  executablePathForSpawn,
  resolveCodexCommand,
  runCodexCommand,
} from "../src/runtime.js";
import { resolveCommandAuthConfig, type JsonObject } from "../src/config.js";
import * as providerProfiles from "../src/provider-profile.js";
import {
  comparisonForScan,
  comparisonEnvironment,
  matchCompletedScan,
  matchScanFindings,
  matchScanFindingsInternal,
  runReadOnlyCodex,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";
import {
  temporaryDirectory as createTemporaryDirectory,
  removeTemporaryDirectory,
} from "./support/temporary-directories.js";
import { fail } from "./support/errors.js";
import { planComponents } from "../src/component-plan.js";
import { VERSION } from "../src/version.js";
import { nodeCommand } from "./support/shell.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(removeTemporaryDirectory),
  );
});

async function temporaryDirectory(prefix = "codex-security-comparison-") {
  const path = await createTemporaryDirectory(prefix, false);
  temporaryDirectories.push(path);
  return path;
}

function finding(occurrenceId: string): ScanComparisonInput["before"][number] {
  return { occurrenceId };
}

function fakeCodex(response: unknown) {
  const calls: {
    prompt?: string;
    threadOptions?: ThreadOptions;
    turnOptions?: TurnOptions;
  } = {};
  const codex: NonNullable<ScanComparisonOptions["codex"]> = {
    startThread(options) {
      calls.threadOptions = options;
      return {
        async run(prompt, turnOptions) {
          calls.prompt = prompt;
          calls.turnOptions = turnOptions;
          return { finalResponse: modelResponseText(response) };
        },
      };
    },
  };
  return { codex, calls };
}

function observeCodexOptions(
  codex: NonNullable<ScanComparisonOptions["codex"]>,
  observe: (options: CodexOptions) => void,
) {
  return spyOn(Codex.prototype, "startThread").mockImplementation(function (
    this: Codex,
    options,
  ) {
    observe((this as unknown as { options: CodexOptions }).options);
    return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
  });
}

function captureProfileClient() {
  const profiles: {
    name: string;
    path: string;
    config: TomlTable;
    scanId: string | undefined;
  }[] = [];
  const spy = spyOn(providerProfiles, "createProfileCodex").mockImplementation(
    async (options, name) => {
      const path = join(options.env!["CODEX_HOME"]!, `${name}.config.toml`);
      profiles.push({
        name,
        path,
        config: parse(await readFile(path, "utf8")),
        scanId: options.env?.["CODEX_SECURITY_SCAN_ID"],
      });
      return new Codex(options);
    },
  );
  return { profiles, spy };
}

describe("semantic scan comparison", () => {
  test.each([
    ["sdk", "matching"],
    ["cli", "matching"],
    ["sdk", "planning"],
    ["cli", "planning"],
  ] as const)(
    "preserves request metadata and attributes %s %s at the model boundary",
    async (surface, helper) => {
      const root = await temporaryDirectory();
      const home = join(root, "home");
      const repository = join(root, "repository");
      await mkdir(home);
      await mkdir(repository);
      await writeFile(join(repository, "source.ts"), "export {};\n");
      await writeFile(
        join(home, "config.toml"),
        stringify({
          responses_api_metadata: {
            synthetic_home: "preserved",
            codex_security_surface: "previous",
          },
        }),
      );
      const options = {
        config: {
          codexOverrides: {
            responses_api_metadata: {
              synthetic_caller: "preserved",
              codex_security_command: "previous",
            },
          },
        },
        environment: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-key",
        },
      };
      let captured: CodexOptions | undefined;
      const { codex } = fakeCodex(
        helper === "matching"
          ? { matches: [], uncertain: [] }
          : { components: [{ name: "Source", paths: ["source.ts"] }] },
      );
      const startThread = observeCodexOptions(codex, (options) => {
        captured = options;
      });
      try {
        if (helper === "planning") {
          await planComponents(repository, {
            ...options,
            ...(surface === "cli" ? { surface } : {}),
          });
        } else {
          const input = {
            before: [finding("before")],
            after: [finding("after")],
          };
          if (surface === "sdk") await matchScanFindings(input, options);
          else await matchScanFindingsInternal(input, options, { surface });
        }
        expect(startThread).toHaveBeenCalledTimes(1);
        expect(captured?.config).not.toHaveProperty("responses_api_metadata");
        expect(
          parse(captured!.configOverrides!.join("\n"))[
            "responses_api_metadata"
          ],
        ).toEqual({
          synthetic_home: "preserved",
          synthetic_caller: "preserved",
          codex_security_surface: surface,
          codex_security_command:
            helper === "matching" ? "compare" : "scan-components",
          codex_security_package_version: VERSION,
        });
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test.each([false, true])(
    "preserves literal metadata keys in SDK arguments with provider profile %p",
    async (withProfile) => {
      const home = await temporaryDirectory();
      const preload = join(home, "capture-codex.mjs");
      await writeFile(
        join(home, "config.toml"),
        stringify({
          responses_api_metadata: {
            "team.tag": "from-home",
            "overlap.tag": "home",
          },
        }),
      );
      await writeFile(
        preload,
        [
          "for await (const _chunk of process.stdin) {}",
          "const send = (event) => console.log(JSON.stringify(event));",
          'send({ type: "thread.started", thread_id: "fixture-thread" });',
          'send({ type: "item.completed", item: { id: "reply", type: "agent_message", text: JSON.stringify(process.argv.slice(2)) } });',
          'send({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } });',
          "process.exit(0);",
        ].join("\n"),
      );
      let captured: CodexOptions | undefined;
      const profileClient = captureProfileClient();
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = observeCodexOptions(codex, (options) => {
        captured = options;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_HOME: home,
              CODEX_SECURITY_STATE_DIR: join(home, "state"),
              OPENAI_API_KEY: "synthetic-key",
            },
            workingDirectory: home,
            config: {
              codexOverrides: {
                responses_api_metadata: {
                  "caller.tag": "from-caller",
                  "overlap.tag": "caller",
                },
                ...(withProfile
                  ? {
                      model_provider: "synthetic",
                      model_providers: {
                        synthetic: {
                          name: "Synthetic",
                          wire_api: "responses",
                          base_url: "https://provider.example.test/v1",
                        },
                      },
                    }
                  : {}),
              },
            },
          },
        );
      } finally {
        startThread.mockRestore();
        profileClient.spy.mockRestore();
      }
      expect(captured).toBeDefined();
      expect(profileClient.profiles).toHaveLength(withProfile ? 1 : 0);
      const capture = new Codex({
        ...captured,
        codexPathOverride: nodeCommand().command,
        env: {
          ...captured!.env,
          NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
        },
      });
      const turn = await capture
        .startThread({ workingDirectory: home, skipGitRepoCheck: true })
        .run("Capture the invocation.");
      const args: string[] = JSON.parse(turn.finalResponse);
      const metadataOverrides = args
        .flatMap((arg, index) => (arg === "--config" ? [args[index + 1]!] : []))
        .filter((value) => value.startsWith("responses_api_metadata"));
      expect(metadataOverrides).toHaveLength(1);
      expect(parse(metadataOverrides[0]!)).toEqual({
        responses_api_metadata: {
          "team.tag": "from-home",
          "caller.tag": "from-caller",
          "overlap.tag": "caller",
          codex_security_surface: "sdk",
          codex_security_command: "compare",
          codex_security_package_version: VERSION,
        },
      });
      const parsed = await runCodexCommand(
        resolveCodexCommand(captured!.env),
        [
          ...metadataOverrides.flatMap((value) => ["-c", value]),
          "mcp",
          "list",
          "--json",
        ],
        captured!.env!,
      );
      expect(parsed).toMatchObject({ success: true });
    },
  );

  test("uses comparison attribution for CLI comparison turns", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    await matchScanFindingsInternal(
      { before: [finding("before")], after: [finding("after")] },
      { codex },
      { surface: "cli" },
    );
    expect(calls.threadOptions?.threadSource).toBe("security_scan_comparison");
  });

  test.each(["synthetic.gateway", "fireworks", "amazon-bedrock", "command"])(
    "automatic matching retains the per-scan %s provider",
    async (selection) => {
      const home = await temporaryDirectory();
      await writeFile(join(home, "config.toml"), "");
      const providerName =
        selection === "command" ? "synthetic.command" : selection;
      const provider = {
        ...(selection === "amazon-bedrock"
          ? { aws: { region: "us-east-1" } }
          : {
              name: "Synthetic",
              wire_api: "responses",
              requires_openai_auth: false,
            }),
        base_url: "https://provider.example.test/v1",
        http_headers: { "X-Synthetic-Secret": "synthetic-header-marker" },
        ...(selection === "command"
          ? {
              auth: {
                command: "synthetic-auth",
                cwd: join(home, "helpers"),
                env: { SYNTHETIC_AUTH_KEY: "synthetic-command-marker" },
              },
            }
          : selection === "amazon-bedrock"
            ? {}
            : { env_key: "SYNTHETIC_PROVIDER_KEY" }),
      };
      const parentProfile =
        selection === "fireworks"
          ? await providerProfiles.createProviderProfile(home, {
              model_provider: providerName,
              model_providers: { [providerName]: provider },
            })
          : undefined;
      const profileClient = captureProfileClient();
      const startupCommands: Parameters<typeof runCodexCommand>[0][] = [];
      const runNativeCommand = runtimeCommands.runCodexCommand;
      const nativeCommand = spyOn(
        runtimeCommands,
        "runCodexCommand",
      ).mockImplementation((...args) => {
        if (args[1].includes("mcp")) startupCommands.push(args[0]);
        return runNativeCommand(...args);
      });
      const before = finding("before");
      const after = finding("after");
      const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
      let captured: CodexOptions | undefined;
      let saved = false;
      const startThread = observeCodexOptions(codex, (options) => {
        captured = options;
      });
      try {
        await matchCompletedScan({
          scanId: "current",
          repository: home,
          previousFindings: [before],
          falsePositives: [],
          findings: [after],
          ...(parentProfile === undefined
            ? {}
            : { nativeProfile: parentProfile }),
          environment: {
            PATH: process.env["PATH"],
            SystemRoot: process.env["SystemRoot"],
            CODEX_HOME: home,
            CODEX_SECURITY_SCAN_ID: "current",
            OPENAI_API_KEY: "synthetic-ambient-key",
            SYNTHETIC_PROVIDER_KEY: "synthetic-provider-key",
          },
          config: {
            codexOverrides: {
              profile: "selected",
              profiles: {
                selected: {
                  model_provider: providerName,
                  model_providers: { [providerName]: provider },
                },
              },
              model_providers: { [providerName]: provider },
              default_permissions: "codex_security_scan",
              permissions: {
                codex_security_scan: { filesystem: { [home]: "write" } },
              },
              projects: { [home]: { trust_level: "trusted" } },
            },
          },
          async workbench(args) {
            if (args[0] === "list-unmatched-scan-pairs") {
              return {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    beforeScans: [{ scanId: "prior", findings: [before] }],
                  },
                ],
              };
            }
            saved = args[0] === "save-scan-comparison";
            return {};
          },
        });
        expect(startThread).toHaveBeenCalledTimes(1);
        expect(captured?.config).toMatchObject({
          model_provider: providerName,
        });
        expect(profileClient.profiles).toHaveLength(1);
        const profile = profileClient.profiles[0]!;
        expect(profile.config).toEqual({
          model_providers: { [providerName]: provider },
        });
        expect(startupCommands).toHaveLength(1);
        expect(parse(startupCommands[0]!.args![1]!)).toEqual({
          model_providers: {
            [providerName]:
              selection === "amazon-bedrock"
                ? {}
                : {
                    name: "Synthetic",
                    wire_api: "responses",
                    requires_openai_auth: false,
                  },
          },
        });
        expect(startupCommands[0]!.args!.join("\n")).not.toContain(
          "synthetic-header-marker",
        );
        expect(startupCommands[0]!.args!.join("\n")).not.toContain(
          "synthetic-command-marker",
        );
        expect(parse(captured!.configOverrides!.join("\n"))).toEqual({
          responses_api_metadata: {
            codex_security_surface: "sdk",
            codex_security_command: "compare",
            codex_security_package_version: VERSION,
          },
          default_permissions: "codex_security_deep_scan_worker",
          permissions: {
            codex_security_deep_scan_worker: {
              extends: ":read-only",
              filesystem: { ":root": "read", [home]: { ".": "deny" } },
              network: { enabled: false },
            },
          },
        });
        expect(JSON.stringify(captured?.config)).not.toContain(
          "synthetic-header-marker",
        );
        expect(captured!.configOverrides!.join("\n")).not.toContain(
          "synthetic-header-marker",
        );
        expect(JSON.stringify(captured?.config)).not.toContain(
          "synthetic-command-marker",
        );
        expect(captured!.configOverrides!.join("\n")).not.toContain(
          "synthetic-command-marker",
        );
        if (parentProfile === undefined) {
          await expect(readFile(profile.path, "utf8")).rejects.toMatchObject({
            code: "ENOENT",
          });
        } else {
          expect(profile.name).toBe(parentProfile.name);
          expect(parse(await readFile(parentProfile.path, "utf8"))).toEqual(
            profile.config,
          );
        }
        for (const key of [
          "model_providers",
          "default_permissions",
          "permissions",
          "projects",
          "profile",
          "profiles",
        ]) {
          expect(captured?.config).not.toHaveProperty(key);
        }
        if (selection === "command") {
          expect(captured?.apiKey).toBeUndefined();
          expect(captured?.env).not.toHaveProperty("OPENAI_API_KEY");
        }
        expect(calls.threadOptions).toMatchObject({
          approvalPolicy: "never",
          networkAccessEnabled: false,
        });
        expect(calls.threadOptions?.sandboxMode).toBeUndefined();
        expect(saved).toBe(true);
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe("");
      } finally {
        nativeCommand.mockRestore();
        profileClient.spy.mockRestore();
        startThread.mockRestore();
        await parentProfile?.cleanup();
      }
    },
  );

  test.each(["complete", "turn error", "abort"])(
    "keeps its private provider profile through evidence turns and cleans up on %s",
    async (outcome) => {
      const home = await temporaryDirectory();
      const controller = new AbortController();
      const profileClient = captureProfileClient();
      let turns = 0;
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(
        () =>
          ({
            async run() {
              expect(
                parse(await readFile(profileClient.profiles[0]!.path, "utf8")),
              ).toMatchObject({
                model_providers: {
                  synthetic: {
                    http_headers: {
                      "X-Synthetic-Secret": "synthetic-lifecycle-marker",
                    },
                  },
                },
              });
              turns++;
              if (turns === 2 && outcome === "turn error")
                throw new Error("synthetic turn failure");
              if (turns === 1 && outcome === "abort")
                controller.abort(new DOMException("canceled", "AbortError"));
              return {
                finalResponse: JSON.stringify({
                  matches: [],
                  uncertain: [],
                  ...(turns === 1
                    ? {
                        request: {
                          kind: "evidence",
                          beforeOccurrenceIds: ["before"],
                          afterOccurrenceIds: ["after"],
                          offset: 0,
                        },
                      }
                    : {}),
                }),
              };
            },
          }) as unknown as ReturnType<Codex["startThread"]>,
      );
      try {
        const result = matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            signal: controller.signal,
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_HOME: home,
            },
            config: {
              codexOverrides: {
                model_provider: "synthetic",
                model_providers: {
                  synthetic: {
                    name: "Synthetic",
                    wire_api: "responses",
                    base_url: "https://provider.example.test/v1",
                    http_headers: {
                      "X-Synthetic-Secret": "synthetic-lifecycle-marker",
                    },
                  },
                },
              },
            },
          },
        );
        if (outcome === "complete")
          await expect(result).resolves.toEqual({ matches: [], uncertain: [] });
        else if (outcome === "turn error")
          await expect(result).rejects.toThrow("synthetic turn failure");
        else await expect(result).rejects.toMatchObject({ name: "AbortError" });
        expect(turns).toBe(outcome === "abort" ? 1 : 2);
        expect(profileClient.profiles).toHaveLength(1);
        await expect(
          readFile(profileClient.profiles[0]!.path, "utf8"),
        ).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        profileClient.spy.mockRestore();
        startThread.mockRestore();
      }
    },
  );

  test.each(["codex_security_policy", "codex_security_deep_scan_worker"])(
    "does not inherit write grants from the existing %s permission profile",
    async (permissionId) => {
      const home = await temporaryDirectory();
      const work = await temporaryDirectory();
      await writeFile(
        join(home, "config.toml"),
        stringify({
          default_permissions: permissionId,
          permissions: {
            [permissionId]: {
              extends: ":read-only",
              filesystem: { [work]: "write" },
            },
          },
        }),
      );
      const profileClient = captureProfileClient();
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      let captured: CodexOptions | undefined;
      const startThread = observeCodexOptions(codex, (options) => {
        captured = options;
      });
      try {
        const matching = matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            workingDirectory: work,
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_HOME: home,
            },
            config: {
              codexOverrides: {
                model_provider: "synthetic",
                model_providers: {
                  synthetic: {
                    name: "Synthetic",
                    wire_api: "responses",
                    base_url: "https://provider.example.test/v1",
                  },
                },
              },
            },
          },
        );
        if (permissionId === "codex_security_deep_scan_worker") {
          await expect(matching).rejects.toThrow(
            "existing Codex configuration changes the reserved",
          );
          expect(startThread).not.toHaveBeenCalled();
          expect(
            (await readdir(home)).filter((name) =>
              name.endsWith(".config.toml"),
            ),
          ).toEqual([]);
          return;
        }
        await matching;
        // App-server reads the same native permission layers without a model turn.
        // Provider definitions stay in their private file and are unnecessary here.
        const child = spawn(
          executablePathForSpawn(resolveCodexCommand({}).command),
          [
            ...captured!.configOverrides!.flatMap((value) => ["-c", value]),
            "-c",
            'model_provider="openai"',
            "app-server",
            "--stdio",
          ],
          {
            cwd: work,
            env: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_HOME: home,
            },
            windowsHide: true,
          },
        );
        const closed = once(child, "close");
        const lines = createInterface({ input: child.stdout });
        let stderr = "";
        child.stderr.on("data", (chunk) => {
          stderr += chunk;
        });
        try {
          child.stdin.write(
            JSON.stringify({
              id: 1,
              method: "initialize",
              params: {
                clientInfo: { name: "synthetic_permission_test", version: "1" },
                capabilities: { experimentalApi: true },
              },
            }) + "\n",
          );
          let inspected = false;
          for await (const line of lines) {
            const message = JSON.parse(line);
            if (message.error) throw new Error(JSON.stringify(message.error));
            if (message.id === 1)
              child.stdin.write(
                JSON.stringify({
                  id: 2,
                  method: "config/read",
                  params: { cwd: work, includeLayers: false },
                }) + "\n",
              );
            if (message.id === 2) {
              const config = message.result.config;
              expect(
                config.permissions[config.default_permissions].filesystem,
              ).not.toHaveProperty(work);
              expect(config.default_permissions).toBe(
                "codex_security_deep_scan_worker",
              );
              expect(
                config.permissions.codex_security_deep_scan_worker.filesystem,
              ).toMatchObject({
                ":root": "read",
                [home]: { ".": "deny" },
              });
              expect(
                config.permissions.codex_security_policy.filesystem[work],
              ).toBe("write");
              inspected = true;
              break;
            }
          }
          expect(inspected, stderr).toBe(true);
        } finally {
          lines.close();
          child.kill();
          await closed;
        }
      } finally {
        profileClient.spy.mockRestore();
        startThread.mockRestore();
      }
    },
  );

  test.each(["allowed", "disallowed", "fallback", "empty"])(
    "checks the actual helper permission child before starting a turn when %s",
    async (mode) => {
      const home = await temporaryDirectory();
      const work = await temporaryDirectory();
      const executable = join(home, "synthetic-codex.mjs");
      const callsPath = join(home, "preflight-calls.jsonl");
      const profileId = "codex_security_deep_scan_worker";
      await writeFile(
        executable,
        `
        import { appendFileSync, existsSync } from "node:fs";
        import { join } from "node:path";
        import { createInterface } from "node:readline";
        const args = process.argv.slice(2);
        if (args.includes("mcp")) { console.log("[]"); process.exit(0); }
        const id = ${JSON.stringify(profileId)};
        const mode = ${JSON.stringify(mode)};
        const profile = {
          extends: ":read-only",
          filesystem: { ":root": "read", [process.env.CODEX_HOME]: { ".": "deny" } },
          network: { enabled: false },
        };
        const lines = createInterface({ input: process.stdin });
        for await (const line of lines) {
          const request = JSON.parse(line);
          appendFileSync(${JSON.stringify(callsPath)}, JSON.stringify({
            method: request.method, args, cwd: process.cwd(),
            home: process.env.CODEX_HOME, sentinel: process.env.SYNTHETIC_PREFLIGHT_SENTINEL,
            lockHeld: existsSync(join(process.env.CODEX_HOME, ".codex-security-preflight", ".codex-security-scan.lock", "owner.json")),
          }) + "\\n");
          if (request.id === undefined) continue;
          const result = request.method === "config/read"
            ? { config: { default_permissions: mode === "fallback" ? ":workspace" : id, permissions: { [id]: profile } } }
            : request.method === "permissionProfile/list"
            ? { data: [{ id, allowed: mode !== "disallowed" }], nextCursor: null }
            : request.method === "configRequirements/read"
            ? { requirements: { allowedPermissionProfiles: { ":workspace": true } } }
            : {};
          console.log(JSON.stringify({ id: request.id, result }));
        }
      `,
      );
      const originalSpawn = childProcess.spawn;
      const spawnSpy = spyOn(childProcess, "spawn").mockImplementation(((
        ...input: Parameters<typeof originalSpawn>
      ) => {
        const [command, args, options] = input;
        return command === process.execPath ||
          command === executablePathForSpawn(process.execPath)
          ? originalSpawn(
              process.execPath,
              [executable, ...(args ?? [])],
              options ?? {},
            )
          : originalSpawn(...input);
      }) as typeof originalSpawn);
      const profileClient = captureProfileClient();
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const lockPath = join(
        home,
        ".codex-security-preflight",
        ".codex-security-scan.lock",
      );
      let windows: unknown;
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        windows = (this as unknown as { options: CodexOptions }).options
          .config?.["windows"];
        expect(existsSync(lockPath)).toBe(false);
        return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
      });
      try {
        const matching = matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            workingDirectory: work,
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_CLI_PATH: process.execPath,
              CODEX_HOME: home,
              SYNTHETIC_PREFLIGHT_SENTINEL: "synthetic-inherited-setting",
              ...(mode === "empty"
                ? { OPENAI_API_KEY: "synthetic-api-key" }
                : {}),
            },
            config: {
              codexOverrides:
                mode === "empty"
                  ? { model_providers: {} }
                  : {
                      model_provider: "synthetic.provider",
                      model_providers: {
                        "synthetic.provider": {
                          name: "Synthetic provider",
                          wire_api: "responses",
                          auth: {
                            command: "synthetic-auth",
                            env: {
                              SYNTHETIC_SECRET: "synthetic-private-marker",
                            },
                          },
                        },
                      },
                    },
            },
          },
        );
        if (mode === "allowed" || mode === "empty") {
          await expect(matching).resolves.toEqual({
            matches: [],
            uncertain: [],
          });
          expect(startThread).toHaveBeenCalledTimes(1);
        } else {
          await expect(matching).rejects.toThrow(
            mode === "disallowed"
              ? "organization policy does not allow"
              : "did not select",
          );
          expect(startThread).not.toHaveBeenCalled();
        }
        if (mode === "empty") {
          expect(windows).toEqual({ sandbox: "elevated" });
          expect(existsSync(callsPath)).toBe(false);
          expect(profileClient.profiles).toEqual([]);
          return;
        }
        const calls = (await readFile(callsPath, "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(calls.map(({ method }) => method)).toEqual([
          "initialize",
          "initialized",
          "config/read",
          "permissionProfile/list",
          ...(mode === "disallowed" ? ["configRequirements/read"] : []),
        ]);
        expect(calls[0]).toMatchObject({
          cwd: work,
          home,
          sentinel: "synthetic-inherited-setting",
          lockHeld: true,
        });
        expect(existsSync(lockPath)).toBe(false);
        const args = calls[0].args as string[];
        const overrides = args.flatMap((arg, index) =>
          arg === "--config" ? [args[index + 1]!] : [],
        );
        expect(parse(overrides.join("\n"))).toMatchObject({
          default_permissions: profileId,
          permissions: {
            [profileId]: {
              filesystem: { [home]: { ".": "deny" } },
              network: { enabled: false },
            },
          },
          model_providers: {
            "synthetic.provider": {
              name: "Synthetic provider",
              wire_api: "responses",
            },
          },
        });
        expect(args.join("\n")).not.toContain("synthetic-private-marker");
        expect(
          (await readdir(home)).filter((name) => name.endsWith(".config.toml")),
        ).toEqual([]);
      } finally {
        startThread.mockRestore();
        profileClient.spy.mockRestore();
        spawnSpy.mockRestore();
      }
    },
  );

  test.each([
    [
      "OPENAI_API_KEY",
      { OPENAI_API_KEY: "synthetic-openai-key" },
      "synthetic-openai-key",
    ],
    [
      "CODEX_API_KEY",
      { CODEX_API_KEY: "synthetic-codex-key" },
      "synthetic-codex-key",
    ],
    [
      "OPENAI_API_KEY precedence",
      {
        OPENAI_API_KEY: "synthetic-openai-key",
        CODEX_API_KEY: "synthetic-codex-key",
      },
      "synthetic-openai-key",
    ],
    [
      "blank OPENAI_API_KEY fallback",
      { OPENAI_API_KEY: " \t ", CODEX_API_KEY: "synthetic-codex-key" },
      "synthetic-codex-key",
    ],
    ["no environment key", {}, undefined],
  ] as const)(
    "supplies %s authentication to Codex matching",
    async (_name, keys, expected) => {
      const home = await temporaryDirectory("codex-security-matcher-auth-");
      let captured: CodexOptions | undefined;
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = observeCodexOptions(codex, (options) => {
        captured = options;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_HOME: home,
              CODEX_SECURITY_STATE_DIR: join(home, "state"),
              ...keys,
            },
            workingDirectory: home,
          },
        );
        expect(startThread).toHaveBeenCalledTimes(1);
        expect(captured?.apiKey).toBe(expected);
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test.each(["unselected", "default", "home", "overrides", "override-profile"])(
    "preserves Cyber selection and %s feature gates at read-only SDK boundaries",
    async (selection) => {
      const home = await temporaryDirectory("codex-security-cyber-helper-");
      const disabled = {
        api_key_cyber_access_programs: false,
        api_key_model_discovery: false,
        shell_tool: true,
      };
      const profile = {
        profile: "selected",
        features: { api_key_cyber_access_programs: true },
        profiles: { selected: { features: disabled } },
      };
      await writeFile(
        join(home, "config.toml"),
        stringify(selection === "home" ? { features: disabled } : {}),
      );
      const options = {
        cyberAccessProgram:
          selection === "unselected" ? undefined : ("daybreak_blue" as const),
        environment: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(home, "state"),
          OPENAI_API_KEY: "synthetic-key",
        },
        workingDirectory: home,
        ...(selection === "overrides"
          ? { config: { codexOverrides: { features: disabled } } }
          : selection === "override-profile"
            ? { config: { codexOverrides: profile } }
            : {}),
      };
      let captured: CodexOptions | undefined;
      const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = observeCodexOptions(codex, (options) => {
        captured = options;
      });
      try {
        for (const helper of ["matching", "planning"]) {
          if (helper === "matching") {
            await matchScanFindings(
              { before: [finding("before")], after: [finding("after")] },
              options,
            );
          } else {
            await runReadOnlyCodex("Plan components.", {}, options, {
              surface: "cli",
              command: "scan-components",
              threadSource: "security_scan",
            });
          }
          expect(calls.turnOptions?.cyberAccessProgram).toBe(
            options.cyberAccessProgram,
          );
          const features = captured?.config?.["features"] as Record<
            string,
            unknown
          >;
          expect(features["api_key_cyber_access_programs"]).toBe(
            selection === "unselected" ? undefined : selection === "default",
          );
          expect(features["api_key_model_discovery"]).toBe(
            selection === "unselected" || selection === "default"
              ? undefined
              : false,
          );
          expect(features).toMatchObject({
            shell_tool: false,
            plugins: false,
            multi_agent: false,
            unified_exec: false,
          });
        }
        expect(startThread).toHaveBeenCalledTimes(2);
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test.each(["home", "home-override", "profile", "overrides", "override-away"])(
    "preserves native command auth selection from %s",
    async (selection) => {
      const root = await temporaryDirectory(
        "codex-security-command-comparison-",
      );
      const home =
        selection === "home" && process.platform !== "win32"
          ? join(root, " selected home ")
          : root;
      if (home !== root) {
        await mkdir(home, { mode: 0o700 });
        await mkdir(home.trim());
        await writeFile(
          join(home.trim(), "config.toml"),
          'model_provider = "openai"\n',
        );
      }
      const commandAuth = selection !== "override-away";
      const provider = {
        name: "Synthetic",
        wire_api: "responses",
        base_url: "https://provider.example/v1",
        auth: {
          command: "./synthetic-auth",
          args: ["original"],
          refresh_interval_ms: 1234,
        },
      };
      const config = {
        ...(selection === "home-override"
          ? { windows: { sandbox: "unelevated" } }
          : {}),
        model_provider:
          selection === "overrides" || selection === "profile"
            ? "openai"
            : "synthetic.provider",
        model_providers: { "synthetic.provider": provider },
      };
      const contents = stringify(config);
      await writeFile(join(home, "config.toml"), contents);
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: relative(process.cwd(), home),
        OPENAI_API_KEY: "synthetic-ambient-key",
        CODEX_API_KEY: "synthetic-other-key",
      };
      let captured: CodexOptions | undefined;
      let threadOptions: ThreadOptions | undefined;
      const profileClient = captureProfileClient();
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        captured = (this as unknown as { options: CodexOptions }).options;
        threadOptions = options;
        return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment,
            workingDirectory: home,
            ...(selection === "overrides"
              ? {
                  config: {
                    codexOverrides: {
                      model_provider: "synthetic.provider",
                      model_providers: {
                        "synthetic.provider": {
                          auth: { args: ["override"], cwd: "~/helpers" },
                        },
                      },
                    },
                  },
                }
              : selection === "override-away"
                ? { config: { codexOverrides: { model_provider: "openai" } } }
                : selection === "profile"
                  ? {
                      config: {
                        codexOverrides: {
                          profile: "review",
                          profiles: {
                            review: { model_provider: "synthetic.provider" },
                          },
                        },
                      },
                    }
                  : {}),
          },
        );
        expect(captured?.env?.["CODEX_HOME"]).toBe(home);
        if (selection === "profile") {
          expect(captured?.config?.["model_provider"]).toBe(
            "synthetic.provider",
          );
          expect(captured?.config).not.toHaveProperty("profile");
          expect(captured?.config).not.toHaveProperty("profiles");
        }
        if (commandAuth) {
          expect(captured?.config?.["windows"]).toEqual({
            sandbox: selection === "home-override" ? "unelevated" : "elevated",
          });
          expect(captured?.env).not.toHaveProperty("OPENAI_API_KEY");
          expect(captured?.env).not.toHaveProperty("CODEX_API_KEY");
          expect(captured?.apiKey).toBeUndefined();
          expect(profileClient.profiles).toHaveLength(1);
          expect(profileClient.profiles[0]!.config).toEqual({
            model_providers: {
              "synthetic.provider": {
                ...provider,
                auth: {
                  ...provider.auth,
                  cwd: selection === "overrides" ? "~/helpers" : home,
                  args: selection === "overrides" ? ["override"] : ["original"],
                },
              },
            },
          });
          await expect(
            readFile(profileClient.profiles[0]!.path, "utf8"),
          ).rejects.toMatchObject({ code: "ENOENT" });
        } else {
          expect(captured?.env?.["OPENAI_API_KEY"]).toBe(
            "synthetic-ambient-key",
          );
          expect(captured?.config?.["model_provider"]).toBe("openai");
          expect(parse(captured!.configOverrides!.join("\n"))).toEqual({
            responses_api_metadata: {
              codex_security_surface: "sdk",
              codex_security_command: "compare",
              codex_security_package_version: VERSION,
            },
          });
          expect(profileClient.profiles).toHaveLength(0);
        }
        expect(threadOptions).toMatchObject({
          workingDirectory: home,
          approvalPolicy: "never",
          networkAccessEnabled: false,
        });
        expect(threadOptions?.sandboxMode).toBe(
          commandAuth ? undefined : "read-only",
        );
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
          contents,
        );
      } finally {
        profileClient.spy.mockRestore();
        startThread.mockRestore();
      }
    },
  );

  test.each(["command", "environment", "permissions"] as const)(
    "automatic matching keeps concurrent %s configurations isolated",
    async (mode) => {
      const home = await temporaryDirectory(
        "codex-security-automatic-matching-",
      );
      await writeFile(join(home, "config.toml"), "");
      if (process.platform !== "win32") await chmod(home, 0o755);
      const providers = [0, 1].map((index) => ({
        name: `Synthetic provider ${index}`,
        base_url: `https://provider-${index}.example.test/v1`,
        wire_api: "responses",
        http_headers: {
          "X-Synthetic-Secret": `synthetic-concurrent-header-${index}`,
        },
        ...(mode === "environment"
          ? { env_key: "SYNTHETIC_PROVIDER_KEY" }
          : {
              auth: {
                command: `synthetic-auth-${index}`,
                cwd: join(home, `native-${index}`, "helpers"),
              },
            }),
      }));
      const captured: CodexOptions[] = [];
      const profileClient = captureProfileClient();
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const turnsStarted = Promise.withResolvers<void>();
      let runningTurns = 0;
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        captured.push((this as unknown as { options: CodexOptions }).options);
        const thread = codex.startThread(options!);
        return {
          async run(...args: Parameters<typeof thread.run>) {
            if (++runningTurns === 2) turnsStarted.resolve();
            await turnsStarted.promise;
            return thread.run(...args);
          },
        } as ReturnType<Codex["startThread"]>;
      });
      try {
        await Promise.all(
          providers.map(async (provider, index) => {
            const before = finding(`before-${index}`);
            const after = finding(`after-${index}`);
            const scanId = `current-${index}`;
            const codexConfig = resolveCommandAuthConfig(
              {
                ...(mode === "permissions"
                  ? {
                      permissions: {
                        audit: { filesystem: { [home]: { ".": "read" } } },
                      },
                    }
                  : {}),
                model_provider: "synthetic.provider",
                model_providers: {
                  "synthetic.provider": {
                    ...provider,
                    ...(!("auth" in provider)
                      ? {}
                      : { auth: { ...provider.auth, cwd: "helpers" } }),
                  },
                },
              },
              join(home, `native-${index}`),
            );
            await matchCompletedScan({
              scanId,
              repository: home,
              previousFindings: [before],
              falsePositives: [],
              findings: [after],
              config: { codexOverrides: codexConfig },
              environment: {
                PATH: process.env["PATH"],
                SystemRoot: process.env["SystemRoot"],
                CODEX_HOME: home,
                CODEX_SECURITY_SCAN_ID: scanId,
                OPENAI_API_KEY: "synthetic-ambient-key",
                SYNTHETIC_PROVIDER_KEY: `synthetic-provider-${index}`,
              },
              async workbench(args) {
                return args[0] === "list-unmatched-scan-pairs"
                  ? {
                      batches: [
                        {
                          afterScanId: scanId,
                          afterFindings: [after],
                          beforeScans: [
                            { scanId: `prior-${index}`, findings: [before] },
                          ],
                        },
                      ],
                    }
                  : {};
              },
            });
          }),
        );
        expect(captured).toHaveLength(2);
        for (const [index, provider] of providers.entries()) {
          const options = captured.find(
            ({ env }) => env?.["CODEX_SECURITY_SCAN_ID"] === `current-${index}`,
          );
          expect(options?.config?.["model_provider"]).toBe(
            "synthetic.provider",
          );
          const profile = profileClient.profiles.find(
            ({ scanId }) => scanId === `current-${index}`,
          );
          expect(profile).toBeDefined();
          expect(profile!.config).toEqual({
            model_providers: { "synthetic.provider": provider },
          });
          for (const markerIndex of [0, 1]) {
            expect(JSON.stringify(options!.config)).not.toContain(
              `synthetic-concurrent-header-${markerIndex}`,
            );
            expect(options!.configOverrides!.join("\n")).not.toContain(
              `synthetic-concurrent-header-${markerIndex}`,
            );
          }
          await expect(readFile(profile!.path, "utf8")).rejects.toMatchObject({
            code: "ENOENT",
          });
          expect(options?.config).not.toHaveProperty("permissions");
          if (mode !== "environment") {
            expect(options?.apiKey).toBeUndefined();
            expect(options?.env).not.toHaveProperty("OPENAI_API_KEY");
          } else {
            expect(options?.env?.["SYNTHETIC_PROVIDER_KEY"]).toBe(
              `synthetic-provider-${index}`,
            );
          }
        }
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe("");
        if (process.platform !== "win32") {
          expect((await stat(home)).mode & 0o777).toBe(0o755);
          expect(
            (await stat(join(home, ".codex-security-preflight"))).mode & 0o777,
          ).toBe(0o700);
        }
      } finally {
        profileClient.spy.mockRestore();
        startThread.mockRestore();
      }
    },
  );

  test("does not substitute managed login for an explicitly configured command provider", async () => {
    const home = await temporaryDirectory("codex-security-command-login-");
    const state = join(home, "state");
    await mkdir(join(state, "codex-home"), { recursive: true });
    // Invalid auth remains native Codex's responsibility, without login fallback.
    await writeFile(
      join(home, "config.toml"),
      'model_provider="openai"\nprofile="review"\n[profiles.review]\nmodel_provider="synthetic"\n[model_providers.synthetic.auth]\ncommand=""\n',
    );
    const environment = { CODEX_HOME: home, CODEX_SECURITY_STATE_DIR: state };
    expect(
      await comparisonEnvironment(environment, async () =>
        fail("Must not probe managed login"),
      ),
    ).toEqual(environment);
  });

  test.each(["chatgpt", "api-key"] as const)(
    "rejects ambient command auth that conflicts with explicit %s authentication",
    async (auth) => {
      const home = await temporaryDirectory("codex-security-auth-conflict-");
      const provider = {
        name: "Synthetic",
        base_url: "https://provider.example/v1",
        wire_api: "responses",
        auth: { command: "./synthetic-auth" },
      };
      const config = {
        model_provider: "synthetic",
        model_providers: { synthetic: provider },
      };
      await writeFile(join(home, "config.toml"), stringify(config));
      const options = {
        auth,
        config: {},
        environment: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
          OPENAI_API_KEY: "synthetic-selected-key",
        },
        workingDirectory: home,
      };
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const profileClient = captureProfileClient();
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(
        (options) =>
          codex.startThread(options!) as ReturnType<Codex["startThread"]>,
      );
      try {
        for (const codexOverrides of [
          {},
          { model_providers: { synthetic: { auth: null } } },
          { model_providers: null },
          {
            profile: "review",
            profiles: { review: { model_provider: "synthetic" } },
            model_providers: { synthetic: { auth: null } },
          },
        ] as JsonObject[]) {
          await expect(
            matchScanFindings(
              { before: [finding("before")], after: [finding("after")] },
              { ...options, config: { codexOverrides } },
            ),
          ).rejects.toThrow("conflicts with command authentication");
          expect(startThread).not.toHaveBeenCalled();
        }

        // A complete command provider selected by the caller keeps scan precedence.
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          { ...options, config: { codexOverrides: config } },
        );
        expect(startThread).toHaveBeenCalledTimes(1);
        startThread.mockClear();

        // An ambient profile must not replace that explicitly selected provider.
        await writeFile(
          join(home, "config.toml"),
          stringify({
            profile: "ambient",
            profiles: { ambient: { model_provider: "other" } },
            model_providers: { other: provider },
          }),
        );
        await expect(
          matchScanFindings(
            { before: [finding("before")], after: [finding("after")] },
            { ...options, config: { codexOverrides: config } },
          ),
        ).rejects.toThrow("conflicts with command authentication");
        expect(startThread).not.toHaveBeenCalled();
      } finally {
        profileClient.spy.mockRestore();
        startThread.mockRestore();
      }
    },
  );

  test.each([
    ["default", {}, "elevated"],
    ["elevated", { windows: { sandbox: "elevated" } }, "elevated"],
    ["unelevated", { windows: { sandbox: "unelevated" } }, "unelevated"],
    ["legacy", { features: { elevated_windows_sandbox: false } }, "unelevated"],
    [
      "profile",
      {
        profile: "selected",
        profiles: { selected: { windows: { sandbox: "unelevated" } } },
      },
      "unelevated",
    ],
  ] as const)(
    "keeps MCP servers disabled with %s Windows settings",
    async (name, homeConfig, sandbox) => {
      const home = await temporaryDirectory("codex-security-comparison-");
      await writeFile(
        join(home, "config.toml"),
        stringify({
          ...(name === "profile" ? {} : homeConfig),
          mcp_servers: { inherited: { command: "synthetic-inherited" } },
        }),
      );
      const executable = join(
        home,
        process.platform === "win32" ? "custom-codex.exe" : "custom-codex",
      );
      await copyFile(resolveCodexCommand({}).command, executable);
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        CODEX_CLI_PATH: executable,
        OPENAI_API_KEY: "synthetic-key",
      };
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      let config: CodexOptions["config"];
      let codexPath: string | undefined;
      let codexEnvironment: CodexOptions["env"];
      const startThread = observeCodexOptions(codex, (options) => {
        config = options.config;
        codexPath = options.codexPathOverride;
        codexEnvironment = options.env;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment,
            workingDirectory: home,
            config: {
              codexOverrides: {
                ...(name === "profile" ? homeConfig : {}),
                mcp_servers: {
                  synthetic: {
                    command: "synthetic-integration",
                    enabled: true,
                  },
                },
              },
            },
          },
        );
        expect(config?.["mcp_servers"]).toEqual({
          synthetic: { command: "synthetic-integration", enabled: false },
          inherited: { enabled: false },
        });
        expect(config?.["windows"]).toEqual({ sandbox });
        expect(codexPath).toBe(
          process.platform === "win32"
            ? win32.toNamespacedPath(executable)
            : executable,
        );
        expect(codexEnvironment?.["CODEX_CLI_PATH"]).toBe(executable);
        const effective = await runCodexCommand(
          resolveCodexCommand(environment),
          [
            "-C",
            home,
            "-c",
            'mcp_servers.synthetic.command="synthetic-integration"',
            ...Object.keys(config!["mcp_servers"]!).flatMap((name) => [
              "-c",
              `mcp_servers.${name}.enabled=false`,
            ]),
            "mcp",
            "list",
            "--json",
          ],
          environment,
        );
        expect(effective.success).toBe(true);
        expect(
          JSON.parse(effective.stdout).map(
            (server: { name: string; enabled: boolean }) => ({
              name: server.name,
              enabled: server.enabled,
            }),
          ),
        ).toEqual([
          { name: "inherited", enabled: false },
          { name: "synthetic", enabled: false },
        ]);
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test("preserves environment API-key precedence over managed credentials", async () => {
    const root = await temporaryDirectory("codex-security-comparison-");
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });

    const account = mock(async () => {
      return { authenticated: true, details: "Logged in using ChatGPT" };
    });

    const environment = await comparisonEnvironment(
      {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-key-must-not-be-used",
        CODEX_API_KEY: "synthetic-secondary-must-not-be-used",
      },
      account,
    );

    expect(environment["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
    expect(environment["OPENAI_API_KEY"]).toBe(
      "synthetic-key-must-not-be-used",
    );
    expect(environment["CODEX_API_KEY"]).toBe(
      "synthetic-secondary-must-not-be-used",
    );
    expect(environment["CODEX_HOME"]).toBeUndefined();
    const provider = {
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      CODEX_SECURITY_SCAN_ID: "scan",
      CODEX_HOME: join(root, "provider-home"),
      CODEX_CLI_PATH: "/compatible-codex",
      CODEX_SAFETY_IDENTIFIER: "synthetic-user",
      FIREWORKS_API_KEY: "provider-key",
    };
    expect(await comparisonEnvironment(provider, account)).toEqual(provider);
    expect(account).not.toHaveBeenCalled();
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes provider scan variables regardless of Windows casing",
    async () => {
      const root = await temporaryDirectory("codex-security-comparison-");
      const stateDirectory = join(root, "state");
      const providerHome = join(root, "provider-home");
      await mkdir(join(stateDirectory, "codex-home"), {
        recursive: true,
        mode: 0o700,
      });
      const statusProbed = mock(async () => {
        return { authenticated: true, details: "Logged in using ChatGPT" };
      });
      const provider = {
        codex_security_scan_id: "scan",
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        codex_home: providerHome,
        FIREWORKS_API_KEY: "synthetic-provider-key",
      };

      const environment = await comparisonEnvironment(provider, statusProbed);

      expect(environment).toEqual(provider);
      expect(statusProbed).not.toHaveBeenCalled();
    },
  );

  test.skipIf(process.platform !== "win32")(
    "replaces differently cased Windows CODEX_HOME variables",
    async () => {
      const root = await temporaryDirectory("codex-security-comparison-");
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });

      const environment = await comparisonEnvironment(
        {
          CODEX_SECURITY_STATE_DIR: stateDirectory,
          codex_home: join(root, "ambient-home"),
        },
        async () => ({
          authenticated: true,
          details: "Logged in using ChatGPT",
        }),
        undefined,
        async () => await realpath(credentialHome),
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(environment["codex_home"]).toBeUndefined();
    },
  );

  test("reuses managed keyring credentials when no environment key is present", async () => {
    const root = await temporaryDirectory("codex-security-comparison-");
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let probedHome: string | undefined;

    const environment = await comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, storedEnvironment) => {
        probedHome = storedEnvironment["CODEX_HOME"];
        return { authenticated: true, details: "Logged in using ChatGPT" };
      },
    );

    expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
    expect(probedHome).toBe(await realpath(credentialHome));
  });

  test.skipIf(process.platform === "win32")(
    "uses the canonical keyring identity when the state parent is symlinked",
    async () => {
      const root = await temporaryDirectory("codex-security-comparison-");
      const actualState = join(root, "actual-state");
      const linkedState = join(root, "linked-state");
      const credentialHome = join(actualState, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });
      await symlink(actualState, linkedState, "dir");
      let probedHome: string | undefined;

      const environment = await comparisonEnvironment(
        { CODEX_SECURITY_STATE_DIR: linkedState },
        async (_command, storedEnvironment) => {
          probedHome = storedEnvironment["CODEX_HOME"];
          return { authenticated: true, details: "Logged in using ChatGPT" };
        },
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(probedHome).toBe(await realpath(credentialHome));
    },
  );

  test("forwards cancellation to managed credential-status checks", async () => {
    const root = await temporaryDirectory("codex-security-comparison-");
    const stateDirectory = join(root, "state");
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });
    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    const started = Promise.withResolvers<void>();

    const waiting = comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, _environment, signal) => {
        observedSignal = signal;
        started.resolve();
        await once(signal!, "abort");
        throw signal!.reason;
      },
      controller.signal,
    );
    await started.promise;
    controller.abort(new DOMException("canceled", "AbortError"));

    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
    expect(observedSignal).toBe(controller.signal);
  });

  test("retains API-key authentication when the managed home is not signed in", async () => {
    const root = await temporaryDirectory("codex-security-comparison-");
    const stateDirectory = join(root, "state");
    const ambientHome = join(root, "ambient-codex-home");
    await mkdir(ambientHome, { mode: 0o700 });
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });

    const environment = await comparisonEnvironment(
      {
        CODEX_HOME: ambientHome,
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-comparison-key",
      },
      async () => ({ authenticated: false, details: "Not logged in" }),
    );

    expect(environment["OPENAI_API_KEY"]).toBe("synthetic-comparison-key");
    expect(environment["CODEX_HOME"]).toBe(ambientHome);
  });

  test.skipIf(process.platform === "win32")(
    "recognizes stored credentials in a literal spaced home",
    async () => {
      const root = await temporaryDirectory("codex-security-spaced-home-");
      const home = join(root, " selected home ");
      await mkdir(home);
      await mkdir(home.trim());
      await writeFile(join(home, "auth.json"), "{}");
      const environment = await comparisonEnvironment({
        CODEX_HOME: home,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        OPENAI_API_KEY: "",
      });
      expect(environment["CODEX_HOME"]).toBe(home);
      expect(environment["OPENAI_API_KEY"]).toBeUndefined();
    },
  );

  test.skipIf(process.platform !== "win32")(
    "recognizes stored credentials under a backslash home-relative path",
    async () => {
      const root = await temporaryDirectory("codex-security-comparison-");
      const ambientHome = join(root, "ambient-codex-home");
      await mkdir(ambientHome);
      await writeFile(join(ambientHome, "auth.json"), "{}");
      const environment = await comparisonEnvironment({
        CODEX_HOME: "~\\ambient-codex-home",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        OPENAI_API_KEY: "",
        USERPROFILE: root,
      });

      expect(environment["OPENAI_API_KEY"]).toBeUndefined();
    },
  );

  test("compares small inputs with one restricted structured-output turn", async () => {
    const input: ScanComparisonInput = {
      before: [finding("before-1"), finding("before-2")],
      after: [finding("after-1"), finding("after-2"), finding("after-3")],
    };
    const result = {
      matches: [
        {
          beforeOccurrenceIds: ["before-1"],
          afterOccurrenceIds: ["after-1", "after-2"],
          confidence: "high",
          reason: "The later scan split the same vulnerable extractor.",
        },
      ],
      uncertain: [
        {
          beforeOccurrenceId: "before-2",
          afterOccurrenceId: "after-3",
          reason: "A second entry point might be independently exploitable.",
        },
      ],
    } satisfies ScanComparisonResult;
    const { codex, calls } = fakeCodex(result);
    const controller = new AbortController();

    expect(
      await matchScanFindings(input, {
        codex,
        model: "comparison-model",
        reasoningEffort: "high",
        signal: controller.signal,
        workingDirectory: "/tmp/comparison",
      }),
    ).toEqual(result);
    expect(calls.threadOptions).toEqual({
      threadSource: "security_scan_comparison",
      model: "comparison-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      workingDirectory: "/tmp/comparison",
      skipGitRepoCheck: true,
    });
    expect(calls.turnOptions).toMatchObject({ signal: controller.signal });
    expect(calls.turnOptions?.outputSchema).toMatchObject({
      required: ["matches", "uncertain", "related", "request"],
    });
    const strictObjects = (schema: unknown): void => {
      if (schema === null || typeof schema !== "object") return;
      const object = schema as Record<string, unknown>;
      if (object["type"] === "object") {
        expect(object["required"]).toEqual(
          Object.keys(object["properties"] as object),
        );
        expect(object["additionalProperties"]).toBe(false);
      }
      for (const value of Object.values(object)) strictObjects(value);
    };
    strictObjects(calls.turnOptions?.outputSchema);
    expect(JSON.stringify(calls.turnOptions?.outputSchema)).toContain(
      '"type":"null"',
    );
    expect(calls.prompt).toContain(
      "same underlying root cause and remediation",
    );
    expect(calls.prompt).toContain(
      "same vulnerable helper share one root cause",
    );
    expect(calls.prompt).toContain("every earlier occurrence in one group");
    expect(calls.prompt).toContain("untrusted data");
    expect(calls.prompt).toContain(JSON.stringify(input));
  });

  test("uses the requested scan model and effort for component matching", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    const input = {
      before: [finding("before")],
      after: [finding("after")],
    };
    const config = {
      codexOverrides: {
        model: "configured-model",
        model_reasoning_effort: "high",
        model_provider: "synthetic-provider",
      },
    };
    await matchScanFindings(input, { config, codex });
    expect(calls.threadOptions).toMatchObject({
      model: "configured-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      networkAccessEnabled: false,
    });
    await matchScanFindings(input, {
      config,
      codex,
      model: "explicit-model",
      reasoningEffort: "future-effort",
    });
    expect(calls.threadOptions).toMatchObject({
      model: "explicit-model",
      modelReasoningEffort: "future-effort",
    });
  });

  test("rejects a confirmed match with conflicting same-scan uncertainty", async () => {
    const open = { findingId: "open", occurrenceId: "old-open" };
    const dismissed = { findingId: "dismissed", occurrenceId: "old-dismissed" };
    const after = { findingId: "renamed", occurrenceId: "new-renamed" };
    const commands: Array<{ args: readonly string[]; input?: string }> = [];
    let input: ScanComparisonInput | undefined;
    await expect(
      matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: [open],
        falsePositives: [{ findingId: "dismissed", sourceScanId: "prior" }],
        findings: [after],
        environment: {
          CODEX_HOME: "/provider-home",
          CODEX_SECURITY_SCAN_ID: "current",
          FIREWORKS_API_KEY: "synthetic-provider-key",
        },
        async workbench(args, commandInput) {
          commands.push({ args, input: commandInput });
          return args[0] === "list-unmatched-scan-pairs"
            ? {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    knownFindingGroups: [["dismissed", "historical-alias"]],
                    beforeScans: [
                      {
                        scanId: "another-target",
                        findings: [{ ...dismissed, occurrenceId: "foreign" }],
                      },
                      { scanId: "prior", findings: [open, dismissed] },
                    ],
                  },
                ],
              }
            : {};
        },
        async matchFindings(value, options) {
          input = value;
          expect(options).toMatchObject({
            environment: {
              CODEX_HOME: "/provider-home",
              CODEX_SECURITY_SCAN_ID: "current",
            },
          });
          const response = {
            matches: [
              {
                beforeOccurrenceIds: ["old-dismissed"],
                afterOccurrenceIds: ["new-renamed"],
                confidence: "high",
                reason: "Same dismissed root cause.",
              },
            ],
            uncertain: [
              {
                beforeOccurrenceId: "old-open",
                afterOccurrenceId: "new-renamed",
                reason: "Possible match.",
              },
            ],
          };
          return await matchScanFindings(value, {
            ...options,
            codex: fakeCodex(response).codex,
          });
        },
      }),
    ).rejects.toThrow("conflicting confirmed and uncertain findings");
    expect(input).toEqual({
      before: [open, dismissed],
      after: [after],
      knownFindingGroups: [["dismissed", "historical-alias"]],
    });
    expect(commands.map(({ args: [command] }) => command)).toEqual([
      "list-unmatched-scan-pairs",
    ]);
  });

  test("compares complete selected scans before caching automatic matches", async () => {
    const firstShared = { findingId: "shared", occurrenceId: "first-shared" };
    const firstOther = { findingId: "other", occurrenceId: "first-other" };
    const latestShared = { findingId: "shared", occurrenceId: "latest-shared" };
    const unselected = { findingId: "unselected", occurrenceId: "unselected" };
    const after = { findingId: "renamed", occurrenceId: "current-renamed" };
    const saved = new Map<string, ScanComparisonResult>();
    const matchFindings = mock<typeof matchScanFindings>((input, options) => {
      return matchScanFindings(input, { ...options, codex: model.codex });
    });
    const model = fakeCodex({
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: latestShared.occurrenceId,
          afterOccurrenceId: after.occurrenceId,
          reason: "The synthetic control may have moved.",
        },
      ],
    });

    await matchCompletedScan({
      scanId: "current",
      repository: "/repository",
      previousFindings: [firstOther, latestShared],
      falsePositives: [],
      findings: [after],
      cyberAccessProgram: "daybreak_red",
      async workbench(args, commandInput) {
        if (args[0] === "list-unmatched-scan-pairs") {
          return {
            batches: [
              {
                afterScanId: "current",
                afterFindings: [after],
                beforeScans: [
                  { scanId: "unselected", findings: [unselected] },
                  { scanId: "first", findings: [firstShared, firstOther] },
                  { scanId: "latest", findings: [latestShared] },
                ],
              },
            ],
          };
        }
        saved.set(args[2]!, JSON.parse(commandInput!) as ScanComparisonResult);
        return {};
      },
      matchFindings,
    });

    expect(matchFindings.mock.lastCall?.[0]).toEqual({
      before: [firstShared, firstOther, latestShared],
      after: [after],
    });
    expect(model.calls.turnOptions?.cyberAccessProgram).toBe("daybreak_red");
    expect([...saved.keys()]).toEqual(["first", "latest"]);
    for (const [scanId, occurrenceId] of [
      ["first", firstShared.occurrenceId],
      ["latest", latestShared.occurrenceId],
    ] as const) {
      expect(saved.get(scanId)).toEqual({
        matches: [],
        uncertain: [
          {
            beforeOccurrenceId: occurrenceId,
            afterOccurrenceId: after.occurrenceId,
            reason: "The synthetic control may have moved.",
          },
        ],
      });
    }
  });

  test.each([
    ["no history", false, false, false, 0, false],
    ["a stable identity", true, false, true, 2, false],
    ["a renamed dismissed identity", false, true, false, 2, true],
  ] as const)(
    "only starts a model turn when needed for %s",
    async (
      _scenario,
      open,
      dismissed,
      stable,
      expectedCalls,
      expectedModel,
    ) => {
      const before = { findingId: "previous", occurrenceId: "old" };
      const after = {
        findingId: stable ? "previous" : "new",
        occurrenceId: "new",
      };
      const workbench = mock(async (args: readonly string[]) => {
        return args[0] === "list-unmatched-scan-pairs"
          ? {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: [after],
                  beforeScans: [{ scanId: "prior", findings: [before] }],
                },
              ],
            }
          : {};
      });
      const model = fakeCodex({ matches: [], uncertain: [] });
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: open ? [before] : [],
        falsePositives: dismissed
          ? [{ findingId: "previous", sourceScanId: "prior" }]
          : [],
        findings: [after],
        workbench,
        matchFindings: (input, options) =>
          matchScanFindings(input, { ...options, codex: model.codex }),
      });
      expect(workbench).toHaveBeenCalledTimes(expectedCalls);
      expect(model.calls.prompt !== undefined).toBe(expectedModel);
    },
  );

  test.each(["split", "combined", "confirmed alias"] as const)(
    "retains known identities when a later finding is %s",
    async (scenario) => {
      const oldA = { findingId: "identity-a", occurrenceId: "old-a" };
      const oldB = { findingId: "identity-b", occurrenceId: "old-b" };
      const newA = { findingId: "identity-a", occurrenceId: "new-a" };
      const newB = { findingId: "identity-b", occurrenceId: "new-b" };
      const before = scenario === "combined" ? [oldA, oldB] : [oldA];
      const after =
        scenario === "split"
          ? [newA, newB]
          : scenario === "combined"
            ? [newA]
            : [newB];
      const knownFindingGroups =
        scenario === "confirmed alias"
          ? [["identity-a", "identity-b"]]
          : undefined;
      const model = fakeCodex({
        matches: [
          {
            beforeOccurrenceIds: before.map(({ occurrenceId }) => occurrenceId),
            afterOccurrenceIds: after.map(({ occurrenceId }) => occurrenceId),
            confidence: "high",
            reason: "The scan split or combined the same defective control.",
          },
        ],
        uncertain: [],
      });
      const saved: ScanComparisonResult[] = [];
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: before,
        falsePositives: [],
        findings: after,
        async workbench(args, commandInput) {
          if (args[0] === "list-unmatched-scan-pairs") {
            return {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: after,
                  beforeScans: [{ scanId: "prior", findings: before }],
                  knownFindingGroups,
                },
              ],
            };
          }
          saved.push(JSON.parse(commandInput!) as ScanComparisonResult);
          return {};
        },
        async matchFindings(input, options) {
          expect(input).toEqual({
            before,
            after,
            ...(knownFindingGroups === undefined ? {} : { knownFindingGroups }),
          });
          return await matchScanFindings(input, {
            ...options,
            codex: model.codex,
          });
        },
      });
      expect(model.calls.prompt !== undefined).toBe(
        scenario !== "confirmed alias",
      );
      expect(saved).toEqual([
        {
          matches: [
            expect.objectContaining({
              beforeOccurrenceIds: before.map(
                ({ occurrenceId }) => occurrenceId,
              ),
              afterOccurrenceIds: after.map(({ occurrenceId }) => occurrenceId),
            }),
          ],
          uncertain: [],
        },
      ]);
    },
  );

  test.each(["new", "resolved", "split", "combined"] as const)(
    "preserves deterministic matches while reconciling a %s issue",
    async (scenario) => {
      const oldA = { findingId: "identity-a", occurrenceId: "old-a" };
      const oldB = { findingId: "identity-b", occurrenceId: "old-b" };
      const newA = { findingId: "identity-a", occurrenceId: "new-a" };
      const newB = { findingId: "identity-b", occurrenceId: "new-b" };
      const before =
        scenario === "resolved" || scenario === "combined"
          ? [oldA, oldB]
          : [oldA];
      const after =
        scenario === "new" || scenario === "split" ? [newA, newB] : [newA];
      const extendsKnown = scenario === "split" || scenario === "combined";
      const saved: ScanComparisonResult[] = [];
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: before,
        falsePositives: [],
        findings: after,
        async workbench(args, commandInput) {
          if (args[0] === "list-unmatched-scan-pairs")
            return {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: after,
                  beforeScans: [{ scanId: "prior", findings: before }],
                },
              ],
            };
          saved.push(JSON.parse(commandInput!) as ScanComparisonResult);
          return {};
        },
        async matchFindings(input, options) {
          const response = {
            matches: extendsKnown
              ? [
                  {
                    beforeOccurrenceIds: [
                      scenario === "split"
                        ? oldA.occurrenceId
                        : oldB.occurrenceId,
                    ],
                    afterOccurrenceIds: [
                      scenario === "split"
                        ? newB.occurrenceId
                        : newA.occurrenceId,
                    ],
                    confidence: "high",
                    reason: "The same control was split or combined.",
                  },
                ]
              : [],
            uncertain: extendsKnown
              ? []
              : [
                  {
                    beforeOccurrenceId: oldA.occurrenceId,
                    afterOccurrenceId: newA.occurrenceId,
                    reason: "The model omitted the proven identity.",
                  },
                ],
            related:
              scenario === "resolved"
                ? []
                : [
                    {
                      beforeOccurrenceId: oldA.occurrenceId,
                      afterOccurrenceId:
                        scenario === "new"
                          ? newB.occurrenceId
                          : newA.occurrenceId,
                      reason: "A related control.",
                    },
                  ],
          };
          return await matchScanFindings(input, {
            ...options,
            codex: fakeCodex(response).codex,
          });
        },
      });
      expect(saved).toHaveLength(1);
      expect(saved[0]!.matches).toHaveLength(1);
      expect(new Set(saved[0]!.matches[0]!.beforeOccurrenceIds)).toEqual(
        new Set(
          (extendsKnown ? before : [oldA]).map(
            ({ occurrenceId }) => occurrenceId,
          ),
        ),
      );
      expect(new Set(saved[0]!.matches[0]!.afterOccurrenceIds)).toEqual(
        new Set(
          (extendsKnown ? after : [newA]).map(
            ({ occurrenceId }) => occurrenceId,
          ),
        ),
      );
      expect(saved[0]!.uncertain).toEqual([]);
      expect(saved[0]!.related).toHaveLength(scenario === "new" ? 1 : 0);
    },
  );

  test("rejects malformed model JSON", async () => {
    const { codex } = fakeCodex("not-json");
    await expect(
      matchScanFindings(
        { before: [finding("before")], after: [finding("after")] },
        { codex },
      ),
    ).rejects.toThrow("invalid JSON");
  });

  test("does not start Codex when either scan has no findings", async () => {
    const codex: NonNullable<ScanComparisonOptions["codex"]> = {
      startThread: () => fail("No model is needed."),
    };
    for (const input of [
      { before: [], after: [finding("after")] },
      { before: [finding("before")], after: [] },
    ]) {
      expect(await matchScanFindings(input, { codex })).toEqual({
        matches: [],
        uncertain: [],
      });
    }
  });

  test.each([
    ["empty", { before: [finding(" ")], after: [] }],
    [
      "same-scan duplicate",
      { before: [finding("duplicate"), finding("duplicate")], after: [] },
    ],
    [
      "cross-scan duplicate",
      {
        before: [finding("duplicate")],
        after: [finding("duplicate")],
      },
    ],
  ])("rejects %s occurrence IDs before matching", async (_, input) => {
    const codex: NonNullable<ScanComparisonOptions["codex"]> = {
      startThread: () => fail("No model should start for invalid input."),
    };

    await expect(matchScanFindings(input, { codex })).rejects.toThrow(
      "must be nonempty and globally unique",
    );
  });

  test("allows cross-history uncertainty without relaxing two-scan matching", async () => {
    const input: ScanComparisonInput = {
      before: [
        { occurrenceId: "before-confirmed", findingId: "shared" },
        { occurrenceId: "before-uncertain", findingId: "other" },
      ],
      after: [{ occurrenceId: "after-shared", findingId: "shared" }],
    };
    const modelResponse = {
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: "before-uncertain",
          afterOccurrenceId: "after-shared",
          reason: "Uncertain in another historical scan.",
        },
      ],
    } satisfies ScanComparisonResult;

    await expect(
      matchScanFindings(input, { codex: fakeCodex(modelResponse).codex }),
    ).rejects.toThrow("invalid uncertain pair");
    const response = await matchScanFindings(input, {
      codex: fakeCodex(modelResponse).codex,
      allowHistoricalUncertainty: true,
    });
    expect(response).toEqual({
      matches: [
        {
          beforeOccurrenceIds: ["before-confirmed"],
          afterOccurrenceIds: ["after-shared"],
          confidence: "high",
          reason:
            "The findings share a stable identity or a previously confirmed link.",
        },
      ],
      uncertain: modelResponse.uncertain,
    });
    expect(comparisonForScan(response, [input.before[0]!])).toEqual({
      matches: response.matches,
      uncertain: [],
    });
    expect(comparisonForScan(response, [input.before[1]!])).toEqual({
      matches: [],
      uncertain: modelResponse.uncertain,
    });
    expect(() => comparisonForScan(response, input.before)).toThrow(
      "conflicting confirmed and uncertain findings",
    );
  });

  test("honors confirmed historical groups and preserves distinct related findings", async () => {
    const input = {
      before: [
        { occurrenceId: "before-known", findingId: "known-a" },
        { occurrenceId: "before-related", findingId: "related-a" },
      ],
      after: [
        { occurrenceId: "after-known", findingId: "known-b" },
        { occurrenceId: "after-related", findingId: "related-b" },
      ],
      knownFindingGroups: [["known-a", "known-b"]],
    };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["before-known"],
          afterOccurrenceIds: ["after-known"],
          confidence: "high" as const,
          reason: "Previously confirmed root cause.",
        },
      ],
      uncertain: [],
      related: [
        {
          beforeOccurrenceId: "before-related",
          afterOccurrenceId: "after-related",
          reason: "Related controls remain independently vulnerable.",
        },
      ],
    };
    const { codex, calls } = fakeCodex(response);

    expect(await matchScanFindings(input, { codex })).toEqual(response);
    expect(JSON.parse(calls.prompt!.split("\n").at(-1)!)).toMatchObject({
      findings: {
        before: [
          { occurrenceId: "before-known", issueId: "known-a" },
          { occurrenceId: "before-related", issueId: "related-a" },
        ],
      },
    });
  });

  test.each([
    ["confirmed aliases", ["a"], ["b"], [["a", "b"]]],
    [
      "overlapping aliases",
      ["a"],
      ["c"],
      [
        ["a", "b"],
        ["b", "c"],
      ],
    ],
    ["repeated stable identities", ["same", "same"], ["same", "same"], []],
  ] as const)(
    "confirms %s without starting Codex",
    async (_scenario, before, after, knownFindingGroups) => {
      const input = {
        before: before.map((findingId, index) => ({
          occurrenceId: `before-${index}`,
          findingId,
        })),
        after: after.map((findingId, index) => ({
          occurrenceId: `after-${index}`,
          findingId,
        })),
        knownFindingGroups,
      };
      const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
      expect(await matchScanFindings(input, { codex })).toEqual({
        matches: [
          {
            beforeOccurrenceIds: input.before.map(
              ({ occurrenceId }) => occurrenceId,
            ),
            afterOccurrenceIds: input.after.map(
              ({ occurrenceId }) => occurrenceId,
            ),
            confidence: "high",
            reason: expect.any(String),
          },
        ],
        uncertain: [],
      });
      expect(calls.prompt).toBeUndefined();
    },
  );

  test("never accepts uncertainty between occurrences of the same stable finding", async () => {
    const input = {
      before: [{ occurrenceId: "before", findingId: "shared-identity" }],
      after: [{ occurrenceId: "after", findingId: "shared-identity" }],
    };
    const response = {
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: "before",
          afterOccurrenceId: "after",
          reason: "Incorrectly treats the same stable identity as uncertain.",
        },
      ],
    };

    const requiringModel = {
      before: [
        ...input.before,
        { occurrenceId: "other-before", findingId: "other-before" },
      ],
      after: [
        ...input.after,
        { occurrenceId: "other-after", findingId: "other-after" },
      ],
    };
    const contradictory = fakeCodex(response);
    expect(
      await matchScanFindings(requiringModel, { codex: contradictory.codex }),
    ).toEqual({
      matches: [
        {
          beforeOccurrenceIds: ["before"],
          afterOccurrenceIds: ["after"],
          confidence: "high",
          reason:
            "The findings share a stable identity or a previously confirmed link.",
        },
      ],
      uncertain: [],
    });
    expect(contradictory.calls.prompt).toBeDefined();
  });

  test("never lets a model split a confirmed historical group", async () => {
    const input = {
      before: [
        { occurrenceId: "before-a", findingId: "known-a" },
        { occurrenceId: "before-b", findingId: "known-b" },
      ],
      after: [{ occurrenceId: "after", findingId: "new" }],
      knownFindingGroups: [["known-a", "known-b"]],
    };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["before-a"],
          afterOccurrenceIds: ["after"],
          confidence: "high" as const,
          reason: "Incorrectly separates a confirmed identity.",
        },
      ],
      uncertain: [],
    };

    const invalid = fakeCodex(response);

    await expect(
      matchScanFindings(input, { codex: invalid.codex }),
    ).rejects.toThrow("unknown before occurrence");
    expect(JSON.parse(invalid.calls.prompt!.split("\n").at(-1)!)).toMatchObject(
      {
        findings: {
          before: [
            {
              occurrenceId: "before-b",
              occurrenceCount: 2,
              issueId: "known-a",
            },
          ],
        },
      },
    );

    const valid = {
      ...response,
      matches: [
        {
          ...response.matches[0]!,
          beforeOccurrenceIds: ["before-b"],
        },
      ],
    };
    expect(
      await matchScanFindings(input, { codex: fakeCodex(valid).codex }),
    ).toMatchObject({
      matches: [
        {
          beforeOccurrenceIds: ["before-a", "before-b"],
          afterOccurrenceIds: ["after"],
          confidence: "high",
        },
      ],
      uncertain: [],
    });
  });

  const match = (beforeOccurrenceIds = ["before-1"]) => ({
    beforeOccurrenceIds,
    afterOccurrenceIds: ["after-1"],
    confidence: "high" as const,
    reason: "Same root cause.",
  });
  const uncertain = (afterOccurrenceId = "after-1") => ({
    beforeOccurrenceId: "before-1",
    afterOccurrenceId,
    reason: "Possible root cause.",
  });

  test.each([
    {
      label: "missing arrays",
      result: {},
      error: "invalid match result",
    },
    {
      label: "unexpected result fields",
      result: { matches: [], uncertain: [], unexpected: true },
      error: "invalid match result",
    },
    {
      label: "blank match reasons",
      result: { matches: [{ ...match(), reason: " " }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "malformed related pairs",
      result: {
        matches: [],
        uncertain: [],
        related: [{ ...uncertain(), beforeOccurrenceId: 1 }],
      },
      error: "invalid match result",
    },
    {
      label: "low confidence",
      result: { matches: [{ ...match(), confidence: "low" }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "empty groups",
      result: { matches: [match([])], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "invented occurrences",
      result: { matches: [match(["invented"])], uncertain: [] },
      error: "unknown before occurrence",
    },
    {
      label: "repeated occurrences",
      result: { matches: [match(), match()], uncertain: [] },
      error: "before occurrence more than once",
    },
    {
      label: "invented uncertain occurrences",
      result: { matches: [], uncertain: [uncertain("invented")] },
      error: "invalid uncertain pair",
    },
    {
      label: "uncertainty already matched with confidence",
      result: { matches: [match()], uncertain: [uncertain()] },
      error: "invalid uncertain pair",
    },
    {
      label: "duplicate uncertain pairs",
      result: { matches: [], uncertain: [uncertain(), uncertain()] },
      error: "duplicate uncertain pair",
    },
    {
      label: "invented related occurrences",
      result: {
        matches: [],
        uncertain: [],
        related: [uncertain("invented")],
      },
      error: "invalid related pair",
    },
    {
      label: "duplicate related pairs",
      result: {
        matches: [],
        uncertain: [],
        related: [uncertain(), uncertain()],
      },
      error: "invalid related pair",
    },
    {
      label: "related pairs that contradict confirmed matches",
      result: {
        matches: [match()],
        uncertain: [],
        related: [uncertain()],
      },
      error: "invalid related pair",
    },
    {
      label: "related pairs that duplicate uncertainty",
      result: {
        matches: [],
        uncertain: [uncertain()],
        related: [uncertain()],
      },
      error: "invalid related pair",
    },
  ])("rejects $label", async ({ result, error }) => {
    const { codex } = fakeCodex(result);
    await expect(
      matchScanFindings(
        { before: [finding("before-1")], after: [finding("after-1")] },
        { codex },
      ),
    ).rejects.toThrow(error);
  });
});
