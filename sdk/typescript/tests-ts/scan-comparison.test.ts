import { execFileSync } from "node:child_process";
import * as childProcess from "node:child_process";
import { fixtureSpawn } from "./support/codex-process.js";
import { createPermissionCheckedCodex } from "../src/permission-profile.js";
import { once } from "node:events";
import {
  copyFile,
  mkdir,
  rm,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, relative, win32 } from "node:path";
import { pathToFileURL } from "node:url";
import { parse, stringify } from "smol-toml";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { resolveCodexCommand, runCodexCommand } from "../src/runtime.js";
import * as runtime from "../src/runtime.js";
import {
  DEFAULT_CODEX_CONFIG,
  deepMerge,
  type JsonObject,
} from "../src/config.js";
import { CodexSecurityError } from "../src/errors.js";
import {
  comparisonForScan,
  comparisonEnvironment,
  disabledMcpServers,
  matchCompletedScan,
  matchScanFindings,
  matchScanFindingsInternal,
  runReadOnlyCodex,
  unionFindingGroups,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";
import { temporaryDirectory as createTemporaryDirectory } from "./support/temporary-directories.js";
import { fail } from "./support/errors.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(async (path) => {
      // Bun 1.3.13 ignores fs.rm's retry options.
      for (let attempt = 0; ; attempt++) {
        try {
          await rm(path, { recursive: true, force: true });
          return;
        } catch (error) {
          if (
            (error as NodeJS.ErrnoException).code !== "EBUSY" ||
            attempt === 10
          )
            throw error;
          await Bun.sleep(100 * (attempt + 1));
        }
      }
    }),
  );
});

async function temporaryDirectory(prefix = "codex-security-comparison-") {
  const path = await createTemporaryDirectory(prefix, false);
  temporaryDirectories.push(path);
  return path;
}

function launchConfig(overrides: readonly string[]): JsonObject {
  return overrides.reduce(
    (config, value) => deepMerge(config, parse(value) as JsonObject),
    {},
  );
}

function argvConfig(argv: readonly string[]): JsonObject {
  return launchConfig(
    argv.flatMap((value, index) =>
      value === "--config" ? [argv[index + 1]!] : [],
    ),
  );
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
          return {
            finalResponse:
              typeof response === "string"
                ? response
                : JSON.stringify(response),
          };
        },
      };
    },
  };
  return { codex, calls };
}

describe("semantic scan comparison", () => {
  test("reconciles finding groups with native Node 20 built-ins", () => {
    const script = `
Reflect.deleteProperty(Map, "groupBy");
const { matchScanFindings } = await import(${JSON.stringify(new URL("../src/scan-comparison.ts", import.meta.url).href)});
const input = {
  before: [{ findingId: "same-control", occurrenceId: "old" }],
  after: [
    { findingId: "same-control", occurrenceId: "retained" },
    { findingId: "split-control", occurrenceId: "split" },
  ],
};
const response = {
  matches: [{ beforeOccurrenceIds: ["old"], afterOccurrenceIds: ["split"], confidence: "high", reason: "The same control was split." }],
  uncertain: [],
};
const codex = { startThread() { return { async run() { return { finalResponse: JSON.stringify(response) }; } }; } };
console.log(JSON.stringify(await matchScanFindings(input, { codex })));
`;
    const result = JSON.parse(
      execFileSync(process.execPath, ["-e", script], { encoding: "utf8" }),
    ) as ScanComparisonResult;
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      beforeOccurrenceIds: ["old"],
      afterOccurrenceIds: ["split", "retained"],
      confidence: "high",
    });
    expect(result.uncertain).toEqual([]);
  });

  test("keeps the first accepted identity when joining finding groups", () => {
    expect(
      unionFindingGroups([
        ["accepted-a", "repeated-a"],
        ["accepted-b", "repeated-b"],
        ["separate"],
        ["repeated-b", "repeated-a", "new-a", "new-a"],
        ["", " ", "independent-a"],
        ["", "independent-b"],
      ]),
    ).toEqual([
      ["accepted-a", "repeated-a", "accepted-b", "repeated-b", "new-a"],
      ["separate"],
      ["independent-a"],
      ["independent-b"],
    ]);
    expect(unionFindingGroups([])).toEqual([]);
  });

  test.each([{}, { codexOverrides: { model_reasoning_effort: "high" } }])(
    "merges default model settings for an injected client with %j",
    async (config) => {
      const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
      await matchScanFindings(
        { before: [finding("before")], after: [finding("after")] },
        { codex, config },
      );
      expect(calls.threadOptions).toMatchObject({
        model: DEFAULT_CODEX_CONFIG["model"],
        modelReasoningEffort:
          config.codexOverrides?.model_reasoning_effort ??
          DEFAULT_CODEX_CONFIG["model_reasoning_effort"],
      });
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

  test.each(["root", "profile"])(
    "applies matcher restrictions after resolving %s settings",
    async (location) => {
      const home = await temporaryDirectory("prepared-matcher-");
      await writeFile(
        join(home, "config.toml"),
        "invalid competing config = [",
      );
      const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
      let prepared: CodexOptions | undefined;
      const configuration = {
        model: "gpt-6-astra",
        model_reasoning_effort: "ultra",
        model_provider: "synthetic",
        model_providers: {
          synthetic: { name: "Synthetic", env_key: "SYNTHETIC_KEY" },
        },
        mcp_servers: { selected: { command: "synthetic-mcp" } },
        features: { plugins: true, shell_tool: true },
        plugins: { "codex-security@synthetic": { enabled: true } },
        default_permissions: "writable",
        sandbox_mode: "workspace-write",
      };
      await matchScanFindingsInternal(
        { before: [finding("before")], after: [finding("after")] },
        {
          config: {
            codexOverrides:
              location === "root"
                ? configuration
                : {
                    profile: "selected",
                    profiles: { selected: configuration },
                  },
          },
          environment: {
            CODEX_HOME: home,
            CODEX_CLI_PATH: join(home, "absent"),
          },
          inheritedPermissions: {
            filesystem: { "/private": "deny" },
            network: { enabled: true },
          },
          createCodex(options) {
            prepared = options;
            return codex;
          },
        },
        { surface: "sdk" },
      );
      expect(prepared?.config?.["model_provider"]).toBe("synthetic");
      expect(prepared?.config?.["model_providers"]).toEqual({
        synthetic: { name: "Synthetic", env_key: "SYNTHETIC_KEY" },
      });
      expect(prepared?.config?.["mcp_servers"]).toEqual({
        selected: { command: "synthetic-mcp", enabled: false },
      });
      expect(prepared?.config?.["features"]).toMatchObject({
        plugins: false,
        shell_tool: false,
        multi_agent_v2: false,
      });
      expect(prepared?.config?.["default_permissions"]).toBe(
        "codex_security_comparison",
      );
      expect(prepared?.config?.["profile"]).toBeUndefined();
      expect(prepared?.config?.["profiles"]).toBeUndefined();
      expect(prepared?.config?.["sandbox_mode"]).toBeUndefined();
      const permissionOverride = prepared?.configOverrides?.find((value) =>
        value.startsWith("permissions.codex_security_comparison="),
      );
      expect(permissionOverride).toBeDefined();
      expect(parse(permissionOverride!)).toMatchObject({
        permissions: {
          codex_security_comparison: {
            filesystem: { "/private": "deny" },
            network: { enabled: false },
          },
        },
      });
      expect(calls.threadOptions).toMatchObject({
        model: "gpt-6-astra",
        modelReasoningEffort: "ultra",
        networkAccessEnabled: false,
        approvalPolicy: "never",
      });
      expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
        "invalid competing config = [",
      );
    },
  );

  test.each([undefined, false, true])(
    "runs permission-checked matching with optional API-key features %p",
    async (feature) => {
      const home = await temporaryDirectory("checked-matcher-features-");
      const captures = join(home, "launches.jsonl");
      const script = join(home, "matcher.mjs");
      await writeFile(
        script,
        `
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(captures)}, JSON.stringify(process.argv.slice(2)) + "\\n");
await new Promise(resolve => { process.stdin.resume(); process.stdin.on("end", resolve); });
console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-comparison" }));
console.log(JSON.stringify({ type: "item.completed", item: {
  id: "answer", type: "agent_message", text: '{"matches":[],"uncertain":[]}'
} }));
console.log(JSON.stringify({ type: "turn.completed", usage: {
  input_tokens: 1, cached_input_tokens: 0, output_tokens: 1
} }));
`,
      );
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        OPENAI_API_KEY: "synthetic-key",
      };
      const command = resolveCodexCommand(environment);
      const originalSpawn = childProcess.spawn;
      const executionSpawn = fixtureSpawn(command.command, script, () => {});
      let preflights = 0;
      const spawning = spyOn(childProcess, "spawn").mockImplementation(((
        ...args: Parameters<typeof childProcess.spawn>
      ) => {
        if (Array.isArray(args[1]) && args[1].includes("app-server")) {
          preflights++;
          return originalSpawn(...args);
        }
        return executionSpawn(...args);
      }) as typeof childProcess.spawn);
      try {
        await matchScanFindingsInternal(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment,
            workingDirectory: home,
            config: {
              codexOverrides: {
                model: "synthetic-model",
                model_reasoning_effort: "medium",
                features:
                  feature === undefined
                    ? {}
                    : {
                        api_key_cyber_access_programs: feature,
                        api_key_model_discovery: feature,
                      },
              },
            },
            inheritedPermissions: {
              filesystem: { [join(home, "private")]: "deny" },
              network: { enabled: true },
            },
            createCodex(options) {
              const checked = createPermissionCheckedCodex({
                ...options,
                codexPathOverride: command.command,
                env: Object.fromEntries(
                  Object.entries(environment).filter(
                    (entry): entry is [string, string] =>
                      entry[1] !== undefined,
                  ),
                ),
              });
              return {
                startThread(options) {
                  const thread = checked.startThread(options);
                  return {
                    async run(input, options) {
                      const { events } = await thread.runStreamed(
                        input,
                        options,
                      );
                      let finalResponse = "";
                      for await (const event of events) {
                        if (
                          event.type === "item.completed" &&
                          event.item.type === "agent_message"
                        )
                          finalResponse = event.item.text;
                      }
                      return { finalResponse };
                    },
                  };
                },
              };
            },
          },
          { surface: "sdk" },
        );
        expect(preflights).toBe(1);
        const argv = JSON.parse(
          (await readFile(captures, "utf8")).trim(),
        ) as string[];
        const overrides = argv.flatMap((value, index) =>
          value === "--config" ? [argv[index + 1]!] : [],
        );
        const config = Object.assign(
          {},
          ...overrides.map((value) => parse(value)),
        );
        expect(config.features.api_key_cyber_access_programs).toBe(feature);
        expect(config.features.api_key_model_discovery).toBe(feature);
        expect(config.features).toMatchObject({
          plugins: false,
          shell_tool: false,
        });
        expect(
          config.permissions.codex_security_comparison.filesystem[
            join(home, "private")
          ],
        ).toBe("deny");
        expect(
          config.permissions.codex_security_comparison.network.enabled,
        ).toBe(false);
      } finally {
        spawning.mockRestore();
      }
    },
  );

  test("retains inherited read restrictions without writes at the matcher process boundary", async () => {
    const home = await temporaryDirectory(
      "codex-security-matcher-permissions-",
    );
    const captures = join(home, "launches.jsonl");
    const preload = join(home, "capture.mjs");
    await writeFile(
      preload,
      `
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(captures)}, JSON.stringify(process.argv.slice(1)) + "\\n");
await new Promise((resolve) => { process.stdin.resume(); process.stdin.on("end", resolve); });
console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-comparison" }));
console.log(JSON.stringify({ type: "item.completed", item: {
  id: "answer", type: "agent_message", text: '{"matches":[],"uncertain":[]}'
} }));
console.log(JSON.stringify({ type: "turn.completed", usage: {
  input_tokens: 1, cached_input_tokens: 0, output_tokens: 1
} }));
process.exit(0);
`,
    );
    const nodeExecutable = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    const inheritedPermissions: {
      filesystem: Record<string, string | number | Record<string, string>>;
      network: { enabled: boolean };
    } = {
      filesystem: {
        ":workspace_roots": "write",
        [join(home, "scoped")]: { ".": "write", private: "deny" },
        [join(home, "literal.[private]")]: { ".": "deny" },
        [join(home, "**", "*.secret")]: "deny",
        glob_scan_max_depth: 3,
      },
      network: { enabled: true },
    };
    const originalStartThread = Codex.prototype.startThread;
    const startThread = spyOn(
      Codex.prototype,
      "startThread",
    ).mockImplementation(function (this: Codex, options) {
      const original = (this as unknown as { options: CodexOptions }).options;
      return originalStartThread.call(
        new Codex({
          ...original,
          codexPathOverride: nodeExecutable,
          env: {
            ...original.env,
            NODE_OPTIONS: `--import=${JSON.stringify(pathToFileURL(preload).href)}`,
          },
        }),
        options,
      );
    });
    try {
      for (const [constraints, injected] of [
        [inheritedPermissions, false],
        [undefined, false],
        [inheritedPermissions, true],
      ] as const) {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              TEMP: process.env["TEMP"],
              TMP: process.env["TMP"],
              CODEX_HOME: home,
              CODEX_SECURITY_SCAN_ID: "synthetic-scan",
              OPENAI_API_KEY: "synthetic-key",
            },
            workingDirectory: home,
            inheritedPermissions: constraints,
            codex: injected
              ? new Codex({ config: { sandbox_mode: "workspace-write" } })
              : undefined,
            config:
              constraints === undefined
                ? {
                    codexOverrides: {
                      profile: "selected",
                      profiles: { selected: { default_permissions: "custom" } },
                      permissions: {
                        custom: {
                          filesystem: {
                            [home]: "read",
                            ":workspace_roots": "write",
                          },
                          network: { enabled: true },
                        },
                      },
                    },
                  }
                : {
                    codexOverrides: {
                      default_permissions: "native",
                      permissions: { native: constraints },
                      projects: {
                        [join(home, "literal.[private]")]: {
                          trust_level: "untrusted",
                        },
                      },
                    },
                  },
          },
        );
      }
      const [constrained, ordinary, injected] = (
        await readFile(captures, "utf8")
      )
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as string[]);
      const overrides = constrained!.flatMap((value, index) =>
        value === "--config" ? [constrained![index + 1]!] : [],
      );
      const permissionOverride = overrides.find((value) =>
        value.startsWith("permissions.codex_security_comparison="),
      );
      expect(parse(permissionOverride!)).toEqual({
        permissions: {
          codex_security_comparison: {
            extends: ":read-only",
            filesystem: {
              ...inheritedPermissions.filesystem,
              ":workspace_roots": "read",
              [join(home, "scoped")]: { ".": "read", private: "deny" },
            },
            network: { enabled: false },
          },
        },
      });
      expect(overrides).toContain(
        'default_permissions="codex_security_comparison"',
      );
      expect(overrides).toContain('approval_policy="never"');
      expect(launchConfig(overrides)["features"]).toMatchObject({
        shell_tool: false,
        plugins: false,
      });
      expect(constrained).not.toContain("--sandbox");
      expect(
        overrides.some((value) => value.startsWith("permissions.native")),
      ).toBe(false);
      expect(overrides.some((value) => value.startsWith("projects."))).toBe(
        false,
      );
      expect(ordinary![ordinary!.indexOf("--sandbox") + 1]).toBe("read-only");
      expect(injected![injected!.indexOf("--sandbox") + 1]).toBe("read-only");
      expect(
        ordinary!.some((value) => value.startsWith("default_permissions=")),
      ).toBe(false);
      expect(
        ordinary!.some((value) => value.includes("codex_security_comparison")),
      ).toBe(false);
      expect(inheritedPermissions.filesystem[":workspace_roots"]).toBe("write");
      expect(inheritedPermissions.filesystem[join(home, "scoped")]).toEqual({
        ".": "write",
        private: "deny",
      });
    } finally {
      startThread.mockRestore();
    }
  });

  test.each([
    ...["synthetic-provider", "synthetic.provider", 'synthetic."provider"'].map(
      (name) => ({
        name,
        provider: {
          name: "Synthetic inherited",
          base_url: "https://provider.example.test/v1",
          wire_api: "responses",
          env_key: "SYNTHETIC_PROVIDER_KEY",
        },
        ambient: false,
        selection: "home-definition" as const,
      }),
    ),
    {
      name: "custom",
      provider: { name: "Synthetic", env_key: "OPENAI_API_KEY" },
      ambient: false,
    },
    {
      name: "custom",
      provider: {
        name: "Synthetic",
        auth: { type: "command", command: "synthetic-auth-provider" },
      },
      ambient: false,
    },
    {
      name: "custom",
      provider: {
        name: "Synthetic",
        base_url: "https://provider.example.test/v1",
        wire_api: "responses",
        auth: { command: "synthetic-auth-provider" },
      },
      ambient: false,
      selection: "home-profile",
    },
    ...(["home-profile", "override-profile"] as const).map((selection) => ({
      name: "custom",
      provider: {
        auth: {
          command: "./profile-auth",
          args: ["--account", "profile-account"],
          cwd: "profile-helpers",
        },
      },
      rootProvider: {
        auth: {
          command: "./root-auth",
          args: ["--account", "root-account"],
          cwd: "root-helpers",
        },
      },
      ambient: false,
      selection,
    })),
    ...(["auto", "api-key"] as const).map((auth) => ({
      name: "openai",
      provider: {},
      ambient: false,
      selection: "override-profile",
      auth,
    })),
    ...["openrouter", "fireworks"].flatMap((name) =>
      [false, true].map((ambient) => ({
        name,
        provider: { name: "Synthetic", env_key: "SYNTHETIC_PROVIDER_KEY" },
        ambient,
      })),
    ),
  ] as {
    name: string;
    provider: JsonObject;
    rootProvider?: JsonObject;
    ambient: boolean;
    selection?: "home-profile" | "override-profile" | "home-definition";
    auth?: "auto" | "api-key";
  }[])(
    "preserves the configured provider at the matcher process boundary: %j",
    async ({ name, provider, rootProvider, ambient, selection, auth }) => {
      const home = await temporaryDirectory("codex-security-matcher-provider-");
      const providerConfig = {
        model: "synthetic-native-model",
        model_reasoning_effort: "ultra",
        model_provider: name,
        model_providers: { [name]: provider },
      };
      const homeConfig =
        selection === "home-definition"
          ? stringify(providerConfig)
          : selection === "home-profile"
            ? stringify({
                model_provider: "openai",
                model_providers: { [name]: rootProvider ?? provider },
                profiles: { review: providerConfig },
              })
            : selection === "override-profile"
              ? stringify(
                  rootProvider === undefined
                    ? {
                        profile: "ambient",
                        profiles: {
                          ambient: { model_provider: "ambient-command" },
                        },
                        model_providers: {
                          "ambient-command": {
                            name: "Synthetic ambient",
                            base_url: "https://provider.example.test/v1",
                            wire_api: "responses",
                            auth: { command: "synthetic-ambient-auth" },
                          },
                        },
                      }
                    : {
                        model_provider: name,
                        model_providers: { [name]: rootProvider },
                      },
                )
              : ambient
                ? stringify(providerConfig)
                : 'model_provider="openai"\nmodel="ambient-model"\nmodel_reasoning_effort="low"\n';
      const requestedConfig: JsonObject =
        selection === "home-definition"
          ? {
              model: providerConfig.model,
              model_reasoning_effort: providerConfig.model_reasoning_effort,
              model_provider: name,
            }
          : selection === "home-profile"
            ? { profile: "review" }
            : selection === "override-profile"
              ? { profile: "review", profiles: { review: providerConfig } }
              : providerConfig;
      const usesOpenaiKey = name === "custom" || name === "openai";
      await writeFile(join(home, "config.toml"), homeConfig);
      const captures = join(home, "launches.jsonl");
      const preload = join(home, "capture.mjs");
      await writeFile(
        preload,
        `
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(captures)}, JSON.stringify({
  openai: process.env.OPENAI_API_KEY ?? null,
  codex: process.env.CODEX_API_KEY ?? null,
  providerKey: process.env.SYNTHETIC_PROVIDER_KEY ?? null,
  argv: process.argv.slice(1),
}) + "\\n");
await new Promise((resolve) => { process.stdin.resume(); process.stdin.on("end", resolve); });
console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-comparison" }));
console.log(JSON.stringify({ type: "item.completed", item: {
  id: "answer", type: "agent_message", text: '{"matches":[],"uncertain":[]}'
} }));
console.log(JSON.stringify({ type: "turn.completed", usage: {
  input_tokens: 1, cached_input_tokens: 0, output_tokens: 1
} }));
process.exit(0);
`,
      );
      const nodeExecutable = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        TEMP: process.env["TEMP"],
        TMP: process.env["TMP"],
        CODEX_HOME: home,
        OPENAI_API_KEY: usesOpenaiKey ? "synthetic-provider-key" : undefined,
        CODEX_API_KEY: usesOpenaiKey ? "synthetic-native-key" : undefined,
        SYNTHETIC_PROVIDER_KEY: usesOpenaiKey
          ? undefined
          : "synthetic-custom-provider-key",
      };
      const originalStartThread = Codex.prototype.startThread;
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        const original = (this as unknown as { options: CodexOptions }).options;
        return originalStartThread.call(
          new Codex({
            ...original,
            codexPathOverride: nodeExecutable,
            env: {
              ...original.env,
              NODE_OPTIONS: `--import=${JSON.stringify(pathToFileURL(preload).href)}`,
            },
          }),
          options,
        );
      });
      // Profile merging belongs to this wrapper; avoid depending on the
      // installed Codex version's legacy-profile support during MCP enumeration.
      const mcpCommand =
        selection === undefined || selection === "home-definition"
          ? undefined
          : spyOn(runtime, "runCodexCommand").mockImplementation(
              async (_command, args) => {
                expect(args).toContain("mcp");
                return { success: true, exitCode: 0, stdout: "[]", stderr: "" };
              },
            );
      try {
        for (const preserveProviderEnvironment of [true, false]) {
          await matchScanFindings(
            { before: [finding("before")], after: [finding("after")] },
            {
              environment,
              config: ambient ? undefined : { codexOverrides: requestedConfig },
              auth,
              workingDirectory: home,
              preserveProviderEnvironment,
            },
          );
        }
        const [native, ordinary] = (await readFile(captures, "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        if (selection === "home-definition") {
          for (const capture of [native, ordinary]) {
            const configArgs = (capture.argv as string[]).flatMap(
              (value, index) =>
                value === "--config" ? ["-c", capture.argv[index + 1]!] : [],
            );
            const validation = await runCodexCommand(
              resolveCodexCommand(environment),
              [...configArgs, "mcp", "list", "--json"],
              Object.fromEntries(
                Object.entries(environment).filter(
                  (entry): entry is [string, string] => entry[1] !== undefined,
                ),
              ),
              undefined,
              undefined,
              home,
            );
            expect(validation.success).toBe(true);
          }
        }
        if (!ambient) {
          expect(native.argv).toContain(
            `model_provider=${JSON.stringify(name)}`,
          );
          expect(native.argv).toContain('model="synthetic-native-model"');
          expect(native.argv).toContain('model_reasoning_effort="ultra"');
          if (provider["env_key"] !== undefined) {
            expect(argvConfig(native.argv)["model_providers"]).toMatchObject({
              [name]: { env_key: provider["env_key"] },
            });
          }
        }
        for (const capture of [native, ordinary]) {
          expect(capture.argv).toContain("read-only");
          expect(argvConfig(capture.argv)["features"]).toMatchObject({
            shell_tool: false,
            plugins: false,
          });
        }
        if (!usesOpenaiKey) {
          for (const capture of [native, ordinary]) {
            expect(capture.providerKey).toBe("synthetic-custom-provider-key");
            expect(capture.openai).toBeNull();
            expect(capture.codex).toBeNull();
          }
        } else if ("auth" in provider) {
          expect(ordinary.openai).toBeNull();
          expect(ordinary.codex).toBeNull();
          for (const capture of [native, ordinary]) {
            expect(argvConfig(capture.argv)["model_providers"]).toMatchObject({
              custom: {
                ...provider,
                auth: {
                  ...(provider["auth"] as JsonObject),
                  cwd: join(
                    home,
                    ((provider["auth"] as JsonObject)["cwd"] as
                      string | undefined) ?? ".",
                  ),
                },
              },
            });
          }
        } else {
          expect(ordinary.openai).toBe("synthetic-provider-key");
          expect(ordinary.codex).toBe("synthetic-provider-key");
        }
        if (usesOpenaiKey) {
          expect(native.openai).toBe("synthetic-provider-key");
          expect(native.codex).toBe("synthetic-native-key");
          expect(environment.OPENAI_API_KEY).toBe("synthetic-provider-key");
          expect(environment.CODEX_API_KEY).toBe("synthetic-native-key");
        } else {
          expect(environment.SYNTHETIC_PROVIDER_KEY).toBe(
            "synthetic-custom-provider-key",
          );
        }
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
          homeConfig,
        );
      } finally {
        startThread.mockRestore();
        mcpCommand?.mockRestore();
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
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        captured = (this as unknown as { options: CodexOptions }).options;
        return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
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
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, threadOptions) {
        captured = (this as unknown as { options: CodexOptions }).options;
        return codex.startThread(threadOptions!) as ReturnType<
          Codex["startThread"]
        >;
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
              threadSource: "security_scan",
            });
          }
          expect(calls.turnOptions?.cyberAccessProgram).toBe(
            options.cyberAccessProgram,
          );
          const features = deepMerge(
            (captured?.config ?? {}) as JsonObject,
            launchConfig(captured?.configOverrides ?? []),
          )["features"] as Record<string, unknown>;
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

  test.each(["home", "profile", "overrides", "override-away"])(
    "preserves native command auth selection from %s",
    async (selection) => {
      const home = await temporaryDirectory(
        "codex-security-command-comparison-",
      );
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
                          auth: {
                            args: ["override"],
                            cwd: join(home, "helpers"),
                          },
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
          expect(
            launchConfig(captured!.configOverrides!)["profile"],
          ).toBeUndefined();
          expect(
            launchConfig(captured!.configOverrides!)["model_provider"],
          ).toBe("synthetic.provider");
        }
        if (commandAuth) {
          expect(captured?.env).not.toHaveProperty("OPENAI_API_KEY");
          expect(captured?.env).not.toHaveProperty("CODEX_API_KEY");
          expect(captured?.apiKey).toBeUndefined();
          expect(launchConfig(captured!.configOverrides!)).toMatchObject({
            model_providers: {
              "synthetic.provider": {
                ...provider,
                auth: {
                  ...provider.auth,
                  cwd: selection === "overrides" ? join(home, "helpers") : home,
                  args: selection === "overrides" ? ["override"] : ["original"],
                },
              },
            },
          });
        } else {
          expect(captured?.env?.["OPENAI_API_KEY"]).toBe(
            "synthetic-ambient-key",
          );
          expect(
            launchConfig(captured!.configOverrides!)["model_provider"],
          ).toBe("openai");
        }
        expect(threadOptions).toMatchObject({
          workingDirectory: home,
          sandboxMode: "read-only",
          approvalPolicy: "never",
          networkAccessEnabled: false,
        });
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
          contents,
        );
      } finally {
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
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(
        (options) =>
          codex.startThread(options!) as ReturnType<Codex["startThread"]>,
      );
      try {
        await expect(
          matchScanFindings(
            { before: [finding("before")], after: [finding("after")] },
            options,
          ),
        ).rejects.toThrow("conflicts with command authentication");
        expect(startThread).not.toHaveBeenCalled();

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
        // The wrapper resolves legacy profile data; native enumeration no longer
        // accepts that home format, so isolate this authentication control.
        const mcpCommand = spyOn(runtime, "runCodexCommand").mockImplementation(
          async (_command, args) => {
            expect(args).toContain("mcp");
            return { success: true, exitCode: 0, stdout: "[]", stderr: "" };
          },
        );
        try {
          await matchScanFindings(
            { before: [finding("before")], after: [finding("after")] },
            { ...options, config: { codexOverrides: config } },
          );
          expect(startThread).toHaveBeenCalledTimes(1);
        } finally {
          mcpCommand.mockRestore();
        }
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test.each(["absolute", "relative"])(
    "disables MCP servers with a %s working directory",
    async (directory) => {
      const home = await temporaryDirectory("codex-security-comparison-");
      const repositoryPath = join(home, "repository");
      await mkdir(join(repositoryPath, ".git"), { recursive: true });
      const repository = await realpath(repositoryPath);
      await mkdir(join(repository, ".codex"));
      await writeFile(
        join(repository, ".codex", "config.toml"),
        stringify({
          mcp_servers: { project: { command: "synthetic-project" } },
        }),
      );
      await writeFile(
        join(home, "config.toml"),
        stringify({
          mcp_servers: { inherited: { command: "synthetic-inherited" } },
          projects: { [repository]: { trust_level: "trusted" } },
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
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        config = launchConfig(
          (this as unknown as { options: CodexOptions }).options
            .configOverrides!,
        ) as CodexOptions["config"];
        codexPath = (this as unknown as { options: CodexOptions }).options
          .codexPathOverride;
        codexEnvironment = (this as unknown as { options: CodexOptions })
          .options.env;
        return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment,
            workingDirectory:
              directory === "relative"
                ? relative(process.cwd(), repository)
                : repository,
            config: {
              codexOverrides: {
                profile: "selected",
                profiles: {
                  selected: {
                    mcp_servers: {
                      synthetic: {
                        command: "synthetic-integration",
                        enabled: true,
                      },
                    },
                  },
                },
              },
            },
          },
        );
        expect(config?.["mcp_servers"]).toEqual({
          synthetic: { command: "synthetic-integration", enabled: false },
          inherited: { enabled: false },
          project: { enabled: false },
        });
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
            repository,
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
          undefined,
          undefined,
          repository,
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
          { name: "project", enabled: false },
          { name: "synthetic", enabled: false },
        ]);
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test.each([false, true])(
    "keeps the selected provider across managed login (explicit: %p)",
    async (explicit) => {
      const root = await temporaryDirectory(
        "codex-security-provider-precedence-",
      );
      const home = join(root, "ambient");
      const state = join(root, "state");
      const managedHome = join(state, "codex-home");
      await mkdir(home, { mode: 0o700 });
      await mkdir(managedHome, { recursive: true, mode: 0o700 });
      const homeConfig = stringify({
        profile: "ambient",
        profiles: { ambient: { model_provider: "synthetic-ambient" } },
        model_providers: {
          "synthetic-ambient": {
            name: "Synthetic ambient",
            base_url: "https://provider.example.test/v1",
            wire_api: "responses",
            env_key: "SYNTHETIC_PROVIDER_KEY",
          },
        },
      });
      await writeFile(join(home, "config.toml"), homeConfig);
      const capturePath = join(root, "capture.json");
      const preload = join(root, "capture.mjs");
      await writeFile(
        preload,
        `
import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify({
  home: process.env.CODEX_HOME,
  key: process.env.SYNTHETIC_PROVIDER_KEY,
  argv: process.argv.slice(1),
}));
await new Promise((resolve) => { process.stdin.resume(); process.stdin.on("end", resolve); });
console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-comparison" }));
console.log(JSON.stringify({ type: "item.completed", item: {
  id: "answer", type: "agent_message", text: '{"matches":[],"uncertain":[]}'
} }));
console.log(JSON.stringify({ type: "turn.completed", usage: {
  input_tokens: 1, cached_input_tokens: 0, output_tokens: 1
} }));
process.exit(0);
`,
      );
      const nodeExecutable = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const originalRun = runtime.runCodexCommand;
      const command = spyOn(runtime, "runCodexCommand").mockImplementation(
        async (...args) => {
          if (args[1][0] === "login") {
            expect(args[2]["CODEX_HOME"]).toBe(await realpath(managedHome));
            return {
              success: true,
              exitCode: 0,
              stdout: "Logged in using ChatGPT",
              stderr: "",
            };
          }
          return originalRun(...args);
        },
      );
      const originalStart = Codex.prototype.startThread;
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        const original = (this as unknown as { options: CodexOptions }).options;
        return originalStart.call(
          new Codex({
            ...original,
            codexPathOverride: nodeExecutable,
            env: {
              ...original.env,
              NODE_OPTIONS: `--import=${JSON.stringify(pathToFileURL(preload).href)}`,
            },
          }),
          options,
        );
      });
      const overrides = {
        ...(explicit ? { model_provider: "openai" } : {}),
        model: "synthetic-requested-model",
        model_reasoning_effort: "high",
      };
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            config: { codexOverrides: overrides },
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              TEMP: process.env["TEMP"],
              TMP: process.env["TMP"],
              CODEX_HOME: home,
              CODEX_SECURITY_STATE_DIR: state,
              SYNTHETIC_PROVIDER_KEY: "synthetic-provider-key",
            },
            workingDirectory: root,
          },
        );
        const captured = JSON.parse(await readFile(capturePath, "utf8"));
        expect(captured.home).toBe(await realpath(managedHome));
        expect(captured.key).toBe("synthetic-provider-key");
        expect(captured.argv).toContain(
          `model_provider="${explicit ? "openai" : "synthetic-ambient"}"`,
        );
        const configArgs = (captured.argv as string[]).flatMap(
          (value, index) =>
            value === "--config" ? ["-c", captured.argv[index + 1]!] : [],
        );
        const validation = await originalRun(
          resolveCodexCommand({}),
          [...configArgs, "mcp", "list", "--json"],
          {
            PATH: process.env["PATH"] ?? "",
            ...(process.env["SystemRoot"] === undefined
              ? {}
              : { SystemRoot: process.env["SystemRoot"] }),
            ...(process.env["TEMP"] === undefined
              ? {}
              : { TEMP: process.env["TEMP"] }),
            ...(process.env["TMP"] === undefined
              ? {}
              : { TMP: process.env["TMP"] }),
            CODEX_HOME: await realpath(managedHome),
            SYNTHETIC_PROVIDER_KEY: "synthetic-provider-key",
          },
          undefined,
          undefined,
          root,
        );
        expect(validation.stderr).not.toContain("not found");
        expect(validation.success).toBe(true);
        if (!explicit) {
          const override = captured.argv.find((value: string) =>
            value.startsWith("model_providers="),
          );
          expect(parse(override)["model_providers"]).toEqual(
            parse(homeConfig)["model_providers"],
          );
        }
        expect(captured.argv).toContain('model="synthetic-requested-model"');
        expect(captured.argv).toContain('model_reasoning_effort="high"');
        expect(argvConfig(captured.argv)["features"]).toMatchObject({
          shell_tool: false,
          plugins: false,
        });
        expect(command.mock.calls.some((call) => call[1].includes("mcp"))).toBe(
          true,
        );
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
          homeConfig,
        );
        expect(overrides.model_provider).toBe(explicit ? "openai" : undefined);
      } finally {
        startThread.mockRestore();
        command.mockRestore();
      }
    },
  );

  test("enumerates project MCP servers with captured scan trust after shared-home changes", async () => {
    const home = await temporaryDirectory("codex-security-matcher-trust-");
    const repositoryPath = join(home, "repository");
    await mkdir(join(repositoryPath, ".git"), { recursive: true });
    const repository = await realpath(repositoryPath);
    await mkdir(join(repository, ".codex"));
    await writeFile(
      join(repository, ".codex", "config.toml"),
      stringify({ mcp_servers: { project: { command: "synthetic-project" } } }),
    );
    const capturedConfig = {
      projects: { [repository]: { trust_level: "trusted" } },
      features: { plugins: true },
    };
    const competingConfig = stringify({
      projects: { [repository]: { trust_level: "untrusted" } },
    });
    await writeFile(join(home, "config.toml"), competingConfig);
    const environment = {
      PATH: process.env["PATH"] ?? "",
      SystemRoot: process.env["SystemRoot"] ?? "",
      TEMP: process.env["TEMP"] ?? "",
      TMP: process.env["TMP"] ?? "",
      CODEX_HOME: home,
    };
    const servers = await disabledMcpServers(
      resolveCodexCommand(environment),
      capturedConfig,
      environment,
      { workingDirectory: repository },
    );
    expect(servers).toEqual({ project: { enabled: false } });
    expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
      competingConfig,
    );
  });

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
      reasoningEffort: "max",
    });
    expect(calls.threadOptions).toMatchObject({
      model: "explicit-model",
      modelReasoningEffort: "max",
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
        preserveProviderEnvironment: true,
        config: {
          codexOverrides: {
            model: "synthetic-model",
            model_reasoning_effort: "ultra",
            model_provider: "synthetic",
          },
        },
        previousFindings: [open],
        falsePositives: [{ findingId: "dismissed", sourceScanId: "prior" }],
        findings: [after],
        inheritedPermissions: {
          filesystem: { "/private": "deny", glob_scan_max_depth: 3 },
          network: { enabled: false },
        },
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
            preserveProviderEnvironment: true,
            config: {
              codexOverrides: {
                model: "synthetic-model",
                model_reasoning_effort: "ultra",
                model_provider: "synthetic",
              },
            },
            inheritedPermissions: {
              filesystem: { "/private": "deny", glob_scan_max_depth: 3 },
              network: { enabled: false },
            },
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

  test("corrects an unknown finding ID in the same matcher conversation", async () => {
    const corrected: ScanComparisonResult = {
      matches: [
        {
          beforeOccurrenceIds: ["before"],
          afterOccurrenceIds: ["after"],
          confidence: "high",
          reason: "The same control is missing.",
        },
      ],
      uncertain: [],
    };
    const prompts: string[] = [];
    const errors: unknown[] = [];
    let threads = 0;
    const result = await matchScanFindingsInternal(
      { before: [finding("before")], after: [finding("after")] },
      {
        codex: {
          startThread() {
            threads += 1;
            return {
              async run(prompt) {
                prompts.push(prompt);
                return {
                  finalResponse: JSON.stringify(
                    prompts.length === 1
                      ? {
                          ...corrected,
                          matches: [
                            {
                              ...corrected.matches[0],
                              beforeOccurrenceIds: ["unknown"],
                            },
                          ],
                        }
                      : corrected,
                  ),
                };
              },
            };
          },
        },
      },
      {
        surface: "sdk",
        async onInvalidResponse(error) {
          errors.push(error);
          return true;
        },
      },
    );
    expect(result).toEqual(corrected);
    expect(threads).toBe(1);
    expect(prompts).toHaveLength(2);
    expect(errors).toHaveLength(1);
    expect(prompts[1]).toContain("unknown before occurrence");
    expect(prompts[1]).not.toContain(prompts[0]!);
  });

  test.each(["returned JSON", "injected parser"])(
    "keeps complete paged evidence after malformed %s",
    async (source) => {
      const input = {
        before: [
          { ...finding("before"), rootCause: "🙂".repeat(1 << 20) + "x" },
        ],
        after: [finding("after")],
      };
      const result: ScanComparisonResult = {
        matches: [
          {
            beforeOccurrenceIds: ["before"],
            afterOccurrenceIds: ["after"],
            confidence: "high",
            reason: "The same control is missing.",
          },
        ],
        uncertain: [],
      };
      const pieces: string[] = [];
      let expectedOffset = 0;
      let turns = 0;
      let invalidResponses = 0;
      let threads = 0;
      expect(
        await matchScanFindingsInternal(
          input,
          {
            codex: {
              startThread() {
                threads += 1;
                return {
                  async run(prompt) {
                    expect([...prompt].length).toBeLessThanOrEqual(1 << 20);
                    const index = turns++;
                    if (index === 2) {
                      expect(prompt).toContain("invalid JSON");
                      expect(prompt).not.toContain('"content"');
                    } else if (index > 0) {
                      const page = JSON.parse(prompt.split("\n").at(-1)!) as {
                        offset: number;
                        nextOffset: number | null;
                        content: string;
                      };
                      expect(page.offset).toBe(expectedOffset);
                      expect(page.content.isWellFormed()).toBe(true);
                      pieces.push(page.content);
                      expectedOffset += [...page.content].length;
                      if (page.nextOffset !== null)
                        expect(page.nextOffset).toBe(expectedOffset);
                      if (index === 1) {
                        expect(page.nextOffset).not.toBeNull();
                        if (source === "injected parser")
                          JSON.parse("not-json");
                        return { finalResponse: "not-json" };
                      }
                    }
                    return { finalResponse: JSON.stringify(result) };
                  },
                };
              },
            },
          },
          {
            surface: "sdk",
            requireFullEvidence: true,
            async onInvalidResponse() {
              invalidResponses += 1;
              return true;
            },
          },
        ),
      ).toEqual(result);
      expect(threads).toBe(1);
      expect(invalidResponses).toBe(1);
      expect(pieces.length).toBeGreaterThan(1);
      expect(
        Buffer.from(pieces.join("")).equals(Buffer.from(JSON.stringify(input))),
      ).toBe(true);
    },
  );

  test("stops when the owning scan exhausts its invalid-response budget", async () => {
    let turns = 0;
    let original: unknown;
    await expect(
      matchScanFindingsInternal(
        { before: [finding("before")], after: [finding("after")] },
        {
          codex: {
            startThread: () => ({
              async run() {
                turns += 1;
                return { finalResponse: "not-json" };
              },
            }),
          },
        },
        {
          surface: "sdk",
          async onInvalidResponse(error) {
            original = error;
            return false;
          },
        },
      ).catch((error: unknown) => {
        expect(error).toBe(original);
        throw error;
      }),
    ).rejects.toThrow("invalid JSON");
    expect(turns).toBe(1);
  });

  test.each(["transport", "permission", "cancellation", "aborted JSON"])(
    "does not charge an invalid-response retry for %s failures",
    async (kind) => {
      const controller = new AbortController();
      const error =
        kind === "transport"
          ? new CodexSecurityError("The connection closed.")
          : kind === "permission"
            ? Object.assign(new Error("Permission denied."), { code: "EACCES" })
            : kind === "cancellation"
              ? new DOMException("Canceled.", "AbortError")
              : new SyntaxError("Incomplete JSON.");
      let retries = 0;
      let turns = 0;
      await expect(
        matchScanFindingsInternal(
          { before: [finding("before")], after: [finding("after")] },
          {
            signal: controller.signal,
            codex: {
              startThread: () => ({
                async run() {
                  turns += 1;
                  if (kind === "aborted JSON") controller.abort();
                  throw error;
                },
              }),
            },
          },
          {
            surface: "sdk",
            async onInvalidResponse() {
              retries += 1;
              return false;
            },
          },
        ),
      ).rejects.toBe(error);
      expect(turns).toBe(1);
      expect(retries).toBe(0);
    },
  );

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
