import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Codex } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import { main } from "../src/cli.js";
import {
  codexConfigOverrides,
  writeCodexConfig,
  type JsonObject,
} from "../src/config.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

const roots: string[] = [];
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture(native = true) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "scan-resume-permissions-")),
  );
  roots.push(root);
  const repository = join(root, "repository");
  const codexHome = native
    ? join(root, "codex")
    : join(root, "state", "codex-home");
  await Promise.all([
    mkdir(repository),
    mkdir(codexHome, { recursive: true, mode: 0o700 }),
  ]);
  await writeFile(join(repository, "app.py"), "print('synthetic fixture')\n");
  const inheritedPermissions = {
    filesystem: { [join(root, "private")]: "deny", glob_scan_max_depth: 6 },
    network: { enabled: false },
  };
  return { root, repository, codexHome, inheritedPermissions };
}

test.each([
  ["native", true],
  ["managed", false],
] as const)(
  "saved ordinary passes retain provider settings and attribution at the resumed Codex process boundary (%s)",
  async (_label, native) => {
    const { root, repository, codexHome, inheritedPermissions } =
      await fixture(native);
    const scanDir = join(root, "scan");
    const captures = join(root, "launches.jsonl");
    const preload = join(root, "codex-stub.mjs");
    const threadId = randomUUID();
    await writeFile(
      preload,
      `
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
appendFileSync(${JSON.stringify(captures)}, JSON.stringify({
  args: process.argv.slice(1),
  selected: process.env.SYNTHETIC_SCAN_SETTING,
  safetyIdentifier: process.env.CODEX_SAFETY_IDENTIFIER,
  providerKey: process.env.SYNTHETIC_PROVIDER_KEY,
}) + "\\n");
const directory = join(process.env.CODEX_HOME, "sessions", "2026", "01", "01");
mkdirSync(directory, {recursive:true});
writeFileSync(join(directory, "rollout-${threadId}.jsonl"), JSON.stringify({
  type: "session_meta", payload: {id: ${JSON.stringify(threadId)}, cwd: process.env.CODEX_SECURITY_SCAN_DIR},
}) + "\\n");
console.log(JSON.stringify({type:"thread.started", thread_id:${JSON.stringify(threadId)}}));
console.log(JSON.stringify({type:"turn.failed", error:{message:"Synthetic interrupted pass"}}));
setInterval(() => {}, 1000);
await new Promise(() => {});
`,
    );
    const nodeExecutable = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    const version = JSON.parse(
      await readFile(join(pluginRoot, ".codex-plugin/plugin.json"), "utf8"),
    ).version;
    const environment = {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      SYNTHETIC_SCAN_SETTING: "selected-value",
      CODEX_SAFETY_IDENTIFIER: "synthetic-ambient-identifier",
      OPENAI_API_KEY: "synthetic-fixture-key",
      SYNTHETIC_PROVIDER_KEY: "synthetic-provider-key",
    };
    let registration: JsonObject | undefined;
    let workbenchOptions: Parameters<typeof runWorkbench>[0] | undefined;
    const makeClient = (native: boolean, config: JsonObject) =>
      new CodexSecurity(
        { pluginPath: pluginRoot, codexOverrides: config },
        {
          environment,
          ...(native ? { inheritedPermissions } : {}),
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
              version,
            },
          }),
          resolvePluginPython: async () => process.env["PYTHON"] ?? "python",
          runWorkbench: async (options, args, input) => {
            const result = await runWorkbench(options, args, input);
            if (args[0] === "register-cli-scan") {
              registration = result;
              workbenchOptions = options;
            }
            return result;
          },
          createCodex: ({ config, configOverrides, ...options }) =>
            new Codex({
              ...options,
              configOverrides: [
                ...codexConfigOverrides(config as JsonObject),
                ...(configOverrides ?? []),
              ],
              codexPathOverride: nodeExecutable,
              env: {
                ...options.env,
                NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
              },
            }),
        },
        { surface: "sdk" },
      );
    const savedSettings = {
      model: "gpt-6-astra",
      model_reasoning_effort: "ultra",
      model_provider: "synthetic",
      model_providers: {
        synthetic: {
          name: "Synthetic provider",
          base_url: "https://provider.example.test/v1",
          env_key: "SYNTHETIC_PROVIDER_KEY",
          env_http_headers: { "X-Synthetic": "SYNTHETIC_PROVIDER_KEY" },
          http_headers: { X_SYNTHETIC_TOKEN: "saved-provider-header" },
          wire_api: "responses",
          ...(!native
            ? { auth: { command: "synthetic-auth", args: ["session"] } }
            : {}),
        },
      },
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
      cli_auth_credentials_store: "file",
      forced_login_method: "api",
    };
    const first = makeClient(native, savedSettings);
    if (native)
      await writeCodexConfig(join(codexHome, "config.toml"), savedSettings);
    try {
      await expect(
        first.run(repository, {
          mode: "standard",
          outputDir: scanDir,
          deepScanPass: true,
          preserveProviderEnvironment: native,
          ...(native ? { safetyIdentifier: "synthetic-saved-identifier" } : {}),
        }),
      ).rejects.toThrow("Synthetic interrupted pass");
    } finally {
      await first.close();
    }
    const saved = await runWorkbench(workbenchOptions!, [
      "get-cli-scan-resume",
      "--scan-id",
      registration!["scanId"] as string,
    ]);
    const recipe = saved["recipe"] as JsonObject;
    expect(recipe["inheritedPermissions"]).toEqual(
      native ? inheritedPermissions : undefined,
    );
    expect(recipe["safetyIdentifier"]).toBe(
      native ? "synthetic-saved-identifier" : undefined,
    );
    expect(recipe["preserveProviderEnvironment"]).toBe(native || undefined);
    const expectedSettings = native
      ? savedSettings
      : {
          model: savedSettings.model,
          model_reasoning_effort: savedSettings.model_reasoning_effort,
          model_provider: savedSettings.model_provider,
          model_providers: {
            synthetic: {
              name: "Synthetic provider",
              base_url: "https://provider.example.test/v1",
              env_key: "SYNTHETIC_PROVIDER_KEY",
              env_http_headers: { "X-Synthetic": "SYNTHETIC_PROVIDER_KEY" },
              wire_api: "responses",
              auth: { command: "synthetic-auth", args: ["session"] },
            },
          },
        };
    expect(recipe["config"]).toMatchObject({
      model: savedSettings.model,
      model_provider: savedSettings.model_provider,
      model_reasoning_effort: savedSettings.model_reasoning_effort,
    });
    expect(recipe["config"]).not.toHaveProperty("model_providers");
    if (!native)
      expect(recipe["providerProfile"]).toMatchObject({ home: "managed" });
    expect(JSON.stringify(recipe)).not.toContain("saved-provider-header");
    expect(JSON.stringify(recipe)).not.toContain("synthetic-provider-key");
    expect(recipe["config"]).not.toHaveProperty("plugins");
    expect(recipe["config"]).not.toHaveProperty("marketplaces");
    expect(recipe["config"]).not.toHaveProperty("features.plugins");
    environment.CODEX_SAFETY_IDENTIFIER = "synthetic-other-host-identifier";
    // CLI replay restores native ambient settings or managed private profiles;
    // the resumed child consumes those settings at its actual process boundary.
    let resumedConfig = recipe["config"] as JsonObject;
    {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["scans", "rerun", saved["scanId"] as string, "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({
            environment: { ...environment, CODEX_HOME: codexHome },
            currentDirectory: repository,
            onWorkbench: () => saved,
            onConfig: (config) => {
              resumedConfig = config.codexOverrides as JsonObject;
            },
          }),
        ),
      ).toBe(0);
      expect(resumedConfig).toMatchObject(expectedSettings);
    }
    const resumed = makeClient(false, resumedConfig);
    try {
      await expect(
        resumed.run(repository, {
          mode: "standard",
          outputDir: scanDir,
          resumeScanId: saved["scanId"] as string,
          deepScanPass: true,
          preserveProviderEnvironment:
            recipe["preserveProviderEnvironment"] === true,
          safetyIdentifier: recipe["safetyIdentifier"] as string,
          inheritedPermissions: recipe[
            "inheritedPermissions"
          ] as ScanOptions["inheritedPermissions"],
        }),
      ).rejects.toThrow("Synthetic interrupted pass");
    } finally {
      await resumed.close();
    }
    const launches = (await readFile(captures, "utf8"))
      .trim()
      .split("\n")
      .map(
        (line) =>
          JSON.parse(line) as {
            args: string[];
            selected: string;
            safetyIdentifier: string;
            providerKey: string;
          },
      );
    expect(launches).toHaveLength(2);
    for (const launch of launches) {
      const config = Object.assign(
        {},
        ...launch.args.flatMap((value, index) =>
          value === "-c" || value === "--config"
            ? [parseToml(launch.args[index + 1]!)]
            : [],
        ),
      );
      const permissions = config.permissions[config.default_permissions];
      if (native)
        expect(permissions).toMatchObject({
          filesystem: {
            ...inheritedPermissions.filesystem,
            ":root": "read",
          },
          network: inheritedPermissions.network,
        });
      if (native)
        expect(permissions.filesystem).not.toHaveProperty(":workspace_roots");
      expect(launch.selected).toBe("selected-value");
      if (native)
        expect(launch.safetyIdentifier).toBe("synthetic-saved-identifier");
      expect(launch.providerKey).toBe("synthetic-provider-key");
      expect(config).toMatchObject(expectedSettings);
    }
    expect(launches[1]!.args).toContain("resume");
    expect(launches[1]!.args).toContain(threadId);
  },
);

test("CLI resume restores saved native permissions into the shared SDK operation", async () => {
  const { root, repository, codexHome, inheritedPermissions } = await fixture();
  const provider = {
    name: "Synthetic provider",
    base_url: "https://provider.example.test/v1",
    env_key: "SYNTHETIC_PROVIDER_KEY",
    wire_api: "responses",
  };
  await writeCodexConfig(join(codexHome, "config.toml"), {
    model_providers: { synthetic: provider },
  });
  const id = randomUUID();
  let selected: ScanOptions | undefined;
  let restoredConfig: JsonObject | undefined;
  const stderr = capture();
  const result = await main(
    ["scans", "resume", id, "--json"],
    capture().stream,
    stderr.stream,
    {
      ...dependencies({
        currentDirectory: root,
        environment: { CODEX_HOME: codexHome },
        onConfig: (config) => {
          restoredConfig = config.codexOverrides as JsonObject;
        },
        result: fakeResult(),
        onTurn: (_repository, options) => {
          selected = options as ScanOptions;
        },
      }),
      runWorkbench: async () => ({
        scanId: id,
        scanDir: join(root, "scan"),
        recipe: {
          repository,
          target: { kind: "repository", paths: [] },
          mode: "deep",
          config: {
            model: "gpt-6-astra",
            model_reasoning_effort: "ultra",
            model_provider: "synthetic",
          },
          preserveProviderEnvironment: true,
          inheritedPermissions,
          safetyIdentifier: "synthetic-saved-identifier",
        },
      }),
    },
  );
  expect(result).toBe(0);
  expect(restoredConfig).toMatchObject({
    model_provider: "synthetic",
    model_providers: { synthetic: provider },
  });
  expect(selected).toMatchObject({
    resumeScanId: id,
    inheritedPermissions,
    safetyIdentifier: "synthetic-saved-identifier",
  });
});
