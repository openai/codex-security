import { effectiveCodexConfiguration } from "./support/api-events.js";
import { codexFactory } from "./support/api-events.js";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import * as os from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import * as runtime from "../src/runtime.js";
import type { CodexOptions } from "@openai/codex-sdk";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { preparedRuntime } from "./support/api-events.js";
import * as providerProfiles from "../src/provider-profile.js";
import type { JsonObject } from "../src/config.js";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import { acquireScanExecution } from "../src/scan-execution.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

function stubPluginInstall() {
  return spyOn(runtime, "bootstrapPlugin").mockImplementation(
    async (_home, pluginRoot) => ({
      ...(await runtime.pluginMetadata(pluginRoot)),
      pluginRoot,
      installedRoot: pluginRoot,
      marketplaceRoot: pluginRoot,
      marketplaceName: "codex-security-sdk",
    }),
  );
}

test.each(["ready", "denied", "canceled"])(
  "protects provider snapshots across runtime reuse (preparation: %s)",
  async (preparation) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    const original = runtime.requirePrivateCredentialHome;
    let protectedDirectory: string | undefined;
    let bootstrapDirectory: string | undefined;
    let launched = false;
    let launchCount = 0;
    let checkedLaunchCount = 0;
    let operation: "deep" | "standard" | "validation" = "deep";
    const controller = new AbortController();
    const install = stubPluginInstall();
    const guard = spyOn(
      runtime,
      "requirePrivateCredentialHome",
    ).mockImplementation(async (metadata, path, options) => {
      if (path !== join(root, "state", "codex-home"))
        return original(metadata, path, options);
      await original(metadata, path, {
        platform: "win32",
        secureWindowsHome: async (directory) => {
          if (protectedDirectory === undefined) {
            expect(await readdir(directory)).toEqual([]);
            protectedDirectory = directory;
          }
          if (preparation === "denied") throw new Error("synthetic ACL denial");
          if (preparation === "canceled") controller.abort();
        },
      });
    });
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: {
          model_provider: "synthetic.provider",
          model_providers: {
            "synthetic.provider": {
              name: "Synthetic provider",
              base_url: "https://provider.example.test/v1",
              wire_api: "responses",
              auth: {
                command: "synthetic-auth",
                env: { CLIENT_SECRET: "synthetic-client-secret" },
              },
            },
          },
        },
      },
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_options, args, input) =>
          args[0] === "list-scans"
            ? { scans: [] }
            : args[0] === "get-scan"
              ? { scan: { progress: { status: "running" } } }
              : mockWorkbench(args, input),
        createCodex: (options: CodexOptions & { nativeProfile?: string }) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              launched = true;
              launchCount++;
              expect(options.env!["CODEX_HOME"]).toBe(protectedDirectory!);
              const file = options.env!["CODEX_SECURITY_CONFIG_PATH"];
              if (operation === "validation") {
                expect(file).toBeUndefined();
              } else {
                expect(file).toBeDefined();
                bootstrapDirectory ??= dirname(file!);
                expect(dirname(file!)).toBe(bootstrapDirectory);
                expect(dirname(file!)).not.toBe(protectedDirectory);
                expect(await readFile(file!, "utf8")).not.toContain(
                  "synthetic-client-secret",
                );
              }
              // Deep Scan now composes ordinary scan sessions; their managed
              // home and configuration replace the retired worker snapshot.
              expect(
                options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"],
              ).toBeUndefined();
              const providers = options.config!["model_providers"] as Record<
                string,
                Record<string, unknown>
              >;
              const auth = providers["synthetic.provider"]!["auth"] as {
                env: Record<string, string>;
              };
              expect(auth.env["CLIENT_SECRET"]).toBe("synthetic-client-secret");
              // The injected factory is a trusted local caller. Native profile
              // transport and argv omission have separate real-process tests.
              const profileFile = join(protectedDirectory!, "config.toml");
              expect(await readFile(profileFile, "utf8")).toContain(
                "synthetic-client-secret",
              );
              const permissions = effectiveCodexConfiguration(options)[
                "permissions"
              ] as Record<string, Record<string, unknown>>;
              const filesystem = permissions["codex_security_scan"]![
                "filesystem"
              ] as Record<string, unknown>;
              expect(filesystem[protectedDirectory!]).toEqual({ ".": "deny" });
              if (process.platform !== "win32") {
                expect((await stat(profileFile)).mode & 0o777).toBe(0o600);
                expect((await stat(protectedDirectory!)).mode & 0o777).toBe(
                  0o700,
                );
                if (file !== undefined) {
                  expect((await stat(file)).mode & 0o777).toBe(0o600);
                  expect((await stat(dirname(file))).mode & 0o777).toBe(0o700);
                }
              }
              checkedLaunchCount++;
              throw new Error("synthetic scan reached");
            },
          }),
        }),
      },
    );
    try {
      await expect(
        client.run(repository, {
          mode: "deep",
          signal: controller.signal,
        }),
      ).rejects.toThrow(
        preparation === "denied"
          ? "synthetic ACL denial"
          : preparation === "canceled"
            ? "interrupted during preparation"
            : "Deep Scan reached its consecutive error limit.",
      );
      expect(protectedDirectory).toBeDefined();
      expect(launched).toBe(preparation === "ready");
      expect(checkedLaunchCount).toBe(launchCount);
      if (preparation === "ready") {
        operation = "standard";
        await expect(client.run(repository)).rejects.toThrow(
          "synthetic scan reached",
        );
        operation = "validation";
        await expect(
          client.validate({
            repositoryPath: repository,
            finding: "Synthetic finding",
            outputDir: join(root, "validation"),
          }),
        ).rejects.toThrow("synthetic scan reached");
        expect(checkedLaunchCount).toBe(launchCount);
      }
    } finally {
      guard.mockRestore();
      install.mockRestore();
      await client.close();
    }
    // Credential storage persists across clients; only bootstrap state is disposable.
    expect(existsSync(protectedDirectory!)).toBe(true);
    if (bootstrapDirectory !== undefined) {
      expect(existsSync(bootstrapDirectory)).toBe(false);
      expect(
        await readFile(join(protectedDirectory!, "config.toml"), "utf8"),
      ).not.toContain("synthetic-client-secret");
      if (process.platform !== "win32") {
        expect((await stat(protectedDirectory!)).mode & 0o777).toBe(0o700);
        expect(
          (await stat(join(protectedDirectory!, "config.toml"))).mode & 0o777,
        ).toBe(0o600);
      }
    }
  },
);

const replaySettings = {
  shell: {
    shell_environment_policy: {
      set: { SYNTHETIC_REPLAY_TOKEN: "synthetic-test-only" },
    },
  },
  provider: {
    model_provider: "synthetic.provider",
    model_providers: {
      "synthetic.provider": {
        name: "Synthetic provider",
        http_headers: { "X-Synthetic": "synthetic-test-only" },
      },
    },
  },
  none: {},
};

async function replayProfileFixture() {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scan = join(root, "scan");
  const state = join(root, "state");
  const home = join(state, "codex-home");
  const missingSkill = join(root, "missing-skill-plugin");
  await Promise.all(
    [repository, scan, home, missingSkill].map((directory) =>
      mkdir(directory, { recursive: true, mode: 0o700 }),
    ),
  );
  return {
    root,
    repository,
    scan,
    state,
    home,
    missingSkill,
    profiles: async () =>
      (await readdir(home)).filter((name) =>
        /^codex_security_.*\.config\.toml$/.test(name),
      ),
  };
}

test.each([
  ["shell", "skill", "standard"],
  ["shell", "registration", "standard"],
  ["shell", "registration", "deep"],
  ["provider", "registration", "standard"],
  ["none", "registration", "standard"],
  ["shell", "registered", "standard"],
  ["provider", "registered", "standard"],
  ["shell", "native", "standard"],
] as const)(
  "owns replay profiles across %s %s startup (%s)",
  async (settings, stage, mode) => {
    const h = await replayProfileFixture();
    const failure = new Error("Synthetic scan startup failure");
    let recipe: JsonObject | undefined;
    let registrationCalls = 0;
    const client = new TestClient(
      { codexOverrides: replaySettings[settings] },
      {
        environment: { CODEX_SECURITY_STATE_DIR: h.state },
        prepareRuntime: async () => {
          const runtime = preparedRuntime(h.home);
          if (stage === "skill") runtime.plugin.pluginRoot = h.missingSkill;
          return runtime;
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => h.scan,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "register-cli-scan") {
            registrationCalls++;
            recipe = JSON.parse(input!).recipe;
            expect(await h.profiles()).toHaveLength(
              settings === "none" ? 0 : 1,
            );
            if (stage === "registration") throw failure;
          }
          if (args[0] === "get-scan-feedback") throw failure;
          if (args[0] === "list-scans") return { scans: [] };
          return mockWorkbench(args, input);
        },
      },
    );
    try {
      const run = client.run(h.repository, {
        mode,
        ...(stage === "native"
          ? {
              outputDir: h.scan,
              registeredScan: {
                scanId: "scan_example_001",
                scanDir: h.scan,
                threadId: "synthetic-native-owner",
                handoffClaimToken: "synthetic-claim",
              },
            }
          : {}),
      });
      if (stage === "skill")
        await expect(run).rejects.toThrow(
          "Installed plugin is missing scan skill",
        );
      else await expect(run).rejects.toBe(failure);
      expect(registrationCalls).toBe(stage === "skill" ? 0 : 1);
      const profiles = await h.profiles();
      const ownsRecipe = stage === "registered" || stage === "native";
      expect(profiles).toHaveLength(ownsRecipe ? 1 : 0);
      if (ownsRecipe) {
        expect(recipe!["providerProfile"]).toMatchObject({ home: "managed" });
        const restored = await providerProfiles.restoreProviderProfile(
          {},
          recipe!["providerProfile"],
          { CODEX_SECURITY_STATE_DIR: h.state },
        );
        expect(restored).toMatchObject(
          settings === "provider"
            ? { model_providers: replaySettings.provider.model_providers }
            : replaySettings.shell,
        );
      }
    } finally {
      await client.close();
    }
  },
);

test.each(
  (["shell", "provider"] as const).flatMap((settings) =>
    (["standard", "deep"] as const).flatMap((mode) =>
      (["resume", "registered"] as const).map((continuation) => ({
        settings,
        mode,
        continuation,
      })),
    ),
  ),
)(
  "resumed scans retain their saved replay profile without leaving a new copy: %j",
  async ({ settings, mode, continuation }) => {
    const h = await replayProfileFixture();
    const failure = new Error("Synthetic failure after registration");
    let saved: JsonObject | undefined;
    const profilesAtResume: string[][] = [];
    const client = new TestClient(
      { codexOverrides: replaySettings[settings] },
      {
        environment: { CODEX_SECURITY_STATE_DIR: h.state },
        prepareRuntime: async () => preparedRuntime(h.home),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => h.scan,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "get-scan") {
            profilesAtResume.push(await h.profiles());
            return { recipe: saved!["recipe"]! };
          }
          if (args[0] === "register-cli-scan") {
            if (saved !== undefined) return saved;
            saved = {
              ...mockWorkbench(args, input),
              recipe: JSON.parse(input!).recipe,
              threadId: null,
            };
            return saved;
          }
          if (args[0] === "get-cli-scan-resume") {
            profilesAtResume.push(await h.profiles());
            return saved!;
          }
          if (args[0] === "get-scan-feedback") throw failure;
          return mockWorkbench(args, input);
        },
      },
    );
    try {
      const scanOptions = {
        mode,
        deepScanPass: mode === "standard",
        onRegisteredScan: async () => {
          throw failure;
        },
      };
      await expect(client.run(h.repository, scanOptions)).rejects.toBe(failure);
      const original = await h.profiles();
      expect(original).toHaveLength(1);
      await expect(
        client.run(h.repository, {
          ...scanOptions,
          outputDir: h.scan,
          ...(continuation === "resume"
            ? { resumeScanId: saved!["scanId"] as string }
            : {
                registeredScan: {
                  scanId: saved!["scanId"] as string,
                  scanDir: h.scan,
                  threadId: "synthetic-native-owner",
                  handoffClaimToken: "synthetic-claim",
                },
              }),
        }),
      ).rejects.toBe(failure);
      expect(profilesAtResume).toHaveLength(1);
      expect(profilesAtResume[0]).toHaveLength(2);
      expect(await h.profiles()).toEqual(original);
      const recipe = saved!["recipe"] as JsonObject;
      expect(
        await providerProfiles.restoreProviderProfile(
          {},
          recipe["providerProfile"],
          { CODEX_SECURITY_STATE_DIR: h.state },
        ),
      ).toMatchObject(
        settings === "provider"
          ? { model_providers: replaySettings.provider.model_providers }
          : replaySettings.shell,
      );
    } finally {
      await client.close();
    }
  },
);

test("profile cleanup preserves the startup failure and its own diagnostic", async () => {
  const h = await replayProfileFixture();
  const failure = new Error("Synthetic registration failure");
  const cleanupFailure = new Error("Synthetic profile removal failed");
  const original = providerProfiles.createProviderProfile;
  const created: Array<Awaited<ReturnType<typeof original>>> = [];
  const warnings: string[] = [];
  const profile = spyOn(
    providerProfiles,
    "createProviderProfile",
  ).mockImplementation(async (...args) => {
    const saved = await original(...args);
    created.push(saved);
    return {
      ...saved,
      cleanup: async () => {
        throw cleanupFailure;
      },
    };
  });
  const client = new TestClient(
    { codexOverrides: replaySettings.shell },
    {
      environment: { CODEX_SECURITY_STATE_DIR: h.state },
      prepareRuntime: async () => preparedRuntime(h.home),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => h.scan,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options, args) => {
        if (args[0] === "list-scans") return { scans: [] };
        throw failure;
      },
    },
  );
  try {
    await expect(
      client.run(h.repository, {
        onWarning: (message) => warnings.push(message),
      }),
    ).rejects.toBe(failure);
    expect(created).toHaveLength(1);
    expect(
      warnings.some((message) => message.includes(cleanupFailure.message)),
    ).toBe(true);
  } finally {
    profile.mockRestore();
    await client.close();
    await Promise.all(created.map((saved) => saved.cleanup()));
  }
});

test.each([
  ...(["standard", "deep"] as const).flatMap((mode) =>
    (["fresh", "native"] as const).flatMap((kind) =>
      (["before", "after"] as const).map((stage) => ({
        mode,
        kind,
        stage,
        queryFailure: "",
      })),
    ),
  ),
  { mode: "deep", kind: "fresh", stage: "before", queryFailure: "list-scans" },
  {
    mode: "deep",
    kind: "fresh",
    stage: "after",
    queryFailure: "get-scan-recipe",
  },
  { mode: "standard", kind: "child", stage: "before", queryFailure: "" },
  { mode: "standard", kind: "child", stage: "after", queryFailure: "" },
] as const)(
  "registration interruption preserves durable profile ownership: %j",
  async ({ mode, kind, stage, queryFailure }) => {
    const h = await replayProfileFixture();
    await writeFile(
      join(h.repository, "source.ts"),
      "export const value = 1;\n",
    );
    const python = Bun.which("python3")!;
    const environment = {
      ...process.env,
      OPENAI_API_KEY: "synthetic-test-key",
      CODEX_API_KEY: "synthetic-test-key",
      CODEX_HOME: h.home,
      CODEX_SECURITY_STATE_DIR: h.state,
    };
    const workbenchOptions = { python, pluginRoot: PLUGIN_ROOT, environment };
    const interruptedPlugin = join(h.root, "interrupted-plugin");
    await mkdir(join(interruptedPlugin, "scripts"), { recursive: true });
    await writeFile(
      join(interruptedPlugin, "scripts", "workbench_db.py"),
      `
import signal, sys
sys.path.insert(0, ${JSON.stringify(join(PLUGIN_ROOT, "scripts"))})
import workbench_db as wb
original = wb.register_cli_scan
def interrupted_registration(*args, **kwargs):
    if ${JSON.stringify(stage)} == "before":
        signal.raise_signal(signal.SIGINT)
    result = original(*args, **kwargs)
    if ${JSON.stringify(stage)} == "after":
        signal.raise_signal(signal.SIGINT)
    return result
wb.register_cli_scan = interrupted_registration
if __name__ == "__main__":
    wb.main()
`,
    );
    let scanDir = h.scan;
    let registeredScan: ScanOptions["registeredScan"];
    let parentScanId: string | undefined;
    if (kind !== "fresh") {
      const started = await runtime.runWorkbench(workbenchOptions, [
        kind === "child" || mode === "deep"
          ? "begin-deep-scan"
          : "start-headless-standard-scan",
        "--thread-id",
        "synthetic-native-owner",
        "--target-path",
        h.repository,
        "--scope",
        ".",
        "--scan-root",
        join(h.root, "native-scans"),
      ]);
      const scan = started["scan"] as JsonObject;
      if (kind === "child") parentScanId = scan["scanId"] as string;
      else {
        scanDir = scan["scanDir"] as string;
        registeredScan = {
          scanId: scan["scanId"] as string,
          scanDir,
          threadId: "synthetic-native-owner",
          handoffClaimToken: scan["handoffClaimToken"] as string,
        };
      }
    }
    const queryError = new Error(
      "Synthetic registration ownership query failed",
    );
    const queries: string[] = [];
    const warnings: string[] = [];
    let locked = false;
    let interrupted: unknown;
    const client = new CodexSecurity(
      { codexOverrides: replaySettings.shell },
      {
        environment,
        prepareRuntime: async () => preparedRuntime(h.home),
        resolvePluginPython: async () => python,
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => null,
        probeCodexSandbox: async () => {},
        createCodex: () => {
          throw new Error(
            "Execution must not start after interrupted registration",
          );
        },
        acquireScanExecution: async (...args) => {
          const release = await acquireScanExecution(...args);
          locked = true;
          return () => {
            locked = false;
            release();
          };
        },
        runWorkbench: async (options, args, input) => {
          if (args[0] === "list-scans" || args[0] === "get-scan-recipe") {
            expect(locked).toBe(true);
            expect(options.signal).toBeUndefined();
            queries.push(args[0]);
            if (args[0] === queryFailure) throw queryError;
          }
          try {
            return await runtime.runWorkbench(
              {
                ...options,
                ...(args[0] === "register-cli-scan"
                  ? { pluginRoot: interruptedPlugin }
                  : {}),
              },
              args,
              input,
            );
          } catch (error) {
            if (args[0] === "register-cli-scan") interrupted = error;
            throw error;
          }
        },
      },
      {
        surface: "sdk",
        ...(kind === "child" ? { parentScanRole: "deep_pass" } : {}),
      },
    );
    const runOptions: ScanOptions = {
      mode,
      outputDir: scanDir,
      registeredScan,
      parentScanId,
      deepScanPass: kind === "child",
      onWarning: (warning) => warnings.push(warning),
    };
    try {
      const failure = await client
        .run(h.repository, runOptions)
        .catch((error: unknown) => error);
      expect(interrupted).toBeInstanceOf(Error);
      expect(failure).toBe(interrupted);
      expect((interrupted as Error).message).toContain("KeyboardInterrupt");
      expect(locked).toBe(false);
      const rows = (
        await runtime.runWorkbench(workbenchOptions, [
          "list-scans",
          "--scan-root",
          scanDir,
        ])
      )["scans"] as JsonObject[];
      const saved = rows.filter((scan) => scan["recipeAvailable"] === true);
      expect(saved).toHaveLength(stage === "after" ? 1 : 0);
      const profiles = await h.profiles();
      expect(profiles).toHaveLength(stage === "after" || queryFailure ? 1 : 0);
      if (queryFailure) {
        expect(queries).toContain(queryFailure);
        expect(
          warnings.some((warning) => warning.includes(queryError.message)),
        ).toBe(true);
      } else expect(warnings).toEqual([]);
      if (stage === "after") {
        const row = saved[0]!;
        if (kind === "child") expect(row["parentScanRole"]).toBe("deep_pass");
        const recipe = (
          await runtime.runWorkbench(workbenchOptions, [
            "get-scan-recipe",
            "--scan-id",
            row["scanId"] as string,
          ])
        )["recipe"] as JsonObject;
        expect(
          await providerProfiles.restoreProviderProfile(
            {},
            recipe["providerProfile"],
            environment,
          ),
        ).toMatchObject(replaySettings.shell);
        if (!queryFailure && kind === "native") {
          // A queued native retry keeps the persisted recipe, even when its
          // acknowledgement is interrupted again after returning that recipe.
          const retryFailure = await client
            .run(h.repository, runOptions)
            .catch((error: unknown) => error);
          expect(retryFailure).toBe(interrupted);
          expect(await h.profiles()).toEqual(profiles);
        } else if (!queryFailure && kind === "fresh" && mode === "deep") {
          const stop = new Error("Synthetic stop after resume registration");
          await expect(
            client.run(h.repository, {
              mode,
              outputDir: scanDir,
              resumeScanId: row["scanId"] as string,
              onRegisteredScan: async () => {
                throw stop;
              },
            }),
          ).rejects.toBe(stop);
          expect(await h.profiles()).toEqual(profiles);
        }
      }
    } finally {
      await client.close();
    }
  },
);

test.each(["directory", "zip"])(
  "isolates and reuses runtime workspaces outside sandbox-writable Windows TEMP (%s plugin)",
  async (source) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const temporary = join(root, "temporary");
    const state = join(root, "state");
    await mkdir(repository);
    await mkdir(temporary, { mode: 0o700 });
    const pluginFiles = {
      ".codex-plugin/plugin.json": strToU8(
        JSON.stringify({ name: "codex-security", version: "1.2.3" }),
      ),
      "skills/security-scan/SKILL.md": strToU8("# Synthetic scan workflow\n"),
    };
    const pluginPath = join(root, source === "zip" ? "plugin.zip" : "plugin");
    if (source === "zip") {
      await writeFile(pluginPath, zipSync(pluginFiles));
    } else {
      for (const [name, contents] of Object.entries(pluginFiles)) {
        await mkdir(dirname(join(pluginPath, name)), { recursive: true });
        await writeFile(join(pluginPath, name), contents);
      }
    }
    const snapshotAcl = () => {
      const system = join(process.env["SystemRoot"]!, "System32");
      const result = spawnSync(
        join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "(Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_TEMP).Sddl",
        ],
        {
          encoding: "utf8",
          env: {
            ...Object.fromEntries(
              Object.entries(process.env).filter(
                ([name]) => name.toUpperCase() !== "PSMODULEPATH",
              ),
            ),
            CODEX_SECURITY_TEST_TEMP: temporary,
            PSModulePath: join(system, "WindowsPowerShell", "v1.0", "Modules"),
          },
          windowsHide: true,
        },
      );
      expect(result.status, result.stderr).toBe(0);
      return result.stdout.trim();
    };
    let temporaryAcl: string | undefined;
    if (process.platform === "win32") {
      const grant = spawnSync(
        join(process.env["SystemRoot"]!, "System32", "icacls.exe"),
        [temporary, "/grant", "*S-1-1-0:(OI)(CI)(M,DC)"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(grant.status, grant.stderr).toBe(0);
      temporaryAcl = snapshotAcl();
      const rejected = await runtime.createIsolatedHome(temporary);
      await expect(
        runtime.requirePrivateCredentialHome(await lstat(rejected), rejected),
      ).rejects.toThrow("allows another identity to replace");
    }
    const processTemporary = {
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
    };
    const temporaryRoot = spyOn(os, "tmpdir").mockReturnValue(temporary);
    const install = stubPluginInstall();
    const workspaces = new Map<number, string>();
    const clients: TestClient[] = [];
    const createClient = (index: number, stateDirectory = state) => {
      const client = new TestClient(
        {
          pluginPath,
          codexOverrides: {
            model_provider: "synthetic",
            model_providers: {
              synthetic: {
                name: "Synthetic",
                base_url: "https://provider.example.test/v1",
                wire_api: "responses",
                auth: { command: "synthetic-auth" },
              },
            },
          },
        },
        {
          environment: {
            CODEX_HOME: join(root, "ambient"),
            CODEX_SECURITY_STATE_DIR: stateDirectory,
            TEMP: temporary,
            TMP: temporary,
          },
          resolvePluginPython: async () => "/managed/python",
          repositoryRevision: async () => "deadbeef",
          createCodex: (options) => {
            const environment = options.env!;
            expect(environment["TEMP"]).toBe(temporary);
            expect(environment["TMP"]).toBe(temporary);
            expect(environment["CODEX_HOME"]).toBe(
              join(stateDirectory, "codex-home"),
            );
            expect(environment["CODEX_SECURITY_STATE_DIR"]).toBe(
              stateDirectory,
            );
            const workspace = dirname(
              environment["CODEX_SECURITY_CONFIG_PATH"]!,
            );
            expect(dirname(workspace)).toBe(
              process.platform === "win32" ? stateDirectory : temporary,
            );
            const previous = workspaces.get(index);
            if (previous !== undefined) expect(workspace).toBe(previous);
            workspaces.set(index, workspace);
            expect(environment["CODEX_SECURITY_PLUGIN_ROOT"]).toBe(
              source === "zip"
                ? join(workspace, "extracted-plugin")
                : pluginPath,
            );
            const codex = codexFactory(async function () {
              throw new Error("synthetic scan reached");
            })();
            return {
              startThread: (threadOptions) => {
                expect(threadOptions.workingDirectory).toBe(
                  join(root, `scan-${index}`),
                );
                return codex.startThread();
              },
            };
          },
        },
      );
      clients.push(client);
      return client;
    };
    const run = (client: TestClient, index: number) =>
      client.run(repository, { outputDir: join(root, `scan-${index}`) });
    try {
      const first = createClient(0);
      const second = createClient(1);
      await Promise.all([
        expect(run(first, 0)).rejects.toThrow("synthetic scan reached"),
        expect(run(second, 1)).rejects.toThrow("synthetic scan reached"),
      ]);
      expect(workspaces.size).toBe(2);
      expect(workspaces.get(0)).not.toBe(workspaces.get(1));
      await first.close();
      expect(existsSync(workspaces.get(0)!)).toBe(false);
      expect(existsSync(workspaces.get(1)!)).toBe(true);
      await expect(run(second, 1)).rejects.toThrow("synthetic scan reached");
      if (process.platform === "win32") {
        const rejected = createClient(2, join(temporary, "untrusted-state"));
        await expect(run(rejected, 2)).rejects.toThrow(
          "allows another identity to replace",
        );
        expect(workspaces.has(2)).toBe(false);
        expect(snapshotAcl()).toBe(temporaryAcl!);
      }
      expect({ TEMP: process.env["TEMP"], TMP: process.env["TMP"] }).toEqual(
        processTemporary,
      );
    } finally {
      temporaryRoot.mockRestore();
      install.mockRestore();
      await Promise.all(clients.map((client) => client.close()));
    }
    for (const workspace of workspaces.values()) {
      expect(existsSync(workspace)).toBe(false);
    }
  },
  60_000,
);
