import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { CodexSecurity } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { restoreReplayProfile } from "../src/provider-profile.js";
import { acquireScanExecution } from "../src/scan-execution.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  ...(["standard", "deep"] as const).flatMap((mode) =>
    (["before", "after", "response"] as const).map((stage) => ({
      mode,
      stage,
      queryFailure: "",
    })),
  ),
  { mode: "deep", stage: "resume", queryFailure: "" },
  { mode: "deep", stage: "missing-instructions", queryFailure: "" },
  { mode: "deep", stage: "home-instructions", queryFailure: "" },
  { mode: "deep", stage: "invalid-home-config", queryFailure: "" },
  { mode: "standard", stage: "before", queryFailure: "list-scans" },
  { mode: "deep", stage: "after", queryFailure: "get-scan-recipe" },
] as const)(
  "replay profile ownership survives registration: %j",
  async ({ mode, stage, queryFailure }) => {
    const instructionFailure =
      stage === "missing-instructions" || stage === "invalid-home-config";
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    const scanDir = join(root, "scan");
    await Promise.all([mkdir(repository), mkdir(home, { mode: 0o700 })]);
    await writeFile(join(repository, "source.ts"), "export const value = 1;\n");
    const environment = {
      ...process.env,
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-fixture-key",
    };
    const missingInstructions = join(root, "missing-instructions.md");
    if (stage === "home-instructions") {
      await writeFile(join(home, "instructions.md"), "");
      await writeFile(
        join(home, "config.toml"),
        'model_instructions_file = "instructions.md"\n',
      );
    } else if (stage === "invalid-home-config") {
      await writeFile(
        join(home, "config.toml"),
        "model_instructions_file = [\n",
      );
    }
    const configuration = {
      ...(stage === "missing-instructions"
        ? { model_instructions_file: missingInstructions }
        : {}),
      model: "gpt-5.6-sol",
      model_provider: "openai",
      mcp_servers: {
        synthetic: {
          url: "https://mcp.example.test",
          http_headers: { Authorization: "synthetic-replay-token" },
        },
      },
    };
    const python =
      stage === "home-instructions" || stage === "invalid-home-config"
        ? await resolvePluginPython({ environment, protectedRoot: repository })
        : (Bun.which("python3") ?? Bun.which("python"));
    expect(python).not.toBeNull();
    const workbenchOptions = {
      python: python!,
      pluginRoot: PLUGIN_ROOT,
      environment,
    };
    const interruptedPlugin = join(root, "interrupted-plugin");
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
    if ${JSON.stringify(stage)} in ("after", "resume"):
        signal.raise_signal(signal.SIGINT)
    return result
wb.register_cli_scan = interrupted_registration
if __name__ == "__main__":
    wb.main()
`,
    );
    let locked = false;
    let interrupted: unknown;
    const launchBoundary = new Error("Synthetic launch boundary");
    const warnings: string[] = [];
    const queryError = new Error("Synthetic replay ownership lookup failed");
    let provisionalPath: string | undefined;
    let registrations = 0;
    let ownershipChecks = 0;
    let cleanedBeforeRelease = false;
    await using client = new CodexSecurity(
      { pluginPath: PLUGIN_ROOT, codexOverrides: configuration },
      {
        environment,
        prepareRuntime: async () => ({
          codexHome: home,
          preserveCodexHomeConfig: true,
          environment,
          credentialsAvailable: true,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
        }),
        resolvePluginPython: async () => python!,
        repositoryRevision: async () => null,
        resolveCodexCommand: () => ({ command: process.execPath }),
        probeCodexSandbox: async () => {},
        acquireScanExecution: async (...args) => {
          const release = await acquireScanExecution(...args);
          locked = true;
          return () => {
            if (instructionFailure)
              cleanedBeforeRelease =
                provisionalPath !== undefined && !existsSync(provisionalPath);
            locked = false;
            release();
          };
        },
        createCodex: () => {
          throw launchBoundary;
        },
        runWorkbench: async (options, args, input) => {
          if (args[0] === "register-cli-scan") {
            registrations++;
            const recipe = JSON.parse(input!).recipe as JsonObject;
            const profile = recipe["replayProfile"] as JsonObject;
            expect(profile).toMatchObject({ home: "ambient" });
            provisionalPath = join(home, `${profile["name"]}.config.toml`);
            expect(await readFile(provisionalPath, "utf8")).toContain(
              "synthetic-replay-token",
            );
          }
          if (stage === "resume" && args[0] === "get-cli-scan-resume") {
            expect(
              (await readdir(home)).filter((name) =>
                /^codex_security_.*\.config\.toml$/u.test(name),
              ),
            ).toHaveLength(2);
          }
          if (args[0] === "list-scans" || args[0] === "get-scan-recipe") {
            expect(locked).toBe(true);
            expect(options.signal).toBeUndefined();
            if (instructionFailure) {
              ownershipChecks++;
              const profiles = (await readdir(home)).filter((name) =>
                /^codex_security_.*\.config\.toml$/u.test(name),
              );
              expect(profiles).toHaveLength(1);
              provisionalPath = join(home, profiles[0]!);
              expect(await readFile(provisionalPath, "utf8")).toContain(
                "synthetic-replay-token",
              );
            }
            if (args[0] === queryFailure) throw queryError;
          }
          try {
            return await runWorkbench(
              {
                ...options,
                ...(args[0] === "register-cli-scan" && stage !== "response"
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
      { surface: "sdk" },
    );
    const failure = await client
      .run(repository, {
        mode,
        outputDir: scanDir,
        inheritedPermissions: {
          filesystem: { ":workspace_roots": "write" },
          network: { enabled: false },
        },
        preserveProviderEnvironment: true,
        onWarning: (warning) => warnings.push(warning),
      })
      .catch((error: unknown) => error);
    expect(provisionalPath, String(failure)).toBeDefined();
    if (instructionFailure) {
      if (stage === "missing-instructions")
        expect(failure).toMatchObject({
          code: "ENOENT",
          path: missingInstructions,
        });
      else {
        expect(failure).toBeInstanceOf(Error);
        expect((failure as Error).message).toContain(
          "Could not read the configured Codex provider",
        );
      }
      expect(registrations).toBe(0);
      expect(ownershipChecks).toBe(1);
      expect(cleanedBeforeRelease).toBe(true);
    } else if (stage === "response" || stage === "home-instructions")
      expect(failure).toBe(launchBoundary);
    else {
      expect(interrupted).toBeInstanceOf(Error);
      expect(failure).toBe(interrupted);
      expect((interrupted as Error).message).toContain("KeyboardInterrupt");
    }
    expect(locked).toBe(false);
    if (queryFailure)
      expect(warnings).toEqual([expect.stringContaining(queryError.message)]);
    else expect(warnings).toEqual([]);
    const rows = (
      await runWorkbench(workbenchOptions, [
        "list-scans",
        "--scan-root",
        scanDir,
      ])
    )["scans"] as JsonObject[];
    const saved = rows.filter((row) => row["recipeAvailable"] === true);
    const registered = stage !== "before" && !instructionFailure;
    expect(saved).toHaveLength(registered ? 1 : 0);
    if (instructionFailure) expect(rows).toEqual([]);
    if (stage === "resume") {
      const originalProfile = await readFile(provisionalPath!);
      await expect(
        client.run(repository, {
          mode,
          outputDir: scanDir,
          resumeScanId: saved[0]!["scanId"] as string,
          inheritedPermissions: {
            filesystem: { ":workspace_roots": "write" },
            network: { enabled: false },
          },
          preserveProviderEnvironment: true,
        }),
      ).rejects.toBe(launchBoundary);
      expect(await readFile(provisionalPath!)).toEqual(originalProfile);
    }
    const profiles = (await readdir(home)).filter((name) =>
      /^codex_security_.*\.config\.toml$/u.test(name),
    );
    expect(profiles).toHaveLength(!registered && !queryFailure ? 0 : 1);
    if (registered) {
      const recipe = (
        await runWorkbench(workbenchOptions, [
          "get-scan-recipe",
          "--scan-id",
          saved[0]!["scanId"] as string,
        ])
      )["recipe"] as JsonObject;
      if (stage === "home-instructions") {
        expect(recipe["config"]).not.toHaveProperty("model_instructions_file");
        expect(recipe["scanInputs"]).toMatchObject({
          modelInstructionsFileSha256: createHash("sha256")
            .update("")
            .digest("hex"),
        });
      }
      expect(
        await restoreReplayProfile({}, recipe["replayProfile"], environment),
      ).toMatchObject({ mcp_servers: configuration.mcp_servers });
    }
  },
);
