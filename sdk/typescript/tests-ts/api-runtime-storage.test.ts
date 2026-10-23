import { codexFactory } from "./support/api-events.js";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import * as os from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import * as runtime from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { parse as parseToml } from "smol-toml";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

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
    const protectedDirectories = new Set<string>();
    let lastConfigFile: string | undefined;
    let launched = false;
    let operation: "deep" | "standard" | "validation" = "deep";
    const controller = new AbortController();
    const reached = new Error("synthetic scan reached");
    const install = stubPluginInstall();
    const guard = spyOn(
      runtime,
      "requirePrivateCredentialHome",
    ).mockImplementation(async (metadata, path, options) => {
      if (!basename(path).startsWith("openai-codex-security-home-"))
        return original(metadata, path, options);
      await original(metadata, path, {
        platform: "win32",
        secureWindowsHome: async (directory) => {
          expect(await readdir(directory)).toEqual([]);
          protectedDirectory = directory;
          protectedDirectories.add(directory);
          expect(dirname(directory)).toBe(
            process.platform === "win32"
              ? join(root, "state")
              : await realpath(os.tmpdir()),
          );
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
        createCodex: (options) =>
          codexFactory(async function runStreamed() {
            launched = true;
            const file =
              options.env!["CODEX_SECURITY_CONFIG_PATH"] ?? lastConfigFile!;
            lastConfigFile = file;
            expect(options.env!["CODEX_SECURITY_CONFIG_PATH"]).toBe(
              operation === "validation" ? undefined : file,
            );
            expect(protectedDirectories.has(dirname(file))).toBe(true);
            expect(await readFile(file, "utf8")).not.toContain(
              "synthetic-client-secret",
            );
            const profileFile = join(
              options.env!["CODEX_HOME"]!,
              `${options.nativeProfile}.config.toml`,
            );
            expect(await readFile(profileFile, "utf8")).toContain(
              "synthetic-client-secret",
            );
            expect(JSON.stringify(options)).not.toContain(
              "synthetic-client-secret",
            );
            const config = parseToml(
              await readFile(
                join(options.env!["CODEX_HOME"]!, "config.toml"),
                "utf8",
              ),
            );
            const permissions = config["permissions"] as Record<
              string,
              { filesystem: Record<string, unknown> }
            >;
            expect(
              permissions["codex_security_scan"]!.filesystem[
                dirname(profileFile)
              ],
            ).toEqual({ ".": "deny" });
            if (process.platform !== "win32") {
              expect((await stat(profileFile)).mode & 0o777).toBe(0o600);
              expect((await stat(file)).mode & 0o777).toBe(0o600);
              expect((await stat(dirname(file))).mode & 0o777).toBe(0o700);
            }
            if (operation === "deep") controller.abort(reached);
            throw reached;
          })(),
      },
    );
    try {
      const scanResult = client.run(repository, {
        mode: "deep",
        signal: controller.signal,
      });
      if (preparation === "ready") {
        await expect(scanResult).rejects.toMatchObject({ cause: reached });
      } else {
        await expect(scanResult).rejects.toThrow(
          preparation === "denied"
            ? "synthetic ACL denial"
            : "interrupted during preparation",
        );
      }
      expect(protectedDirectory).toBeDefined();
      expect(launched).toBe(preparation === "ready");
      if (preparation !== "ready") {
        expect(existsSync(protectedDirectory!)).toBe(false);
      } else {
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
      }
    } finally {
      guard.mockRestore();
      install.mockRestore();
      await client.close();
    }
    expect(existsSync(protectedDirectory!)).toBe(false);
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
