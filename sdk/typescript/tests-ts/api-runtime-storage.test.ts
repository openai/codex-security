import { codexFactory } from "./support/api-events.js";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import * as fsPromises from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
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

test("preflights with explicit storage paths when the account has no home directory", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  await writeFile(join(repository, "source.py"), "value = 1\n");
  const client = new TestClient(
    {},
    {
      environment: {
        CODEX_HOME: join(root, "codex"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
    },
  );
  const home = spyOn(os, "homedir").mockImplementation(() => {
    throw new Error("No home directory for this account");
  });
  try {
    const scan = await client.preflight(repository, { target: ["source.py"] });
    expect(scan.target.paths).toEqual(["source.py"]);
  } finally {
    home.mockRestore();
    await client.close();
  }
});

test.skipIf(process.platform !== "win32").each(["changed", "canceled"])(
  "retains a %s ZIP error when Windows holds the scan input open",
  async (result) => {
    const root = await temporaryDirectory();
    using temporary = spyOn(os, "tmpdir").mockReturnValue(root);
    const bootstrap = join(root, "bootstrap");
    const output = join(root, "scan");
    const archive = join(root, "selected.zip");
    await mkdir(bootstrap);
    await mkdir(output);
    const plugin = (description: string) =>
      zipSync({
        ".codex-plugin/plugin.json": strToU8(
          JSON.stringify({
            name: "codex-security",
            version: "1.2.3",
            description,
          }),
        ),
      });
    await writeFile(archive, plugin("original"));
    const { zip } = await runtime.resolvePluginSource(
      archive,
      bootstrap,
      undefined,
      true,
    );
    if (result === "changed") await writeFile(archive, plugin("replacement"));
    const controller = new AbortController();
    const reason = new Error("Canceled while preparing the scan input");
    const nativeRename = fsPromises.rename;
    let held = "";
    let release: (() => Promise<void>) | undefined;
    using publication = spyOn(fsPromises, "rename").mockImplementation(
      async (from, to) => {
        await nativeRename(from, to);
        if (basename(String(to)) !== "plugin") return;
        held = dirname(String(to));
        const holder = spawn(
          "node",
          ["-e", 'process.stdout.write("ready"); process.stdin.resume()'],
          { cwd: held, windowsHide: true },
        );
        const exited = once(holder, "exit");
        release = async () => {
          holder.stdin.end();
          await exited;
        };
        await once(holder.stdout, "data");
        if (result === "canceled") controller.abort(reason);
      },
    );
    try {
      const operation = runtime.prepareWindowsScanPluginZip(
        zip!,
        output,
        [bootstrap],
        () => {},
        controller.signal,
      );
      if (result === "canceled") await expect(operation).rejects.toBe(reason);
      else {
        const failure = await operation.catch((error: unknown) => error);
        expect((failure as Error).message).toContain(
          `Could not remove scan input directory ${held}:`,
        );
        expect(failure).toMatchObject({
          cause: {
            name: "LocalPluginBootstrapError",
            message: expect.stringContaining("ZIP changed"),
          },
        });
      }
      expect(publication).toHaveBeenCalled();
      expect(temporary).toHaveBeenCalled();
      expect(existsSync(held)).toBe(true);
    } finally {
      await release?.();
    }
  },
);

test.skipIf(process.platform !== "win32")(
  "cancels ZIP staging while a candidate parent is still being resolved",
  async () => {
    const root = await temporaryDirectory();
    const temp = join(root, "temp");
    const output = join(root, "longer-output-parent", "scan");
    const bootstrap = join(root, "bootstrap");
    const archive = join(root, "selected.zip");
    await mkdir(temp);
    await mkdir(bootstrap);
    await mkdir(output, { recursive: true });
    await writeFile(
      archive,
      zipSync({
        ".codex-plugin/plugin.json": strToU8(
          '{"name":"codex-security","version":"1.2.3"}',
        ),
      }),
    );
    const { zip } = await runtime.resolvePluginSource(
      archive,
      bootstrap,
      undefined,
      true,
    );
    using temporary = spyOn(os, "tmpdir").mockReturnValue(temp);
    const started = Promise.withResolvers<void>();
    const held = Promise.withResolvers<string>();
    const canonicalize = fsPromises.realpath;
    using lookup = spyOn(fsPromises, "realpath").mockImplementation(
      new Proxy(canonicalize, {
        apply(target, receiver, args) {
          if (args[0] !== temp) return Reflect.apply(target, receiver, args);
          started.resolve();
          return held.promise;
        },
      }),
    );
    const controller = new AbortController();
    const reason = new Error("Canceled during scan input placement");
    let canceled: unknown;
    const operation = runtime
      .prepareWindowsScanPluginZip(
        zip!,
        output,
        [bootstrap],
        () => {},
        controller.signal,
      )
      .catch((error: unknown) => {
        canceled = error;
      });
    try {
      await started.promise;
      controller.abort(reason);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(canceled).toBe(reason);
    } finally {
      held.resolve(temp);
      await operation;
    }
    expect(await readdir(temp)).toEqual([]);
    expect(temporary).toHaveBeenCalled();
    expect(lookup).toHaveBeenCalledWith(temp);
    expect(await readdir(dirname(output))).toEqual(["scan"]);
  },
);

test.skipIf(process.platform !== "win32")(
  "prepares the pinned ZIP from its original source for explicit and default Windows scan outputs",
  async () => {
    const root = await temporaryDirectory();
    const archive = join(root, "workflow [source].ZIP");
    const ambient = join(root, "ambient");
    const bootstrap = join(root, "bootstrap");
    const ordinaryTemp = join(root, "scan-temporary");
    const explicit = join(root, "explicit", "scan");
    const deepOutput = join(root, "nested-output-".repeat(8), "scan");
    const equalLengthTemp = join(root, "parallel");
    const configuredDefault = join(root, "state", "scans", "fixture", "scan");
    const privateDefault = join(ambient, "state", "scans", "fixture", "scan");
    for (const path of [
      bootstrap,
      ordinaryTemp,
      explicit,
      deepOutput,
      equalLengthTemp,
      configuredDefault,
      privateDefault,
    ])
      await mkdir(path, { recursive: true });
    const contents = (skill: string) =>
      zipSync({
        "release/.codex-plugin/plugin.json": strToU8(
          JSON.stringify({ name: "codex-security", version: "1.2.3" }),
        ),
        "release/skills/security-scan/SKILL.md": strToU8(skill),
      });
    const original = Buffer.from(contents("# Selected workflow"));
    await writeFile(archive, original);
    const { zip } = await runtime.resolvePluginSource(
      archive,
      bootstrap,
      undefined,
      true,
    );
    expect(zip).toBeDefined();
    // Removing the synthetic install proves every scan reads its selected ZIP.
    await rm(bootstrap, { recursive: true });
    using temporary = spyOn(os, "tmpdir").mockReturnValue(ordinaryTemp);
    const prepare = (scan: string) =>
      runtime.prepareWindowsScanPluginZip(
        zip!,
        scan,
        [ambient, bootstrap],
        () => {},
      );
    for (const [output, temp, expectedParent] of [
      [explicit, ordinaryTemp, dirname(explicit)],
      [explicit, equalLengthTemp, dirname(explicit)],
      [deepOutput, ordinaryTemp, ordinaryTemp],
      [configuredDefault, ordinaryTemp, ordinaryTemp],
      [deepOutput, ambient, dirname(deepOutput)],
      [privateDefault, ordinaryTemp, ordinaryTemp],
    ] as const) {
      temporary.mockReturnValue(temp);
      const staged = await prepare(output);
      expect(staged).toBeDefined();
      try {
        expect(dirname(staged!.workspace)).toBe(expectedParent);
        expect(staged!.root).toBe(join(staged!.workspace, "plugin", "release"));
        expect(
          await readFile(
            join(staged!.root, "skills/security-scan/SKILL.md"),
            "utf8",
          ),
        ).toBe("# Selected workflow");
      } finally {
        await runtime.cleanupSdkDirectory(staged!.workspace);
      }
    }
    expect(await readFile(archive)).toEqual(original);
    await writeFile(archive, contents("different bytes at the same version"));
    await expect(prepare(explicit)).rejects.toThrow(
      "changed after runtime preparation",
    );
    expect(await readdir(dirname(explicit))).toEqual(["scan"]);
    await rm(archive);
    expect(await prepare(explicit)).toBeUndefined();
    expect(await readdir(dirname(explicit))).toEqual(["scan"]);
    await writeFile(archive, original);
    temporary.mockReturnValue(ambient);
    expect(await prepare(privateDefault)).toBeUndefined();
  },
);

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
    let workerFile: string | undefined;
    const stagedPlugins: string[] = [];
    let launched = false;
    let operation: "deep" | "standard" | "validation" = "deep";
    const controller = new AbortController();
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
            const file = join(protectedDirectory!, "config-preflight.toml");
            expect(options.env!["CODEX_SECURITY_CONFIG_PATH"]).toBe(
              operation === "validation" ? undefined : file,
            );
            expect(dirname(file)).toBe(protectedDirectory!);
            expect(await readFile(file, "utf8")).not.toContain(
              "synthetic-client-secret",
            );
            workerFile ??= options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"];
            expect(options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]).toBe(
              operation === "deep" ? workerFile : undefined,
            );
            expect(dirname(dirname(workerFile!))).toBe(
              options.env!["CODEX_HOME"]!,
            );
            expect(await readFile(workerFile!, "utf8")).not.toContain(
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
            const filesystem = parseToml(
              options.configOverrides!.find((value) =>
                value.startsWith("permissions.codex_security_scan.filesystem="),
              )!,
            )["permissions"] as Record<string, Record<string, unknown>>;
            const roots = filesystem["codex_security_scan"]![
              "filesystem"
            ] as Record<string, unknown>;
            expect(roots[dirname(profileFile)]).toEqual({ ".": "deny" });
            if (process.platform === "win32" && operation !== "validation") {
              const staged = options.env!["CODEX_SECURITY_PLUGIN_ROOT"]!;
              expect(dirname(staged)).toBe(protectedDirectory!);
              expect(roots[staged]).toEqual({ ".": "read" });
              expect(roots[protectedDirectory!]).toBeUndefined();
              expect(roots[await realpath(PLUGIN_ROOT)]).toBeUndefined();
              const skill = join("skills", "security-scan", "SKILL.md");
              expect(await readFile(join(staged, skill))).toEqual(
                await readFile(join(PLUGIN_ROOT, skill)),
              );
              stagedPlugins.push(staged);
            }
            if (process.platform !== "win32") {
              expect((await stat(profileFile)).mode & 0o777).toBe(0o600);
              expect((await stat(file)).mode & 0o777).toBe(0o600);
              expect((await stat(dirname(file))).mode & 0o777).toBe(0o700);
              expect((await stat(workerFile!)).mode & 0o777).toBe(0o600);
              expect((await stat(dirname(workerFile!))).mode & 0o777).toBe(
                0o700,
              );
            }
            throw new Error("synthetic scan reached");
          })(),
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
            : "synthetic scan reached",
      );
      expect(protectedDirectory).toBeDefined();
      expect(launched).toBe(preparation === "ready");
      if (preparation !== "ready") {
        expect(existsSync(protectedDirectory!)).toBe(false);
      } else {
        operation = "standard";
        await expect(client.run(repository)).rejects.toThrow(
          "synthetic scan reached",
        );
        expect(existsSync(protectedDirectory!)).toBe(true);
        for (const staged of stagedPlugins)
          expect(existsSync(staged)).toBe(false);
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
    if (workerFile !== undefined) {
      expect(existsSync(dirname(workerFile))).toBe(false);
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
    const snapshotAcl = (path = temporary) => {
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
            CODEX_SECURITY_TEST_TEMP: path,
            PSModulePath: join(system, "WindowsPowerShell", "v1.0", "Modules"),
          },
          windowsHide: true,
        },
      );
      expect(result.status, result.stderr).toBe(0);
      return result.stdout.trim();
    };
    let temporaryAcl: string | undefined;
    const sourceAcl =
      process.platform === "win32" ? snapshotAcl(pluginPath) : undefined;
    if (process.platform === "win32") {
      const grant = spawnSync(
        join(process.env["SystemRoot"]!, "System32", "icacls.exe"),
        [temporary, "/grant", "*S-1-1-0:(OI)(CI)(M,DC)"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(grant.status, grant.stderr).toBe(0);
      temporaryAcl = snapshotAcl();
      await expect(runtime.createIsolatedHome(temporary)).rejects.toThrow(
        "could not be trusted",
      );
      const rejected = join(temporary, "credential-home");
      await mkdir(rejected);
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
    const zipInputs = new Set<string>();
    let defaultOutput = false;
    let movedArchive = false;
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
            const plugin = environment["CODEX_SECURITY_PLUGIN_ROOT"]!;
            if (
              source === "zip" &&
              process.platform === "win32" &&
              !movedArchive
            ) {
              const input = dirname(plugin);
              expect(dirname(input)).toBe(
                dirname(environment["CODEX_SECURITY_SCAN_DIR"]!),
              );
              expect(zipInputs.has(input)).toBe(false);
              zipInputs.add(input);
              expect(
                existsSync(join(plugin, "skills/security-scan/SKILL.md")),
              ).toBe(true);
              const overrides = options.configOverrides!.find((entry) =>
                entry.startsWith("permissions.codex_security_scan.filesystem="),
              )!;
              expect(parseToml(overrides)).toEqual({
                permissions: {
                  codex_security_scan: {
                    filesystem: {
                      ":root": "read",
                      ":workspace_roots": "write",
                      [plugin]: { ".": "read" },
                      [environment["CODEX_HOME"]!]: { ".": "deny" },
                    },
                  },
                },
              });
            } else {
              expect(plugin).toBe(
                source === "zip"
                  ? join(workspace, "extracted-plugin")
                  : pluginPath,
              );
              if (movedArchive)
                expect(
                  options.configOverrides!.some((entry) =>
                    entry.startsWith(
                      "permissions.codex_security_scan.filesystem=",
                    ),
                  ),
                ).toBe(false);
            }
            const codex = codexFactory(async function () {
              throw new Error("synthetic scan reached");
            })();
            return {
              startThread: (threadOptions) => {
                if (defaultOutput) {
                  expect(dirname(threadOptions.workingDirectory!)).toBe(
                    join(stateDirectory, "scans", "repository"),
                  );
                } else
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
      for (const input of zipInputs) expect(existsSync(input)).toBe(false);
      expect(workspaces.get(0)).not.toBe(workspaces.get(1));
      await first.close();
      expect(existsSync(workspaces.get(0)!)).toBe(false);
      expect(existsSync(workspaces.get(1)!)).toBe(true);
      await expect(run(second, 1)).rejects.toThrow("synthetic scan reached");
      for (const input of zipInputs) expect(existsSync(input)).toBe(false);
      if (process.platform === "win32") {
        if (source === "zip") {
          defaultOutput = true;
          await expect(second.run(repository)).rejects.toThrow(
            "synthetic scan reached",
          );
          defaultOutput = false;
          for (const input of zipInputs) expect(existsSync(input)).toBe(false);
          movedArchive = true;
          await fsPromises.rename(pluginPath, `${pluginPath}.moved`);
          try {
            await expect(run(second, 1)).rejects.toThrow(
              "synthetic scan reached",
            );
          } finally {
            await fsPromises.rename(`${pluginPath}.moved`, pluginPath);
            movedArchive = false;
          }
        }
        const rejected = createClient(2, join(temporary, "untrusted-state"));
        await expect(run(rejected, 2)).rejects.toThrow(
          "allows another identity to replace",
        );
        expect(workspaces.has(2)).toBe(false);
        expect(snapshotAcl()).toBe(temporaryAcl!);
        expect(snapshotAcl(pluginPath)).toBe(sourceAcl!);
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
  process.platform === "win32" ? 120_000 : 60_000,
);
