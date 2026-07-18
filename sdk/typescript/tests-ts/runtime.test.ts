import { renameSync, rmSync, symlinkSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, parse, relative, sep } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import {
  bootstrapPlugin,
  bundledPluginRoot,
  createIsolatedHome,
  createMarketplace,
  extractPluginZip,
  importAmbientAuth,
  pluginExecutionEnvironment,
  PluginBootstrapError,
  PluginPythonUnavailableError,
  OutputDirectoryError,
  prepareOutputDir,
  resolveCodexCommand,
  resolvePluginPath,
  resolvePluginPython,
  validateOutputDir,
} from "../src/index.js";
import {
  bundledPluginCandidates,
  codexPlatformPackage,
  isPythonPathCandidate,
} from "../src/runtime.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

async function temporaryDirectory(
  prefix = "codex-security-runtime-",
): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  temporaryDirectories.push(path);
  return path;
}

async function plugin(root: string, version = "1.2.3"): Promise<string> {
  const path = join(root, "plugin");
  await mkdir(join(path, ".codex-plugin"), { recursive: true });
  await writeFile(
    join(path, ".codex-plugin", "plugin.json"),
    JSON.stringify({ name: "codex-security", version }),
  );
  await mkdir(join(path, "scripts"));
  await writeFile(join(path, "scripts", "helper.py"), "print('ok')\n");
  return path;
}

describe("plugin runtime preparation", () => {
  test("keeps installed-package plugin lookup inside the package", async () => {
    const root = await temporaryDirectory();
    const packageRoot = join(root, "node_modules", "@openai", "codex-security");
    const candidates = bundledPluginCandidates(join(packageRoot, "dist"));
    expect(candidates).toEqual([
      join(packageRoot, "dist", "_bundled_plugin"),
      join(packageRoot, "_bundled_plugin"),
    ]);
    expect(
      candidates.every((candidate) => {
        const path = relative(packageRoot, candidate);
        return (
          path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path)
        );
      }),
    ).toBe(true);
  });

  test("projects only the unchanged external payload from the source checkout", async () => {
    const root = await temporaryDirectory();
    const workspace = join(root, "workspace");
    await mkdir(workspace);
    const projected = await resolvePluginPath(undefined, workspace);
    expect(
      await readFile(join(projected, ".codex-plugin", "plugin.json"), "utf8"),
    ).toContain('"name": "codex-security"');
    expect(
      await stat(join(projected, "scripts", "config_preflight.py")),
    ).toBeDefined();
    await expect(stat(join(projected, ".internal"))).rejects.toThrow();
    expect(
      await stat(
        join(await bundledPluginRoot(), ".codex-plugin", "plugin.json"),
      ),
    ).toBeDefined();
  });

  test("creates the SDK marketplace around a validated plugin", async () => {
    const root = await temporaryDirectory();
    const selected = await plugin(root);
    const marketplace = await createMarketplace(join(root, "home"), selected);
    const manifest = JSON.parse(
      await readFile(
        join(marketplace, ".agents", "plugins", "marketplace.json"),
        "utf8",
      ),
    );
    expect(manifest.name).toBe("codex-security-sdk");
    expect(manifest.plugins[0].source.path).toBe("./plugins/codex-security");
    expect(
      await stat(
        join(
          marketplace,
          "plugins",
          "codex-security",
          ".codex-plugin",
          "plugin.json",
        ),
      ),
    ).toBeDefined();
  });

  test("extracts a plugin in one top-level directory", async () => {
    const root = await temporaryDirectory();
    const archive = join(root, "plugin.zip");
    await writeFile(
      archive,
      zipSync({
        "release/.codex-plugin/plugin.json": strToU8(
          JSON.stringify({ name: "codex-security", version: "1.2.3" }),
        ),
      }),
    );
    const extracted = await extractPluginZip(archive, join(root, "extracted"));
    expect(extracted).toBe(join(root, "extracted", "release"));
  });

  test("decodes flag-clear ZIP filenames with the legacy CP437 encoding", async () => {
    const root = await temporaryDirectory();
    const archive = Buffer.from(
      zipSync({
        "release/.codex-plugin/plugin.json": strToU8(
          JSON.stringify({ name: "codex-security", version: "1.2.3" }),
        ),
        "release/x.txt": strToU8("legacy filename\n"),
      }),
    );
    let replacements = 0;
    for (let offset = archive.indexOf("release/x.txt"); offset >= 0; ) {
      archive[offset + "release/".length] = 0x82;
      replacements += 1;
      offset = archive.indexOf("release/x.txt", offset + 1);
    }
    expect(replacements).toBe(2);
    const path = join(root, "legacy.zip");
    await writeFile(path, archive);

    const extracted = await extractPluginZip(path, join(root, "extracted"));
    expect(await readFile(join(extracted, "é.txt"), "utf8")).toBe(
      "legacy filename\n",
    );
  });

  test("honors cancellation while preparing a plugin ZIP", async () => {
    const root = await temporaryDirectory();
    const archive = join(root, "plugin.zip");
    await writeFile(
      archive,
      zipSync({
        "release/.codex-plugin/plugin.json": strToU8(
          JSON.stringify({ name: "codex-security", version: "1.2.3" }),
        ),
      }),
    );
    const controller = new AbortController();
    controller.abort(new DOMException("canceled", "AbortError"));
    await expect(
      extractPluginZip(archive, join(root, "extracted"), controller.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(
      (await readdir(root)).some((name) =>
        name.startsWith(".codex-security-plugin-"),
      ),
    ).toBe(false);
  });

  test("rejects traversal, Windows-qualified, duplicate, and symlink ZIP paths", async () => {
    const unsafeArchives: Array<[string, Uint8Array]> = [
      ["traversal", zipSync({ "../escape": strToU8("bad") })],
      ["drive", zipSync({ "D:/escape": strToU8("bad") })],
      ["backslash", zipSync({ "release\\escape": strToU8("bad") })],
      [
        "symlink",
        zipSync({
          "release/.codex-plugin/plugin.json": strToU8(
            JSON.stringify({ name: "codex-security", version: "1.2.3" }),
          ),
          "release/link": [strToU8("target"), { os: 3, attrs: 0o120777 << 16 }],
        }),
      ],
    ];
    for (const [name, archive] of unsafeArchives) {
      const root = await temporaryDirectory();
      const path = join(root, `${name}.zip`);
      await writeFile(path, archive);
      await expect(
        extractPluginZip(path, join(root, "extract")),
      ).rejects.toThrow(PluginBootstrapError);
    }
  });

  test("reports malformed ZIPs as plugin bootstrap errors", async () => {
    const root = await temporaryDirectory();
    const archive = join(root, "bad.zip");
    await writeFile(archive, "not a zip archive");
    await expect(
      extractPluginZip(archive, join(root, "extract")),
    ).rejects.toThrow("Invalid plugin ZIP");
  });

  test("rejects ZIP entries whose contents fail CRC-32 validation", async () => {
    const root = await temporaryDirectory();
    const archive = Buffer.from(
      zipSync(
        {
          "release/file.txt": strToU8("ORIGINAL"),
        },
        { level: 0 },
      ),
    );
    const contentOffset = archive.indexOf("ORIGINAL");
    expect(contentOffset).toBeGreaterThanOrEqual(0);
    archive.write("TAMPERED", contentOffset, "utf8");
    const path = join(root, "bad-crc.zip");
    await writeFile(path, archive);
    await expect(extractPluginZip(path, join(root, "extract"))).rejects.toThrow(
      "CRC-32",
    );
  });

  test("rejects ZIP entries whose declared expansion exceeds the limit", async () => {
    const root = await temporaryDirectory();
    const archive = Buffer.from(zipSync({ file: strToU8("small") }));
    let central = -1;
    for (let index = 0; index <= archive.length - 4; index += 1) {
      if (archive.readUInt32LE(index) === 0x02014b50) {
        central = index;
        break;
      }
    }
    expect(central).toBeGreaterThanOrEqual(0);
    archive.writeUInt32LE(128 * 1024 * 1024 + 1, central + 24);
    const path = join(root, "oversized.zip");
    await writeFile(path, archive);
    await expect(extractPluginZip(path, join(root, "extract"))).rejects.toThrow(
      "safety limit",
    );
  });

  test("imports ambient auth with private permissions", async () => {
    const root = await temporaryDirectory();
    const ambient = join(root, "ambient");
    const isolated = join(root, "isolated");
    await mkdir(ambient);
    await writeFile(join(ambient, "auth.json"), '{"token":"test"}\n');
    expect(await importAmbientAuth(ambient, isolated)).toBe(true);
    expect(await readFile(join(isolated, "auth.json"), "utf8")).toBe(
      '{"token":"test"}\n',
    );
    if (process.platform !== "win32") {
      expect((await stat(join(isolated, "auth.json"))).mode & 0o777).toBe(
        0o600,
      );
    }
  });

  test.skipIf(process.platform === "win32")(
    "imports symlink-backed ambient auth",
    async () => {
      const root = await temporaryDirectory();
      const ambient = join(root, "ambient");
      const isolated = join(root, "isolated");
      const source = join(root, "auth-source.json");
      await mkdir(ambient);
      await writeFile(source, '{"token":"linked"}\n');
      await symlink(source, join(ambient, "auth.json"));

      expect(await importAmbientAuth(ambient, isolated)).toBe(true);
      expect(await readFile(join(isolated, "auth.json"), "utf8")).toBe(
        '{"token":"linked"}\n',
      );
    },
  );

  test("bootstraps through supported Codex plugin commands and verifies registration", async () => {
    const root = await temporaryDirectory();
    const selected = await plugin(root);
    const home = join(root, "home");
    await mkdir(home);
    await writeFile(join(home, "config.toml"), "[features]\nplugins = true\n");
    const calls: string[][] = [];
    const installed = join(
      home,
      "plugins",
      "cache",
      "codex-security-sdk",
      "codex-security",
      "1.2.3",
    );
    const install = await bootstrapPlugin(home, selected, {
      codexCommand: { command: "/codex", prefixArgs: [] },
      environment: {
        CODEX_API_KEY: "codex-secret",
        OPENAI_API_KEY: "openai-secret",
        CoDeX_ApI_KeY: "mixed-secret",
        openai_api_key: "lowercase-secret",
        SAFE_VALUE: "kept",
      },
      runCodex: async (_command, args, environment) => {
        expect(environment["CODEX_HOME"]).toBe(home);
        expect(environment["CODEX_API_KEY"]).toBeUndefined();
        expect(environment["OPENAI_API_KEY"]).toBeUndefined();
        expect(environment["CoDeX_ApI_KeY"]).toBeUndefined();
        expect(environment["openai_api_key"]).toBeUndefined();
        expect(environment["SAFE_VALUE"]).toBe("kept");
        calls.push([...args]);
        if (args[1] === "marketplace") {
          await writeFile(
            join(home, "config.toml"),
            `\n[marketplaces.codex-security-sdk]\nsource_type = "local"\nsource = ${JSON.stringify(join(home, "sdk-marketplace"))}\n`,
            { flag: "a" },
          );
        } else {
          await writeFile(
            join(home, "config.toml"),
            '\n[plugins."codex-security@codex-security-sdk"]\nenabled = true\n',
            { flag: "a" },
          );
          await mkdir(join(installed, ".codex-plugin"), { recursive: true });
          await writeFile(
            join(installed, ".codex-plugin", "plugin.json"),
            JSON.stringify({ name: "codex-security", version: "1.2.3" }),
          );
        }
        return "";
      },
    });
    expect(calls).toEqual([
      ["plugin", "marketplace", "add", join(home, "sdk-marketplace")],
      ["plugin", "add", "codex-security@codex-security-sdk"],
    ]);
    expect(install.installedRoot).toBe(installed);
    expect(install.version).toBe("1.2.3");
  });

  test("resolves the exact npm Codex executable", () => {
    const command = resolveCodexCommand();
    const target = codexPlatformPackage();
    expect(command.prefixArgs).toEqual([]);
    expect(command.command).toContain(
      join(
        "vendor",
        target.targetTriple,
        "bin",
        process.platform === "win32" ? "codex.exe" : "codex",
      ),
    );
  });

  test("selects the native Windows Codex executable package", () => {
    expect(codexPlatformPackage("win32", "x64")).toEqual({
      packageName: "@openai/codex-win32-x64",
      targetTriple: "x86_64-pc-windows-msvc",
    });
  });
});

describe("runtime directories and plugin Python boundary", () => {
  test("validates explicit output directories and creates private temporary paths", async () => {
    const root = await temporaryDirectory();
    const absent = join(root, "scan");
    expect(await validateOutputDir(absent)).toBe(absent);
    expect(await prepareOutputDir(absent, "repo")).toBe(absent);
    if (process.platform !== "win32") {
      const callerOwned = join(root, "caller-owned");
      await mkdir(callerOwned, { mode: 0o770 });
      await chmod(callerOwned, 0o770);
      expect(await prepareOutputDir(callerOwned, "repo")).toBe(callerOwned);
      expect((await stat(callerOwned)).mode & 0o777).toBe(0o770);
    }
    const filesystemChild = join(
      parse(root).root,
      `codex-security-uncreated-${process.pid}`,
    );
    expect(await validateOutputDir(filesystemChild)).toBe(filesystemChild);
    await writeFile(join(absent, "occupied"), "x");
    await expect(validateOutputDir(absent)).rejects.toThrow("must be empty");

    const home = await createIsolatedHome();
    temporaryDirectories.push(home);
    if (process.platform !== "win32") {
      expect((await stat(home)).mode & 0o777).toBe(0o700);

      const canonicalParent = join(root, "canonical-parent");
      const linkedParent = join(root, "linked-parent");
      await mkdir(canonicalParent);
      await symlink(canonicalParent, linkedParent);
      expect(await prepareOutputDir(join(linkedParent, "scan"), "repo")).toBe(
        await realpath(join(canonicalParent, "scan")),
      );

      const restrictedRoot = join(root, "restricted-root");
      await mkdir(restrictedRoot);
      const previousUmask = process.umask(0o777);
      try {
        const restrictedPaths = [
          await createIsolatedHome(restrictedRoot),
          await prepareOutputDir(undefined, "repo", restrictedRoot),
          await prepareOutputDir(join(restrictedRoot, "scan"), "repo"),
        ];
        for (const path of restrictedPaths) {
          expect((await stat(path)).mode & 0o777).toBe(0o700);
        }
      } finally {
        process.umask(previousUmask);
      }

      const repository = join(root, "repository");
      const movableParent = join(root, "movable-parent");
      const movedParent = join(root, "moved-parent");
      await mkdir(repository);
      await mkdir(movableParent);
      const requested = await validateOutputDir(join(movableParent, "scan"));
      expect(requested).not.toBeNull();
      await rename(movableParent, movedParent);
      await symlink(repository, movableParent);
      let checkedPath: string | undefined;
      await expect(
        prepareOutputDir(requested ?? undefined, "repo", undefined, (path) => {
          checkedPath = path;
          throw new Error("unsafe output location");
        }),
      ).rejects.toThrow("unsafe output location");
      expect(checkedPath).toBe(join(repository, "scan"));
      await expect(stat(join(repository, "scan"))).rejects.toThrow();

      const temporaryRoot = join(root, "temporary-root");
      const movedTemporaryRoot = join(root, "moved-temporary-root");
      await mkdir(temporaryRoot);
      let checks = 0;
      await expect(
        prepareOutputDir(undefined, "repo", temporaryRoot, (path) => {
          checks += 1;
          if (checks === 1) {
            renameSync(temporaryRoot, movedTemporaryRoot);
            symlinkSync(repository, temporaryRoot);
          } else {
            expect(path.startsWith(`${repository}${sep}`)).toBe(true);
            throw new Error("unsafe temporary output location");
          }
        }),
      ).rejects.toThrow("unsafe temporary output location");
      expect(checks).toBe(2);
      expect(await readdir(repository)).toEqual([]);

      const runtimeVictim = join(root, "runtime-victim");
      await mkdir(runtimeVictim);
      await expect(
        createIsolatedHome(root, (path) => {
          renameSync(path, `${path}-moved`);
          symlinkSync(runtimeVictim, path);
        }),
      ).rejects.toThrow("changed during preparation");
      expect(await readdir(runtimeVictim)).toEqual([]);

      const cleanupParent = join(root, "cleanup-parent");
      const movedCleanupParent = join(root, "moved-cleanup-parent");
      const victim = join(root, "cleanup-victim");
      const victimScan = join(victim, "one", "scan");
      await mkdir(victimScan, { recursive: true });
      let cleanupChecks = 0;
      await expect(
        prepareOutputDir(
          join(cleanupParent, "one", "scan"),
          "repo",
          undefined,
          () => {
            cleanupChecks += 1;
            if (cleanupChecks === 2) {
              renameSync(cleanupParent, movedCleanupParent);
              symlinkSync(victim, cleanupParent);
              throw new Error("unsafe cleanup location");
            }
          },
        ),
      ).rejects.toThrow("Unable to create scan output directory");
      expect(cleanupChecks).toBe(2);
      await expect(stat(victimScan)).resolves.toBeDefined();
      await expect(
        stat(join(movedCleanupParent, "one", "scan")),
      ).resolves.toBeDefined();

      const leafParent = join(root, "leaf-parent");
      const leaf = join(leafParent, "scan");
      await mkdir(leafParent);
      let leafChecks = 0;
      await expect(
        prepareOutputDir(leaf, "repo", undefined, (path) => {
          leafChecks += 1;
          if (leafChecks === 2) {
            rmSync(path, { recursive: true, force: true });
            symlinkSync(repository, path);
          }
        }),
      ).rejects.toBeInstanceOf(OutputDirectoryError);
      expect(leafChecks).toBe(2);
      expect(await readdir(repository)).toEqual([]);
    }
  });

  test.skipIf(process.platform === "win32")(
    "uses configured, inherited, then managed Python and forwards PYTHON",
    async () => {
      const root = await temporaryDirectory();
      const configured = join(root, "configured-python");
      await writeFile(
        configured,
        '#!/bin/sh\n[ "$1" = "-c" ] || exit 1\ncase "$2" in *"raise SystemExit(1)"*) ;; *) exit 1 ;; esac\ncase "$2" in *assert*) exit 1 ;; esac\nprintf "codex-security-python-ok\\n"\n',
      );
      await chmod(configured, 0o700);
      const canonicalConfigured = await realpath(configured);
      expect(
        await resolvePluginPython({
          configuredPath: relative(process.cwd(), configured),
          environment: { PATH: "", PYTHONOPTIMIZE: "1" },
        }),
      ).toBe(canonicalConfigured);
      expect(
        await resolvePluginPython({
          environment: { PYTHON: configured, PATH: "" },
        }),
      ).toBe(canonicalConfigured);

      const managedRoot = join(root, "codex-primary-runtime");
      const managed = join(
        managedRoot,
        "dependencies",
        "python",
        "bin",
        "python3",
      );
      await mkdir(join(managedRoot, "dependencies", "python", "bin"), {
        recursive: true,
      });
      await writeFile(
        managed,
        '#!/bin/sh\n[ "$1" = "-c" ] || exit 1\ncase "$2" in *"raise SystemExit(1)"*) ;; *) exit 1 ;; esac\ncase "$2" in *assert*) exit 1 ;; esac\nprintf "codex-security-python-ok\\n"\n',
      );
      await chmod(managed, 0o700);
      expect(
        await resolvePluginPython({
          environment: { PATH: "" },
          managedRuntimeRoots: [managedRoot],
        }),
      ).toBe(managed);
      expect(pluginExecutionEnvironment(managed, { TEST: "1" })).toEqual({
        TEST: "1",
        PYTHON: managed,
      });
      if (process.platform !== "win32") {
        await expect(
          resolvePluginPython({
            configuredPath: "/bin/true",
            environment: { PATH: "" },
          }),
        ).rejects.toThrow(PluginPythonUnavailableError);
      }
    },
  );

  test("recognizes Python paths using either platform separator", () => {
    expect(isPythonPathCandidate("runtime/python3")).toBe(true);
    expect(isPythonPathCandidate("runtime\\python.exe")).toBe(true);
    expect(isPythonPathCandidate("./python3")).toBe(true);
    expect(isPythonPathCandidate("python3")).toBe(false);
  });

  test("returns a targeted plugin diagnostic when Python is unavailable", async () => {
    const root = await temporaryDirectory();
    const emptyPath = join(root, "empty-path");
    await mkdir(emptyPath);
    await expect(
      resolvePluginPython({
        environment: { PATH: emptyPath },
        homeDirectory: root,
        managedRuntimeRoots: [],
      }),
    ).rejects.toThrow(PluginPythonUnavailableError);
  });

  test.skipIf(process.platform === "win32")(
    "preserves cancellation during Python interpreter probes",
    async () => {
      const root = await temporaryDirectory();
      const interpreter = join(root, "python");
      await writeFile(interpreter, "#!/bin/sh\nwhile :; do :; done\n");
      await chmod(interpreter, 0o700);
      const controller = new AbortController();
      const resolving = resolvePluginPython({
        configuredPath: interpreter,
        environment: { PATH: "" },
        signal: controller.signal,
      });
      controller.abort();
      await expect(resolving).rejects.toMatchObject({ name: "AbortError" });
    },
  );

  test("does not leave extraction staging directories after failure", async () => {
    const root = await temporaryDirectory();
    const archive = join(root, "bad.zip");
    await writeFile(archive, zipSync({ "../escape": strToU8("bad") }));
    await expect(
      extractPluginZip(archive, join(root, "extract")),
    ).rejects.toThrow();
    expect(
      (await readdir(root)).some((name) =>
        name.startsWith(".codex-security-plugin-"),
      ),
    ).toBe(false);
  });
});
