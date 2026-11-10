import { chmod, mkdir, stat, symlink, writeFile } from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import * as moduleApi from "node:module";
import { join } from "node:path";
import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  bundledPluginRoot,
  createWindowsOutputDirectory,
  validateOutputDir,
} from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { createCliTest } from "./support/cli-run.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const fixtures = createApiTestFixtures("codex-security-cli-output-");
afterEach(fixtures.cleanup);

async function scanFixture() {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const output = join(root, "results");
  await mkdir(repository);
  git(repository, "init", "-q");
  const started = mock();
  const deps = dependencies({
    currentDirectory: repository,
    onRun: started,
  });
  const createSecurity = deps.createSecurity;
  deps.createSecurity = (config) => {
    const security = createSecurity(config);
    return {
      ...security,
      run: async (target, options) => {
        await validateOutputDir(options?.outputDir, options?.archiveExisting);
        return security.run(target, options);
      },
      preflight: async (target, options) => {
        await validateOutputDir(options?.outputDir, options?.archiveExisting);
        return security.preflight(target, options);
      },
    };
  };
  return { root, output, started, deps };
}

async function mockWindowsOutputBinding(load: () => unknown) {
  const binding = join(
    await bundledPluginRoot(),
    "mcp",
    "native",
    `win32-${process.arch}`,
    "windows.node",
  );
  const createRequire = moduleApi.createRequire;
  return spyOn(moduleApi, "createRequire").mockImplementation((from) => {
    const require = createRequire(from);
    return Object.assign(
      (id: string) => (id === binding ? load() : require(id)),
      require,
    );
  });
}

describe("CLI output directory permissions", () => {
  test.skipIf(process.platform !== "win32").each([
    [
      "Node policy block",
      "An Application Control policy has blocked this file.\r\nC:\\synthetic-install\\windows.node",
      true,
    ],
    [
      "Bun policy block",
      "LoadLibrary failed: An Application Control policy has blocked this file.",
      true,
    ],
    [
      "another load failure",
      "Invalid image in C:\\An Application Control policy has blocked this file.\\windows.node",
      false,
    ],
  ] as const)(
    "identifies a Windows module load failure (%s)",
    async (_label, detail, blocked) => {
      const { output, started, deps } = await scanFixture();
      const cause = Object.assign(new Error(detail), {
        code: "ERR_DLOPEN_FAILED",
      });
      using _loader = await mockWindowsOutputBinding(() => {
        throw cause;
      });
      const { runCli, stdout } = createCliTest(main);
      expect(
        await runCli(["scan", ".", "--json", "--output-dir", output], deps),
      ).toBe(2);
      const message = blocked
        ? "Windows Application Control blocked the bundled Codex Security filesystem module (windows.node). Check the CodeIntegrity Operational log in Event Viewer."
        : "Could not load the bundled Codex Security filesystem module (windows.node) on Windows.";
      expect(JSON.parse(stdout.text())).toEqual({
        status: "failed",
        code: "SCAN_FAILED",
        message,
      });
      await mkdir(output);
      await expect(validateOutputDir(output)).rejects.toMatchObject({
        message,
        cause,
      });
      await expect(createWindowsOutputDirectory(output, false)).rejects.toBe(
        cause,
      );
      expect(started).not.toHaveBeenCalled();
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves the Windows output ACL error after loading the module",
    async () => {
      const { output } = await scanFixture();
      using _loader = await mockWindowsOutputBinding(() => ({
        validateWindowsOutputPath: () => 5,
      }));
      await expect(validateOutputDir(output)).rejects.toThrow(
        "could not be trusted (Windows error 5)",
      );
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves other output inspection failures",
    async () => {
      const { output } = await scanFixture();
      const cause = Object.assign(
        new Error("An Application Control policy has blocked this file."),
        { code: "EACCES" },
      );
      const load = mock(() => {
        throw cause;
      });
      using _loader = await mockWindowsOutputBinding(load);
      await expect(validateOutputDir(output)).rejects.toMatchObject({
        message: `Unable to inspect scan output directory: ${output}`,
        cause,
      });
      const unrelated = Object.assign(new Error("Other module"), {
        code: "ERR_DLOPEN_FAILED",
      });
      using _lstat = spyOn(fsPromises, "lstat").mockRejectedValueOnce(
        unrelated,
      );
      await expect(validateOutputDir(output)).rejects.toMatchObject({
        message: `Unable to inspect scan output directory: ${output}`,
        cause: unrelated,
      });
      await writeFile(output, "existing file");
      await expect(validateOutputDir(output)).rejects.toThrow(
        `Scan output is not a directory: ${output}`,
      );
      expect(load).toHaveBeenCalledTimes(1);
    },
  );

  test.skipIf(process.platform === "win32").each([
    ["standard", [], 0o755],
    ["deep", [], 0o775],
    ["standard", ["--headless"], 0o770],
  ] as const)(
    "preserves existing permissions for a %s scan %j",
    async (mode, flags, permissions) => {
      const { output, started, deps } = await scanFixture();
      await mkdir(output);
      await chmod(output, permissions);
      const { runCli } = createCliTest(main, { stderr: true });

      expect(
        await runCli(
          ["scan", ".", "--mode", mode, "--output-dir", output, ...flags],
          deps,
        ),
      ).toBe(0);
      expect((await stat(output)).mode & 0o777).toBe(permissions);
      expect(started).toHaveBeenCalledTimes(1);
    },
  );

  test.skipIf(process.platform === "win32")(
    "accepts existing permissions during non-interactive scans and dry runs",
    async () => {
      for (const scenario of [
        { flags: ["--json"] },
        { flags: ["--format", "jsonl"] },
        { flags: ["--dry-run"], dryRun: true },
        { environment: { CI: "true" } },
        { environment: { TERM: "dumb" } },
        { terminal: false },
      ]) {
        const { output, started, deps } = await scanFixture();
        await mkdir(output);
        await chmod(output, 0o755);
        deps.environment = scenario.environment ?? {};
        const { runCli } = createCliTest(main, {
          stderr: scenario.terminal !== false,
        });

        expect(
          await runCli(
            ["scan", ".", "--output-dir", output, ...(scenario.flags ?? [])],
            deps,
          ),
        ).toBe(0);
        expect((await stat(output)).mode & 0o777).toBe(0o755);
        expect(started).toHaveBeenCalledTimes(scenario.dryRun ? 0 : 1);
      }
    },
  );

  test.each(["missing", "private"])(
    "accepts a %s output directory",
    async (state) => {
      const { output, started, deps } = await scanFixture();
      if (state === "private") await mkdir(output, { mode: 0o700 });
      const { runCli } = createCliTest(main, { stderr: true });

      expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(0);
      expect(started).toHaveBeenCalledTimes(1);
    },
  );

  test.skipIf(process.platform === "win32")(
    "still rejects nonempty or linked output directories",
    async () => {
      for (const state of ["nonempty", "symlink"] as const) {
        const { root, output, started, deps } = await scanFixture();
        const actual =
          state === "symlink" ? join(root, "actual-results") : output;
        await mkdir(actual);
        await chmod(actual, 0o755);
        if (state === "symlink") await symlink(actual, output, "dir");
        else await writeFile(join(output, "previous.txt"), "previous scan\n");
        const { runCli } = createCliTest(main, { stderr: true });

        expect(await runCli(["scan", ".", "--output-dir", output], deps)).toBe(
          2,
        );
        expect((await stat(actual)).mode & 0o777).toBe(0o755);
        expect(started).not.toHaveBeenCalled();
      }
    },
  );
});
