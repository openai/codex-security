import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { mkdir, rm, symlink } from "node:fs/promises";
import { join, toNamespacedPath, win32 } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { importModule, importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { registerWorkerExecutableFirstLaunchTests } from "./windows_executable_first_launch_cases.ts";
import { registerWorkerExecutableCancellationTests } from "./windows_executable_cancellation_cases.ts";

const packagedHelper = new URL(
  "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
  import.meta.url,
);
const { resolvedPathText, isMissingPathError } = (await importSource(
  "src/helpers/helper-files.ts",
  {
    define: {
      "import.meta.url": JSON.stringify(packagedHelper.href),
    },
  },
)) as typeof import("../src/helpers/helper-files.ts");
const { expandHome } = (await importSource(
  "src/helpers/resolve-security-md.ts",
)) as typeof import("../src/helpers/resolve-security-md.ts");
const { windowsFileSystem } = (await importModule({
  entryPoints: ["../native/windows-files.mts"],
})) as typeof import("../../native/windows-files.mjs");
const { sqliteFilename } = (await importSource(
  "src/windows-path.ts",
)) as typeof import("../src/windows-path.ts");
const directories = createTemporaryDirectories(true);
after(() => directories.cleanup());

const { replaceArtifactText } = (await importSource(
  join(import.meta.dirname, "../src/artifact-io.ts"),
)) as typeof import("../src/artifact-io.js");

const { writeJsonAtomic } = (await importSource(
  "src/deep-scan/artifacts.ts",
)) as typeof import("../src/deep-scan/artifacts.js");

test("a failed Deep Scan JSON rename preserves the diagnostic and cleans its staging file", async (t) => {
  const directory = await directories.create("deep-scan-json-");
  const destination = join(directory, "heartbeat.json");
  await fs.writeFile(destination, "old");
  const failure = Object.assign(new Error("synthetic rename failure"), {
    code: "EIO",
  });
  const rename = t.mock.method(fs, "rename", async () => {
    throw failure;
  });
  await assert.rejects(
    writeJsonAtomic(destination, { beat: 2 }),
    (error) => error === failure,
  );
  assert.equal(rename.mock.callCount(), 1);
  assert.equal(await fs.readFile(destination, "utf8"), "old");
  assert.deepEqual(await fs.readdir(directory), ["heartbeat.json"]);
});

test(
  "Windows publishes the Deep Scan heartbeat after a reader releases the old file",
  { skip: process.platform !== "win32" },
  async (t) => {
    const directory = join(
      await directories.create("held-artifact-"),
      "nested",
    );
    const destination = join(directory, "heartbeat.json");
    await writeJsonAtomic(destination, { beat: 1 });
    const reader = await fs.open(destination, "r");
    t.after(() => reader.close());
    const rename = fs.rename.bind(fs);
    let conflicts = 0;
    t.mock.method(
      fs,
      "rename",
      async (...args: Parameters<typeof fs.rename>) => {
        try {
          return await rename(...args);
        } catch (error) {
          if (args[1] === destination && conflicts === 0) {
            conflicts++;
            assert.deepEqual(
              JSON.parse(await fs.readFile(destination, "utf8")),
              { beat: 1 },
            );
            await reader.close();
          }
          throw error;
        }
      },
    );
    await writeJsonAtomic(destination, { beat: 2 });
    assert.equal(conflicts, 1);
    assert.equal(await fs.readFile(destination, "utf8"), '{\n  "beat": 2\n}\n');
    assert.deepEqual(await fs.readdir(directory), ["heartbeat.json"]);
  },
);

test(
  "Windows retains the old artifact and cleans the temporary file when a reader stays open",
  { skip: process.platform !== "win32" },
  async () => {
    const directory = await directories.create("locked-artifact-");
    const destination = join(directory, "result.jsonl");
    await fs.writeFile(destination, "old");
    const reader = await fs.open(destination, "r");
    try {
      await assert.rejects(
        replaceArtifactText(destination, "new"),
        (error: NodeJS.ErrnoException) =>
          ["EPERM", "EBUSY", "EACCES"].includes(error.code ?? ""),
      );
      assert.equal(await fs.readFile(destination, "utf8"), "old");
      assert.deepEqual(await fs.readdir(directory), ["result.jsonl"]);
    } finally {
      await reader.close();
    }
  },
);

test(
  "preserves ordinary Windows SQLite spellings for short paths and verbatim-sensitive components",
  { skip: process.platform !== "win32" },
  () => {
    const root = "C:/synthetic";
    const long = join(root, "a".repeat(128), "b".repeat(128));
    for (const filename of [
      join(root, "workbench.sqlite3"),
      join(long, "state.", "workbench.sqlite3"),
      join(long, "state ", "workbench.sqlite3"),
      `\\\\.\\C:\\..\\synthetic\\${long.slice(3)}`,
      `\\\\?\\C:\\example\\..\\synthetic\\${long.slice(3)}`,
      `\\\\first.invalid\\..\\second.invalid\\share\\${long.slice(3)}`,
      `\\\\first.invalid\\\\share\\${long.slice(3)}`,
      `\\\\first.invalid\\share.\\${long.slice(3)}`,
      "/".repeat(3) +
        "synthetic/share/" +
        "a".repeat(128) +
        "/" +
        "b".repeat(128),
      "\\".repeat(3) +
        "synthetic\\share\\" +
        "a".repeat(128) +
        "\\" +
        "b".repeat(128),
    ]) {
      assert.equal(sqliteFilename(filename), filename);
    }
    const share = `\\\\first.invalid\\share`;
    assert.equal(
      sqliteFilename(`${share}\\\\${long.slice(3)}`),
      toNamespacedPath(`${share}\\${long.slice(3)}`),
    );
  },
);

test(
  "the severity reader rejects NUL even before a parent path component",
  { skip: process.platform !== "win32" },
  async () => {
    const state = await directories.create("invalid-sqlite-name-");
    const helper = fileURLToPath(packagedHelper);
    execFileSync(process.execPath, [helper, "database-info"], {
      input: JSON.stringify(state),
      windowsHide: true,
    });
    const invalid = `${state}\\${"x".repeat(Math.max(1, 260 - state.length))}\0\\..`;
    assert.ok(invalid.length >= 260);
    const request = JSON.stringify({
      stateDirectory: invalid,
      payload: { scanId: "synthetic" },
    });
    assert.throws(() =>
      execFileSync(process.execPath, [helper, "read-severity-classification"], {
        input: request,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      }),
    );
  },
);

test(
  "opens and reopens a workbench database beyond Windows MAX_PATH",
  { skip: process.platform !== "win32" },
  async (t) => {
    const root = await directories.create("codex-long-workbench-");
    const filename = "workbench.sqlite3";
    const padding = Math.max(0, 260 - join(root, filename).length);
    const state = join(root, "x".repeat(padding));
    const expected = join(state, filename);
    if (Buffer.byteLength(toNamespacedPath(expected)) > 1032) {
      t.skip(
        "Temporary root exceeds the SQLite filename limit for this fixture",
      );
      return;
    }
    for (const suffix of ["", "\\", "/", "\\\\", "/\\"]) {
      const output = execFileSync(
        process.execPath,
        [fileURLToPath(packagedHelper), "database-info"],
        {
          encoding: "utf8",
          input: JSON.stringify(state + suffix),
          windowsHide: true,
        },
      );
      assert.equal(JSON.parse(output).databasePath, expected);
    }
    const database = new DatabaseSync(toNamespacedPath(expected), {
      readOnly: true,
    });
    try {
      assert.equal(
        database.prepare("PRAGMA journal_mode").get()?.journal_mode,
        "wal",
      );
    } finally {
      database.close();
    }
  },
);

test(
  "POSIX home expansion removes boundary separators while retaining literal suffixes",
  { skip: process.platform === "win32" },
  () => {
    for (const [home, path, expected] of [
      ["/", "~", "/"],
      ["/", "~/.codex", "/.codex"],
      ["//", "~/.codex", "/.codex"],
      ["", "~", "/"],
      ["", "~/child", "/child"],
      [
        "/synthetic/home///",
        "~/alias/../child",
        "/synthetic/home/alias/../child",
      ],
      ["/synthetic/home/", "//literal/path", "//literal/path"],
    ] as const)
      assert.equal(expandHome(path, home), expected);
  },
);

test("optional probes recognize unavailable Windows paths while retaining access errors", () => {
  for (const [winerror, absent] of [
    [21, true],
    [123, true],
    [5, false],
    [32, false],
  ] as const) {
    const native = {
      windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
      openWindowsFile: () => ({ error: winerror, handle: null }),
    } as unknown as Parameters<typeof windowsFileSystem>[0];
    assert.throws(
      () =>
        windowsFileSystem(native).stat(Buffer.from("R:\\marker", "utf16le")),
      (error: unknown) => {
        assert.equal((error as { winerror: number }).winerror, winerror);
        assert.equal(isMissingPathError(error), absent);
        return true;
      },
    );
  }
});

test("resolved text preserves ordinary paths, aliases, and missing suffixes", async () => {
  const root = await directories.create("helper-path-");
  const target = join(root, "target");
  const alias = join(root, "alias");
  await mkdir(target);
  await symlink(
    target,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  assert.equal(resolvedPathText(target), target);
  assert.equal(resolvedPathText(alias), target);
  assert.equal(
    resolvedPathText(join(alias, "missing"), false),
    join(target, "missing"),
  );
  assert.throws(
    () => resolvedPathText(join(alias, "missing")),
    /ENOENT|filesystem error/u,
  );
  if (process.platform !== "win32")
    assert.throws(
      () => resolvedPathText(`${root}/missing/../target`, false),
      /ENOENT/u,
    );
});

test(
  "Windows resolution keeps an explicitly requested namespace",
  { skip: process.platform !== "win32" },
  async () => {
    const root = await directories.create("helper-namespace-");
    const namespaced = win32.toNamespacedPath(root);
    assert.equal(resolvedPathText(namespaced), namespaced);
    assert.equal(
      resolvedPathText(join(namespaced, "missing"), false),
      join(namespaced, "missing"),
    );
  },
);

test(
  "Windows display spelling still identifies a raw target through a junction",
  { skip: process.platform !== "win32" },
  async () => {
    const root = await directories.create("helper-raw-path-");
    const ordinary = join(root, "target");
    const raw = `${win32.toNamespacedPath(ordinary)}. `;
    const alias = join(root, "alias");
    await mkdir(ordinary);
    await mkdir(raw);
    try {
      await symlink(raw, alias, "junction");
      const display = resolvedPathText(alias);
      // An ordinary alias must never select the neighboring trimmed directory.
      assert.notEqual(display, ordinary);
      assert.equal(resolvedPathText(win32.toNamespacedPath(display)), raw);
    } finally {
      await rm(alias, { recursive: true, force: true });
      await rm(raw, { recursive: true, force: true });
    }
  },
);

// The Windows CI job runs this entry point directly and retains native TAP results.
registerWorkerExecutableFirstLaunchTests();
registerWorkerExecutableCancellationTests();
