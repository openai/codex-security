import assert from "node:assert/strict";
import { mkdir, rm, symlink } from "node:fs/promises";
import { join, win32 } from "node:path";
import { after, test } from "node:test";
import { importModule, importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { resolvedPathText, isMissingPathError } = (await importSource(
  "src/helpers/helper-files.ts",
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
)) as typeof import("../src/helpers/helper-files.ts");
const { expandHome } = (await importSource(
  "src/helpers/resolve-security-md.ts",
)) as typeof import("../src/helpers/resolve-security-md.ts");
const { windowsFileSystem } = (await importModule({
  entryPoints: ["../native/windows-files.mts"],
})) as typeof import("../../native/windows-files.mjs");
const directories = createTemporaryDirectories(true);
after(() => directories.cleanup());

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
