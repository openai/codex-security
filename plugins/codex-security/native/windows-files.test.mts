import assert from "node:assert/strict";
import { test } from "node:test";
import { win32 } from "node:path";
import { type WindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

const opened = new Error("Captured native open");

for (const [input, expected] of [
  ["\\\\?\\C:\\\\..\\file", "\\\\?\\C:\\file"],
  ["\\\\?\\UNC\\server\\share\\\\..\\file", "\\\\?\\UNC\\server\\share\\file"],
  [
    "\\\\?\\UNC\\server\\share\\..\\other\\file",
    "\\\\?\\UNC\\server\\share\\other\\file",
  ],
  ["\\\\?\\UNC\\server\\share\\child\\..\\..\\", "\\\\?\\UNC\\server\\share\\"],
  ["\\\\?\\C:\\..\\file-\ud800", "\\\\?\\C:\\file-\ud800"],
  ["\\\\?\\C:\\child\\.\\..\\", "\\\\?\\C:\\"],
  ["\\\\?\\C:\\trailing.\\", "\\\\?\\C:\\trailing."],
  ["\\\\?\\UNC\\server\\share\\space \\", "\\\\?\\UNC\\server\\share\\space "],
] as const) {
  test(`verbatim realpath preserves its root: ${JSON.stringify(input)}`, () => {
    const native = {
      windowsAbsolutePath(path: Buffer) {
        return { error: 0, value: path };
      },
      openWindowsFile(path: Buffer) {
        assert.equal(pathText(path), expected);
        throw opened;
      },
    } as unknown as WindowsBinding;
    assert.throws(
      () => windowsFileSystem(native).realpath(widePath(input)),
      (error) => error === opened,
    );
  });
}

for (const [input, absolute] of [
  ["C:.\\..\\sentinel", "C:\\parent\\sentinel"],
  ["\\\\server\\share\\..\\file\\", "\\\\server\\share\\file\\"],
  ["C:/", "C:\\"],
  ["C:\\file\\", "C:\\file\\"],
] as const) {
  test(`ordinary realpath uses native absolute resolution: ${JSON.stringify(input)}`, () => {
    const native = {
      windowsAbsolutePath(path: Buffer) {
        return {
          error: 0,
          value: widePath(win32.resolve("C:\\parent\\child", pathText(path))),
        };
      },
      openWindowsFile(path: Buffer) {
        const root = win32.parse(absolute).root;
        const trimmed = root + absolute.slice(root.length).replace(/\\+$/u, "");
        assert.equal(pathText(path), win32.toNamespacedPath(trimmed));
        throw opened;
      },
    } as unknown as WindowsBinding;
    assert.throws(
      () => windowsFileSystem(native).realpath(widePath(input)),
      (error) => error === opened,
    );
  });
}

for (const share of ["\\\\server\\share", "//server/share"]) {
  test(`realpath resolves the UNC share root from a directory on that share: ${share}`, () => {
    const native = {
      windowsAbsolutePath(path: Buffer) {
        return {
          error: 0,
          value: widePath(
            win32.resolve("\\\\server\\share\\nested", pathText(path)),
          ),
        };
      },
      openWindowsFile(path: Buffer) {
        assert.equal(pathText(path), "\\\\?\\UNC\\server\\share\\");
        throw opened;
      },
    } as unknown as WindowsBinding;
    assert.throws(
      () => windowsFileSystem(native).realpath(widePath(share)),
      (error) => error === opened,
    );
  });
}

test("non-strict realpath resolves a whitespace-only relative path from cwd", () => {
  const native = {
    windowsAbsolutePath(path: Buffer) {
      return pathText(path).trim() === ""
        ? { error: 123, value: Buffer.alloc(0) }
        : {
            error: 0,
            value: widePath(
              win32.resolve("C:\\work", pathText(path).replace(/ +$/u, "")),
            ),
          };
    },
    windowsReadLink: () => ({ error: 2, value: Buffer.alloc(0) }),
    openWindowsFile(path: Buffer) {
      return pathText(path) === "\\\\?\\C:\\work"
        ? {
            error: 0,
            handle: { finalPath: () => ({ error: 0, path }), close: () => 0 },
          }
        : { error: 2, handle: null };
    },
  } as unknown as WindowsBinding;
  assert.equal(
    pathText(windowsFileSystem(native).realpath(widePath("  "), false)),
    "C:\\work",
  );
});

for (const target of ["missing.", "missing "]) {
  for (const siblingExists of [true, false]) {
    test(`dangling link target ${JSON.stringify(target)} with ordinary sibling present=${siblingExists}`, () => {
      const native = {
        windowsAbsolutePath(path: Buffer) {
          const text = pathText(path);
          return {
            error: 0,
            value: widePath(
              text.startsWith("\\\\?\\") ? text : text.replace(/[. ]+$/u, ""),
            ),
          };
        },
        windowsReadLink(path: Buffer) {
          return pathText(path) === "\\\\?\\C:\\links\\link"
            ? { error: 0, value: widePath(target) }
            : { error: 4390, value: Buffer.alloc(0) };
        },
        openWindowsFile(path: Buffer) {
          if (
            ![
              "\\\\?\\C:\\links",
              ...(siblingExists ? ["\\\\?\\C:\\links\\missing"] : []),
            ].includes(pathText(path))
          )
            return { error: 2, handle: null };
          return {
            error: 0,
            handle: {
              finalPath: () => ({ error: 0, path }),
              close: () => 0,
            },
          };
        },
      } as unknown as WindowsBinding;
      assert.equal(
        pathText(
          windowsFileSystem(native).realpath(
            widePath("C:\\links\\link"),
            false,
          ),
        ),
        `\\\\?\\C:\\links\\${target}`,
      );
    });
  }
}

for (const parent of ["C:\\dir", "\\\\server\\share\\dir"]) {
  for (const namespaced of [false, true]) {
    const input = `${namespaced ? win32.toNamespacedPath(parent) : parent}\\a:stream`;
    test(`non-strict resolution preserves the stream parent: ${JSON.stringify(input)}`, () => {
      const native = {
        windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
        windowsReadLink: () => ({ error: 2, value: Buffer.alloc(0) }),
        openWindowsFile(path: Buffer) {
          return pathText(path) === win32.toNamespacedPath(parent)
            ? {
                error: 0,
                handle: {
                  finalPath: () => ({ error: 0, path }),
                  close: () => 0,
                },
              }
            : { error: 2, handle: null };
        },
      } as unknown as WindowsBinding;
      assert.equal(
        pathText(windowsFileSystem(native).realpath(widePath(input), false)),
        input,
      );
    });
  }
}

test("non-strict resolution handles deeply nested missing paths", () => {
  const root = "\\\\?\\C:\\";
  const input = root + "a\\".repeat(8_000) + "missing";
  const native = {
    windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
    windowsReadLink: () => ({ error: 3, value: Buffer.alloc(0) }),
    openWindowsFile(path: Buffer) {
      return pathText(path) === root
        ? {
            error: 0,
            handle: { finalPath: () => ({ error: 0, path }), close: () => 0 },
          }
        : { error: 3, handle: null };
    },
  } as unknown as WindowsBinding;
  assert.equal(
    pathText(windowsFileSystem(native).realpath(widePath(input), false)),
    input,
  );
});
