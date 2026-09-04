import assert from "node:assert/strict";
import { test } from "node:test";
import { win32 } from "node:path";
import { type WindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

const opened = new Error("Captured native open");

for (const [input, expected] of [
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
    let absoluteCalls = 0;
    const native = {
      windowsAbsolutePath(path: Buffer) {
        if (absoluteCalls++ === 0) {
          assert.equal(pathText(path), input);
          return { error: 0, value: widePath(absolute) };
        }
        return { error: 0, value: path };
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
