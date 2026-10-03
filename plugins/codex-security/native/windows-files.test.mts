import assert from "node:assert/strict";
import { test } from "node:test";
import { win32 } from "node:path";
import { type WindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";
import { windowsFlags as flags } from "./windows-flags.mjs";

for (const [input, absolute] of [
  ["C:.\\..\\sentinel", "C:\\parent\\sentinel"],
  ["\\\\server\\share", "\\\\server\\share\\"],
  ["\\\\?\\C:\\file-\ud800", "\\\\?\\C:\\file-\ud800"],
  ["\\\\?\\C:\\trailing.", "\\\\?\\C:\\trailing."],
] as const) {
  test(`realpath uses native absolute and final paths: ${JSON.stringify(input)}`, () => {
    const final = widePath("\\\\?\\C:\\canonical-\ud800");
    let closes = 0;
    let resolutions = 0;
    const native = {
      windowsAbsolutePath(path: Buffer) {
        if (resolutions++ === 0) assert.deepEqual(path, widePath(input));
        return { error: 0, value: widePath(absolute) };
      },
      openWindowsFile(path: Buffer) {
        assert.equal(pathText(path), win32.toNamespacedPath(absolute));
        return {
          error: 0,
          handle: {
            finalPath: () => ({ error: 0, path: final }),
            close: () => {
              closes++;
              return 0;
            },
          },
        };
      },
    } as unknown as WindowsBinding;
    assert.deepEqual(
      windowsFileSystem(native).realpath(widePath(input)),
      final,
    );
    assert.equal(closes, 1);
  });
}

for (const [parent, tail] of [
  ["C:\\alias", "missing-\udfff\\child"],
  ["C:\\alias", "a:stream"],
  ["\\\\server\\share\\alias", "missing"],
  ["\\\\?\\C:\\trailing.", "new.json"],
  ["\\\\?\\C:\\space ", "new.json"],
  ["\\\\?\\C:\\alias", "a\\".repeat(8_000) + "missing"],
] as const) {
  test(`non-strict realpath resolves the existing ancestor: ${JSON.stringify(parent)} (${tail.length} chars)`, () => {
    const canonical = "\\\\?\\C:\\destination";
    const native = {
      windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
      openWindowsFile(path: Buffer) {
        return pathText(path) === win32.toNamespacedPath(parent)
          ? {
              error: 0,
              handle: {
                finalPath: () => ({ error: 0, path: widePath(canonical) }),
                close: () => 0,
              },
            }
          : { error: 3, handle: null };
      },
    } as unknown as WindowsBinding;
    assert.equal(
      pathText(
        windowsFileSystem(native).realpath(
          widePath(`${parent}\\${tail}`),
          false,
        ),
      ),
      `${canonical}\\${tail}`,
    );
    assert.throws(
      () => windowsFileSystem(native).realpath(widePath(`${parent}\\${tail}`)),
      { code: "ENOENT" },
    );
  });
}

for (const suffix of ["", "\\child"]) {
  test(`non-strict realpath rejects dangling reparse points${suffix}`, () => {
    let closes = 0;
    const native = {
      windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
      openWindowsFile(
        path: Buffer,
        _access: number,
        _share: number,
        _disposition: number,
        options: number,
      ) {
        return pathText(path) === "\\\\?\\C:\\link" &&
          options & flags.FILE_FLAG_OPEN_REPARSE_POINT
          ? {
              error: 0,
              handle: {
                close: () => {
                  closes++;
                  return 0;
                },
              },
            }
          : { error: 3, handle: null };
      },
    } as unknown as WindowsBinding;
    assert.throws(
      () =>
        windowsFileSystem(native).realpath(
          widePath(`C:\\link${suffix}`),
          false,
        ),
      { code: "ENOENT" },
    );
    assert.equal(closes, 1);
  });
}

for (const error of [5, 32, 1921]) {
  test(`non-strict realpath preserves native error ${error}`, () => {
    const native = {
      windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
      openWindowsFile: () => ({ error, handle: null }),
    } as unknown as WindowsBinding;
    assert.throws(
      () => windowsFileSystem(native).realpath(widePath("C:\\file"), false),
      { winerror: error },
    );
  });
}

for (const bounded of [true, false]) {
  test(`${bounded ? "bounded" : "complete"} reads continue after short reads and close at EOF`, () => {
    const chunks = [Buffer.from("ab"), Buffer.from("c"), Buffer.alloc(0)];
    let closes = 0;
    const native = {
      windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
      openWindowsFile(
        path: Buffer,
        access: number,
        share: number,
        disposition: number,
        options: number,
      ) {
        assert.equal(pathText(path), "\\\\?\\C:\\file-\ud800");
        assert.equal(access, flags.GENERIC_READ);
        assert.equal(
          share,
          flags.FILE_SHARE_READ |
            flags.FILE_SHARE_WRITE |
            flags.FILE_SHARE_DELETE,
        );
        assert.equal(disposition, flags.OPEN_EXISTING);
        assert.equal(options & flags.FILE_FLAG_BACKUP_SEMANTICS, 0);
        return {
          error: 0,
          handle: {
            read(buffer: Buffer, offset: number, length: number) {
              const chunk = chunks.shift()!;
              assert(chunk.length <= length);
              chunk.copy(buffer, offset);
              return { error: 0, value: chunk.length };
            },
            close: () => {
              closes++;
              return 0;
            },
          },
        };
      },
    } as unknown as WindowsBinding;
    const files = windowsFileSystem(native);
    const path = widePath("C:\\file-\ud800");
    if (bounded) {
      const buffer = Buffer.alloc(8);
      assert.equal(files.readInto(path, buffer), 3);
      assert.equal(buffer.subarray(0, 3).toString(), "abc");
    } else assert.equal(files.readFile(path).toString(), "abc");
    assert.equal(chunks.length, 0);
    assert.equal(closes, 1);
  });
}

test("exclusive writes handle short writes without consuming input on open failure", () => {
  const written: Buffer[] = [];
  let opens = 0;
  let closes = 0;
  let iterations = 0;
  const native = {
    windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
    openWindowsFile(
      path: Buffer,
      access: number,
      share: number,
      disposition: number,
    ) {
      assert.equal(pathText(path), "\\\\?\\C:\\output-\ud800");
      assert.equal(access, flags.GENERIC_WRITE);
      assert.equal(
        share,
        flags.FILE_SHARE_READ |
          flags.FILE_SHARE_WRITE |
          flags.FILE_SHARE_DELETE,
      );
      assert.equal(disposition, flags.CREATE_NEW);
      if (opens++) return { error: 80, handle: null };
      return {
        error: 0,
        handle: {
          write(buffer: Buffer, offset: number, length: number) {
            const count = Math.min(length, 2);
            written.push(buffer.subarray(offset, offset + count));
            return { error: 0, value: count };
          },
          close: () => {
            closes++;
            return 0;
          },
        },
      };
    },
  } as unknown as WindowsBinding;
  const data = {
    *[Symbol.iterator]() {
      iterations++;
      yield Buffer.from("abc");
      yield Buffer.alloc(0);
      yield Buffer.from("def");
    },
  };
  const files = windowsFileSystem(native);
  const path = widePath("C:\\output-\ud800");
  files.writeFile(path, data, true);
  assert.equal(Buffer.concat(written).toString(), "abcdef");
  assert.throws(() => files.writeFile(path, data, true), { winerror: 80 });
  assert.equal(iterations, 1);
  assert.equal(closes, 1);
});

for (const closeError of [0, 5]) {
  test(`write input failures close the handle, preserving close error ${closeError}`, () => {
    const inputError = new Error("input failed");
    let closes = 0;
    const native = {
      windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
      openWindowsFile: () => ({
        error: 0,
        handle: {
          close: () => {
            closes++;
            return closeError;
          },
        },
      }),
    } as unknown as WindowsBinding;
    const data = {
      [Symbol.iterator](): Iterator<Buffer> {
        throw inputError;
      },
    };
    assert.throws(
      () => windowsFileSystem(native).writeFile(widePath("C:\\output"), data),
      closeError ? { winerror: closeError } : (error) => error === inputError,
    );
    assert.equal(closes, 1);
  });
}
