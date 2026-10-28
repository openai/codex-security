import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { test } from "node:test";
import type { WindowsBinding } from "../../native/windows-binding.mjs";
import { importSource } from "./import-module.ts";

const fixtureName = "__codexWindowsChunkFixture";
const sourceOptions = {
  define: { "process.platform": JSON.stringify("win32") },
  plugins: [
    {
      name: "synthetic-windows-binding",
      setup(builder: import("esbuild").PluginBuild) {
        builder.onLoad({ filter: /\/src\/native\.ts$/ }, () => ({
          loader: "ts",
          contents: `export const windowsBinding = () => globalThis.${fixtureName};
            export const unixBinding = () => { throw new Error("unexpected POSIX binding"); };`,
        }));
      },
    },
  ],
};
const { readChunks } = await importSource(
  "src/helpers/helper-files.ts",
  sourceOptions,
);
const { createSourceSampler } = await importSource(
  "src/helpers/source-preview.ts",
  sourceOptions,
);
const rawPath = "\\\\?\\C:\\fixture-\ud800.txt";

function fixture(chunks: Array<Buffer | number | Error>, openError = 0) {
  const state = { reads: 0, opens: 0, closes: 0 };
  const native = {
    windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
    openWindowsFile(path: Buffer) {
      state.opens++;
      assert.deepEqual(path, Buffer.from(rawPath, "utf16le"));
      return {
        error: openError,
        handle: {
          read(buffer: Buffer, offset: number, length: number) {
            state.reads++;
            assert(chunks.length, "read past the supplied file contents");
            const next = chunks.shift()!;
            if (next instanceof Error) throw next;
            if (typeof next === "number") return { error: next, value: 0 };
            assert(next.length <= length);
            next.copy(buffer, offset);
            return { error: 0, value: next.length };
          },
          close() {
            state.closes++;
            return 0;
          },
        },
      };
    },
  } as unknown as WindowsBinding;
  (globalThis as Record<string, unknown>)[fixtureName] = native;
  return state;
}

test("Windows binary sampling stops at the first NUL without reading the rest", () => {
  const state = fixture([
    Buffer.from([0, 65, 66, 67]),
    new Error("the excluded binary must not be read further"),
  ]);
  const sampler = createSourceSampler();
  for (const chunk of readChunks(rawPath)) if (!sampler.consume(chunk)) break;
  assert.equal(sampler.finish()[1], true);
  assert.deepEqual(state, { reads: 1, opens: 1, closes: 1 });
});

for (const fail of [false, true]) {
  test(`Windows chunk reads close after the consumer ${fail ? "throws" : "stops"}`, () => {
    const state = fixture([
      Buffer.from("selected text"),
      new Error("the stopped consumer must not read further"),
    ]);
    const failure = new Error("synthetic consumer failure");
    const consume = () => {
      for (const chunk of readChunks(rawPath)) {
        assert.equal(chunk.toString(), "selected text");
        if (fail) throw failure;
        break;
      }
    };
    if (fail) assert.throws(consume, failure);
    else consume();
    assert.deepEqual(state, { reads: 1, opens: 1, closes: 1 });
  });
}

test("Windows chunk reads preserve native read errors and missing-file labels", () => {
  const state = fixture([5]);
  assert.throws(() => [...readChunks(rawPath)], { winerror: 5 });
  assert.deepEqual(state, { reads: 1, opens: 1, closes: 1 });
  const missing = fixture([], 2);
  assert.throws(() => [...readChunks(rawPath, "Source")], {
    message: `Source missing: ${rawPath}`,
  });
  assert.deepEqual(missing, { reads: 0, opens: 1, closes: 0 });
});

test("Windows text reads preserve raw paths and every short-read byte", () => {
  const expected = Buffer.from("selected text\n\u03b2\r\n");
  const state = fixture([
    expected.subarray(0, 3),
    expected.subarray(3, 14),
    expected.subarray(14),
    Buffer.alloc(0),
  ]);
  assert.deepEqual(Buffer.concat([...readChunks(rawPath)]), expected);
  assert.deepEqual(state, { reads: 4, opens: 1, closes: 1 });
});

test("Windows text chunk streams respect a blocked sink and deliver the full file", async () => {
  const data = Array.from({ length: 64 }, (_, index) =>
    Buffer.alloc(64 * 1024, 65 + (index % 26)),
  );
  const expected = Buffer.concat(data);
  const state = fixture([...data, Buffer.alloc(0)]);
  const received: Buffer[] = [];
  let release!: () => void;
  let started!: () => void;
  const firstWrite = new Promise<void>((resolve) => {
    started = resolve;
  });
  const sink = new Writable({
    highWaterMark: 1,
    write(chunk: Buffer, _encoding, callback) {
      received.push(Buffer.from(chunk));
      if (received.length === 1) {
        release = callback;
        started();
      } else callback();
    },
  });
  const completion = pipeline(
    Readable.from(readChunks(rawPath), { objectMode: false }),
    sink,
  );
  await firstWrite;
  await new Promise<void>((resolve) => setImmediate(resolve));
  try {
    assert(state.reads < data.length, "the blocked sink read the entire file");
    assert.equal(state.closes, 0);
  } finally {
    release();
  }
  await completion;
  assert.deepEqual(Buffer.concat(received), expected);
  assert.deepEqual(state, { reads: data.length + 1, opens: 1, closes: 1 });
});

test("Windows chunk streams close the native handle when the sink fails", async () => {
  const state = fixture([
    ...Array.from({ length: 64 }, () => Buffer.alloc(64 * 1024, 65)),
    Buffer.alloc(0),
  ]);
  const failure = new Error("synthetic sink failure");
  const sink = new Writable({
    write(_chunk, _encoding, callback) {
      callback(failure);
    },
  });
  await assert.rejects(
    pipeline(Readable.from(readChunks(rawPath), { objectMode: false }), sink),
    failure,
  );
  assert(state.reads < 64, "the failed sink read the entire file");
  assert.equal(state.closes, 1);
});
