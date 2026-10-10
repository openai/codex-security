import { constants, zstdCompressSync, zstdDecompressSync } from "node:zlib";
import * as module from "zstd-codec/lib/module.js";
import { expect, spyOn, test } from "bun:test";
import { decodeZstd } from "../src/zstd.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const encode = (bytes: Uint8Array, contentSize = true) =>
  zstdCompressSync(bytes, {
    params: {
      [constants.ZSTD_c_checksumFlag]: 1,
      [constants.ZSTD_c_contentSizeFlag]: Number(contentSize),
    },
  });

async function* chunks(bytes: Uint8Array, size = 64 * 1024) {
  for (let offset = 0; offset < bytes.length; offset += size)
    yield bytes.subarray(offset, offset + size);
}

async function decoded(bytes: Uint8Array, size?: number) {
  const result = [];
  for await (const part of decodeZstd(chunks(bytes, size))) result.push(part);
  return Buffer.concat(result);
}

test.each([1, 2, 7, 64 * 1024])(
  "Zstandard preserves multi-block content with %i-byte input chunks",
  async (size) => {
    const plain = Buffer.from("Synthetic session line: café.\n".repeat(30_000));
    for (const contentSize of [false, true])
      expect(await decoded(encode(plain, contentSize), size)).toEqual(plain);
  },
);

test("Zstandard decodes concatenated frames and skippable frames", async () => {
  const skip = (contents: Buffer) => {
    const header = Buffer.alloc(8);
    header.writeUInt32LE(0x184d2a50);
    header.writeUInt32LE(contents.length, 4);
    return Buffer.concat([header, contents]);
  };
  const source = Buffer.concat([
    skip(Buffer.from("skipped")),
    encode(Buffer.from("first\n")),
    skip(Buffer.alloc(0)),
    encode(Buffer.from("second\n")),
  ]);
  for (const size of [1, 11, source.length])
    expect((await decoded(source, size)).toString()).toBe("first\nsecond\n");
});

test("Zstandard accepts raw and RLE blocks with every optional header width", async () => {
  for (const blockType of [0, 1]) {
    for (const contentFlag of [0, 1, 2, 3]) {
      for (const dictionaryFlag of [0, 1, 2, 3]) {
        const plain = Buffer.alloc(contentFlag === 1 ? 300 : 5, 0x61);
        const dictionarySize = [0, 1, 2, 4][dictionaryFlag]!;
        const contentSize = contentFlag === 0 ? 1 : 2 ** contentFlag;
        const header = Buffer.alloc(5 + dictionarySize + contentSize);
        header.writeUInt32LE(0xfd2fb528);
        header[4] = (contentFlag << 6) | 0x20 | dictionaryFlag;
        const value = plain.length - (contentFlag === 1 ? 256 : 0);
        if (contentSize === 8)
          header.writeBigUInt64LE(BigInt(value), 5 + dictionarySize);
        else header.writeUIntLE(value, 5 + dictionarySize, contentSize);
        const block = Buffer.alloc(3);
        block.writeUIntLE((plain.length << 3) | (blockType << 1) | 1, 0, 3);
        const frame = Buffer.concat([
          header,
          block,
          blockType === 1 ? plain.subarray(0, 1) : plain,
        ]);
        expect(zstdDecompressSync(frame)).toEqual(plain);
        expect(await decoded(frame, 1)).toEqual(plain);
      }
    }
  }
  const empty = Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0]);
  expect(zstdDecompressSync(empty)).toEqual(Buffer.alloc(0));
  expect(await decoded(empty, 1)).toEqual(Buffer.alloc(0));
});

test("Zstandard rejects truncated headers, data, checksums and skippable frames", async () => {
  const frame = encode(Buffer.from("Synthetic session payload.\n".repeat(500)));
  for (const length of [
    0,
    1,
    4,
    5,
    8,
    frame.length - 5,
    frame.length - 4,
    frame.length - 1,
  ])
    await expect(decoded(frame.subarray(0, length), 3)).rejects.toThrow();
  const skip = Buffer.from([0x50, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 1]);
  await expect(decoded(skip, 1)).rejects.toThrow("Incomplete Zstandard frame");
  await expect(
    decoded(Buffer.concat([frame, Buffer.from([0x28])])),
  ).rejects.toThrow("Incomplete Zstandard frame");
});

test("Zstandard rejects checksum mismatches and invalid compressed data", async () => {
  const frame = Buffer.from(encode(Buffer.from("Synthetic session payload.")));
  frame[frame.length - 1] = frame[frame.length - 1]! ^ 1;
  await expect(decoded(frame, 5)).rejects.toThrow(
    "Invalid Zstandard compressed data or checksum",
  );
  await expect(decoded(Buffer.from("not a Zstandard frame"))).rejects.toThrow(
    "Invalid Zstandard frame magic",
  );
});

const cleanupTest =
  "Zstandard prefix reads release codec and input before later blocks";
test(cleanupTest, async () => {
  if (runTestInSubprocess("tests-ts/zstd.test.ts", cleanupTest)) return;
  const originalRun = module.run;
  let deleted = 0;
  let finished = 0;
  let compressedBytes = 0;
  const hook = spyOn(module, "run").mockImplementation(
    (ready: (value: unknown) => void) => {
      originalRun((binding: any) => {
        const Original = binding.ZstdDecompressStreamBinding;
        binding.ZstdDecompressStreamBinding = class {
          inner = new Original();
          begin() {
            return this.inner.begin();
          }
          transform(input: Uint8Array, output: (chunk: Uint8Array) => void) {
            compressedBytes += input.length;
            return this.inner.transform(input, output);
          }
          end(output: (chunk: Uint8Array) => void) {
            finished++;
            return this.inner.end(output);
          }
          delete() {
            deleted++;
            this.inner.delete();
          }
        };
        ready(binding);
      });
    },
  );
  try {
    const frame = encode(Buffer.alloc(8 * 1024 * 1024, 0x61));
    let closed = false;
    async function* input() {
      try {
        yield frame;
        throw new Error("A prefix read must not request the next input chunk.");
      } finally {
        closed = true;
      }
    }
    for await (const part of decodeZstd(input())) {
      expect(part[0]).toBe(0x61);
      expect(part.length).toBeLessThanOrEqual(128 * 1024);
      break;
    }
    expect(compressedBytes).toBeLessThan(frame.length);
    expect(closed).toBe(true);
    expect(deleted).toBe(1);
    expect(finished).toBe(0);

    const corrupt = Buffer.from(frame);
    corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
    await expect(decoded(corrupt)).rejects.toThrow();
    expect(deleted).toBe(2);
    expect((await decoded(encode(Buffer.from("complete")))).toString()).toBe(
      "complete",
    );
    expect(deleted).toBe(3);
    expect(finished).toBe(1);

    async function* unreadable() {
      yield frame.subarray(0, 10);
      throw new Error("Synthetic input read failure.");
    }
    await expect(
      (async () => {
        for await (const _part of decodeZstd(unreadable())) {
        }
      })(),
    ).rejects.toThrow("Synthetic input read failure");
    expect(deleted).toBe(4);
  } finally {
    hook.mockRestore();
  }
});
