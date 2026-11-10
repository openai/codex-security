import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import zlib from "node:zlib";
import { sessionLines } from "../src/session-lines.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("session-lines-");
afterEach(cleanup);

// Native level-3 frame, also usable on Node versions without a compressor.
const frame = Buffer.from(
  "KLUv/SA2sQEAeyJ0eXBlIjoic2Vzc2lvbl9tZXRhIiwicGF5bG9hZCI6eyJpZCI6ImNvbXByZXNzZWQifX0K",
  "base64",
);
const line = '{"type":"session_meta","payload":{"id":"compressed"}}';

async function withoutNativeZstd(run: () => Promise<void>): Promise<void> {
  const original = Object.getOwnPropertyDescriptor(
    zlib,
    "createZstdDecompress",
  );
  Object.defineProperty(zlib, "createZstdDecompress", {
    value: undefined,
    configurable: true,
  });
  try {
    await run();
  } finally {
    if (original) Object.defineProperty(zlib, "createZstdDecompress", original);
    else Reflect.deleteProperty(zlib, "createZstdDecompress");
  }
}

test("portable decoder reads concatenated native frames and rejects truncated input", async () => {
  const path = join(await temporaryDirectory(), "rollout.jsonl.zst");
  await withoutNativeZstd(async () => {
    await writeFile(path, Buffer.concat([frame, frame]));
    expect(await Array.fromAsync(sessionLines(path))).toEqual([line, line]);
    await writeFile(path, frame.subarray(0, frame.length - 3));
    await expect(Array.fromAsync(sessionLines(path))).rejects.toThrow();
  });
});

test("bundled Python reader helper works without native Zstandard", async () => {
  const path = join(await temporaryDirectory(), "rollout.jsonl.zst");
  await writeFile(path, frame);
  const output = execFileSync(
    "node",
    [
      "--input-type=module",
      "--eval",
      `import zlib from "node:zlib";
import { pathToFileURL } from "node:url";
Object.defineProperty(zlib, "createZstdDecompress", { value: undefined });
const [helper, rollout] = process.argv.slice(1);
process.argv = [process.execPath, helper, rollout];
await import(pathToFileURL(helper).href);`,
      join(PLUGIN_ROOT, "scripts", "read_codex_session.mjs"),
      path,
    ],
    { encoding: "utf8" },
  );
  expect(output).toBe(`${line}\n`);
});

test.skipIf(typeof zlib.zstdCompressSync !== "function")(
  "portable decoder streams native level-3 rollouts larger than 32 MiB",
  async () => {
    const path = join(await temporaryDirectory(), "large.jsonl.zst");
    const repetitions = Math.ceil((33 * 1024 * 1024) / (line.length + 1));
    await writeFile(
      path,
      zlib.zstdCompressSync(Buffer.from(`${line}\n`.repeat(repetitions))),
    );
    await withoutNativeZstd(async () => {
      let count = 0;
      let bytes = 0;
      for await (const value of sessionLines(path)) {
        count += 1;
        bytes += value.length + 1;
      }
      expect(count).toBe(repetitions);
      expect(bytes).toBe(repetitions * (line.length + 1));
    });
  },
);
