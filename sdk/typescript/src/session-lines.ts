import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { pipeline, type Transform } from "node:stream";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { bundledPluginRoot } from "./runtime.js";

/** Plain and cold compressed rollouts have the same newline-delimited format. */
export async function* sessionLines(path: string): AsyncGenerator<string> {
  const decompressor = path.endsWith(".zst")
    ? await sessionDecompressor()
    : null;
  const file = createReadStream(path);
  const stream =
    decompressor !== null ? pipeline(file, decompressor, () => {}) : file;
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    yield* lines;
  } finally {
    lines.close();
    stream.destroy();
  }
}

async function sessionDecompressor(): Promise<Transform> {
  // Decode every concatenated frame and reject truncated tails. Native Node
  // Zstandard streams can finish successfully after only the first frame.
  const decoder = (await import(
    pathToFileURL(
      join(await bundledPluginRoot(), "mcp", "session-decompression.mjs"),
    ).href
  )) as { createZstdDecompress: () => Transform };
  return decoder.createZstdDecompress();
}
