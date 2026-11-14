import { createReadStream } from "node:fs";
import zlib from "node:zlib";
import { createInterface } from "node:readline";
import { pipeline, type Transform } from "node:stream";
import { dirname, join } from "node:path";
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

/** Native zstd can stop at the first frame. Only a newline completes a header. */
export async function firstNativeSessionLine(
  path: string,
): Promise<string | undefined> {
  if (!path.endsWith(".zst") || typeof zlib.createZstdDecompress !== "function")
    return;
  const stream = pipeline(
    createReadStream(path),
    zlib.createZstdDecompress(),
    () => {},
  );
  try {
    stream.setEncoding("utf8");
    let line = "";
    for await (const chunk of stream as AsyncIterable<string>) {
      const newline = chunk.search(/[\r\n]/u);
      if (newline >= 0) return line + chunk.slice(0, newline);
      line += chunk;
    }
  } catch {
    // The complete portable reader handles unsupported or damaged frames.
  } finally {
    stream.destroy();
  }
}

export async function sessionDecompressor(): Promise<Transform> {
  // Decode every concatenated frame and reject truncated tails. Native Node
  // Zstandard streams can finish successfully after only the first frame.
  // The standalone MCP bundle replaces import.meta.url with its own filename.
  const mcpDirectory = import.meta.url.startsWith("file:")
    ? join(await bundledPluginRoot(), "mcp")
    : dirname(import.meta.url);
  const decoder = (await import(
    pathToFileURL(join(mcpDirectory, "session-decompression.mjs")).href
  )) as { createZstdDecompress: () => Transform };
  return decoder.createZstdDecompress();
}
