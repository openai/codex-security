import { createReadStream } from "node:fs";
import { pipeline } from "node:stream/promises";

// The Python usage collector uses the plugin's required Node runtime to read
// cold rollouts without requiring a separate Python compression dependency.
try {
  const path = process.argv[2];
  if (!path) throw new Error("A Codex rollout path is required.");
  // Native Node decoding can stop after the first frame. Rollouts may contain
  // concatenated frames, and an incomplete later frame must remain an error.
  const { createZstdDecompress } =
    await import("../mcp/session-decompression.mjs");
  await pipeline(
    createReadStream(path),
    createZstdDecompress(),
    process.stdout,
  );
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
