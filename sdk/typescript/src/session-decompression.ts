import { join } from "node:path";
import type { Transform } from "node:stream";
import { pathToFileURL } from "node:url";
import { bundledPluginRoot } from "./bundled-plugin.js";

export async function createZstdDecompress(): Promise<Transform> {
  const plugin = await bundledPluginRoot();
  const decoder = (await import(
    pathToFileURL(join(plugin, "mcp", "session-decompression.mjs")).href
  )) as { createZstdDecompress: () => Transform };
  return decoder.createZstdDecompress();
}
