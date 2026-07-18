import { readFileSync } from "node:fs";

/** npm-compatible successor to the Python package version 0.1.0b3. */
export const VERSION = manifestVersion(
  new URL("../package.json", import.meta.url),
  "package",
);
export const BUNDLED_PLUGIN_VERSION = "0.1.14" as const;

function manifestVersion(url: URL, label: string): string {
  try {
    const manifest: unknown = JSON.parse(readFileSync(url, "utf8"));
    if (
      typeof manifest !== "object" ||
      manifest === null ||
      !("version" in manifest) ||
      typeof manifest.version !== "string" ||
      manifest.version.length === 0
    ) {
      throw new Error("version must be a non-empty string");
    }
    return manifest.version;
  } catch (error) {
    throw new Error(`Unable to read Codex Security ${label} version.`, {
      cause: error,
    });
  }
}
