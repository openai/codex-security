import { brotliDecompressSync } from "node:zlib";
import { existsSync } from "node:fs";
import { chmod, cp, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);
const hasMonorepoSdk = existsSync(
  new URL("../../../project/codex-security-sdk/src/", import.meta.url),
);

export const PLUGIN_ROOT = fileURLToPath(bundledPlugin);

export const INTEGRATION_TARGET = hasMonorepoSdk
  ? "project/codex-security-sdk/src"
  : "sdk/typescript/src";

let bundledRuntime: Promise<string> | undefined;

export function loadBundledRuntime(): Promise<string> {
  return (bundledRuntime ??= readdir(new URL("mcp/", bundledPlugin)).then(
    async (names) => {
      const parts = await Promise.all(
        names
          .filter((name) => /^server\.mjs\.br\.part-\d+$/u.test(name))
          .sort()
          .map((name) => readFile(new URL(`mcp/${name}`, bundledPlugin))),
      );
      return brotliDecompressSync(Buffer.concat(parts)).toString("utf8");
    },
  ));
}

export const copyCompletedScanFixture = (destination: string) =>
  cp(new URL("examples/completed-scan/", bundledPlugin), destination, {
    recursive: true,
  });

export async function copyCompletedScan(root: string): Promise<string> {
  const scanDir = join(root, "scan");
  await copyCompletedScanFixture(scanDir);
  await chmod(scanDir, 0o700);
  await writeFile(join(scanDir, "report.md"), "# Scan report\n");
  return scanDir;
}
