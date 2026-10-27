import { existsSync } from "node:fs";
import {
  chmod,
  cp,
  mkdir,
  readdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync } from "node:zlib";

const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);
const hasMonorepoSdk = existsSync(
  new URL("../../../project/codex-security-sdk/src/", import.meta.url),
);

export const PLUGIN_ROOT = fileURLToPath(bundledPlugin);

// Credential tests run worker configuration and plugin refresh up to the Codex
// client boundary, so copy the MCP descriptor and both platform launchers.
export async function copyCredentialTestPlugin(root: string): Promise<string> {
  const plugin = join(root, "plugin");
  const manifest = ".codex-plugin/plugin.json";
  const { name, version, skills, mcpServers, codexSecurity } = JSON.parse(
    await readFile(new URL(manifest, bundledPlugin), "utf8"),
  );
  await mkdir(join(plugin, ".codex-plugin"), { recursive: true });
  await writeFile(
    join(plugin, manifest),
    JSON.stringify({ name, version, skills, mcpServers, codexSecurity }),
  );
  for (const file of [
    ".mcp.json",
    "scripts/launch_codex_security_mcp",
    "scripts/launch_codex_security_mcp.cmd",
    "skills/security-scan/SKILL.md",
  ]) {
    await cp(new URL(file, bundledPlugin), join(plugin, file));
  }
  return plugin;
}

export const INTEGRATION_TARGET = hasMonorepoSdk
  ? "project/codex-security-sdk/src"
  : "sdk/typescript/src";

let bundledRuntime: Promise<string> | undefined;

export function loadBundledRuntime(): Promise<string> {
  return (bundledRuntime ??= readdir(new URL("mcp/", bundledPlugin))
    .then((names) =>
      Promise.all(
        names
          .filter((name) => name.startsWith("server.mjs.br.part-"))
          .sort()
          .map((name) => readFile(new URL(`mcp/${name}`, bundledPlugin))),
      ),
    )
    .then((parts) =>
      brotliDecompressSync(Buffer.concat(parts)).toString("utf8"),
    ));
}

export const copyCompletedScanFixture = (destination: string) =>
  cp(new URL("examples/legacy-completed-scan/", bundledPlugin), destination, {
    recursive: true,
  });

export async function copyCompletedScan(root: string): Promise<string> {
  const scanDir = join(root, "scan");
  await copyCompletedScanFixture(scanDir);
  await chmod(scanDir, 0o700);
  await writeFile(join(scanDir, "report.md"), "# Scan report\n");
  return scanDir;
}
