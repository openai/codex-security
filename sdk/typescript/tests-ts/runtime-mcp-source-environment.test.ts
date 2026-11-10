import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createMarketplace } from "../src/runtime.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const parentSandbox = new URL(
  "../../../plugins/codex-security/mcp-app/src/deep-scan/parent-sandbox.ts",
  import.meta.url,
).href;

test.each(["bundled", "legacy projection", "declared projection"])(
  "%s forwards each scan's repository through the MCP environment",
  async (configuration) => {
    const root = await temporaryDirectory();
    let manifest = join(pluginRoot, ".mcp.json");
    if (configuration !== "bundled") {
      const selected = join(root, "selected plugin");
      await mkdir(join(selected, ".codex-plugin"), { recursive: true });
      await writeFile(
        join(selected, ".codex-plugin", "plugin.json"),
        JSON.stringify({ name: "codex-security", version: "1.2.3" }),
      );
      await writeFile(
        join(selected, ".mcp.json"),
        JSON.stringify({
          mcpServers: {
            "codex-security": {
              command: "./scripts/launch_codex_security_mcp",
              env_vars:
                configuration === "declared projection"
                  ? ["CODEX_SECURITY_PLUGIN_ROOT", "CODEX_SECURITY_REPOSITORY"]
                  : [],
            },
          },
        }),
      );
      const marketplace = await createMarketplace(join(root, "home"), selected);
      manifest = join(marketplace, "plugins", "codex-security", ".mcp.json");
    }
    const mcp = JSON.parse(await readFile(manifest, "utf8"));
    const allowed: string[] = mcp.mcpServers["codex-security"].env_vars;
    expect(
      allowed.filter((name) => name === "CODEX_SECURITY_REPOSITORY"),
    ).toHaveLength(1);

    for (const scan of ["fresh", "resumed"]) {
      const source = join(root, `${scan} source [fixture]`);
      const credentials = join(source, "config.toml");
      const parentEnvironment = {
        CODEX_SECURITY_PLUGIN_ROOT: pluginRoot,
        CODEX_SECURITY_REPOSITORY: source,
        SYNTHETIC_UNDECLARED_VALUE: "ambient fixture",
      };
      // Model the native MCP allowlist, then inspect the actual child process.
      const environment = Object.fromEntries(
        Object.entries(parentEnvironment).filter(([name]) =>
          allowed.includes(name),
        ),
      );
      const entries = [
        { path: { type: "special", value: { kind: "root" } }, access: "read" },
        { path: { type: "path", path: source }, access: "read" },
        { path: { type: "path", path: credentials }, access: "deny" },
      ];
      const extra = {
        _meta: {
          "codex/sandbox-state-meta": {
            permissionProfile: {
              type: "managed",
              file_system: { type: "restricted", entries },
            },
          },
        },
      };
      const child = spawnSync(
        process.execPath,
        [
          "--eval",
          `import { resolveDeepWorkerParentSandbox } from ${JSON.stringify(parentSandbox)};
const extra = JSON.parse(process.argv[1]);
const inherited = resolveDeepWorkerParentSandbox(extra);
extra._meta["codex/sandbox-state-meta"].permissionProfile.file_system.entries.splice(1, 1);
console.log(JSON.stringify({
  repository: process.env.CODEX_SECURITY_REPOSITORY,
  ambient: process.env.SYNTHETIC_UNDECLARED_VALUE,
  inherited,
  withoutNamedGrant: resolveDeepWorkerParentSandbox(extra),
}));`,
          JSON.stringify(extra),
        ],
        {
          env: { SystemRoot: process.env["SystemRoot"], ...environment },
          encoding: "utf8",
          windowsHide: true,
        },
      );
      expect(child.error).toBeUndefined();
      expect(child.stderr).toBe("");
      expect(child.status).toBe(0);
      expect(JSON.parse(child.stdout)).toEqual({
        repository: source,
        inherited: {
          filesystemDenies: [],
          literalFilesystemDenies: [credentials],
          ...(process.platform === "win32" ? { sourceReadRoot: source } : {}),
        },
        withoutNamedGrant: {
          filesystemDenies: [],
          literalFilesystemDenies: [credentials],
        },
      });
    }
  },
);
