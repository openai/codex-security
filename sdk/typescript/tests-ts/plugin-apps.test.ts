import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("registers security access through the Codex Security MCP, not a hosted app", async () => {
  const [appConfiguration, mcpConfiguration] = await Promise.all([
    readFile(join(PLUGIN_ROOT, ".app.json"), "utf8"),
    readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
  ]);
  const apps = (JSON.parse(appConfiguration) as Record<string, unknown>)[
    "apps"
  ] as Record<string, unknown>;
  const mcpServers = (JSON.parse(mcpConfiguration) as Record<string, unknown>)[
    "mcpServers"
  ] as Record<string, unknown>;

  expect(apps).not.toHaveProperty("codex-security-access");
  expect(
    Object.values(apps).some(
      (app) =>
        (app as Record<string, unknown>)["id"] ===
        "connector_openai_codex_security_access",
    ),
  ).toBe(false);
  expect(mcpServers).toHaveProperty("codex-security");
  expect(mcpServers).not.toHaveProperty("codex-security-access");
});
