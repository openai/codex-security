import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";

test("keeps model-visible attack-path tool names within the Codex limit", async () => {
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const state = mkdtempSync(join(tmpdir(), "codex-security-mcp-tools-"));

  try {
    const { status, stdout, stderr } = await runCommand(
      node!,
      [join(PLUGIN_ROOT, "mcp", "server.mjs")],
      {
        env: { ...process.env, CODEX_SECURITY_STATE_DIR: state },
        input: [
          '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex-security-test","version":"1.0.0"}}}',
          '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
          '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
          "",
        ].join("\n"),
        timeout: 30_000,
      },
    );
    expect(status, stderr).toBe(0);

    const tools = stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line))
      .find((response) => response.id === 2).result.tools as {
      name: string;
      _meta?: { ui?: { visibility?: string[] } };
    }[];

    expect(tools.map((tool) => tool.name)).toContain(
      "record_candidate_attack_paths",
    );
    for (const tool of tools) {
      if (tool._meta?.ui?.visibility?.includes("model") === false) continue;
      expect(`mcp__codex_security__${tool.name}`.length).toBeLessThanOrEqual(
        64,
      );
    }
  } finally {
    rmSync(state, { recursive: true, force: true });
  }
});
