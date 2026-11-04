import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { assertNoError } from "./assertions.ts";
import { startRpcServer } from "./support/rpc-server.ts";

const plugin = resolve(
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
    join(import.meta.dirname, "../../../../sdk/typescript/_bundled_plugin"),
);

test("packaged MCP and standalone reader select the same runtime instructions", async () => {
  const server = startRpcServer({
    command: process.execPath,
    args: [join(plugin, "mcp", "server.mjs"), "--stdio"],
    env: { ...process.env, CODEX_SECURITY_PLUGIN_ROOT: plugin },
  });
  try {
    assertNoError(await server.initialize("codex-mcp-client"));
    const name = "get_codex_security_skill_instructions";
    let id = 2;
    async function instructions(
      topic: string,
      clientSurface?: "desktop" | "headless",
    ) {
      const response = await server.callTool(id++, {
        name,
        arguments: { topic, clientSurface },
      });
      assertNoError(response);
      const text: string = response.result.content[0].text;
      const args = [join(plugin, "scripts", "skill_runtime.mjs"), topic];
      if (clientSurface) args.push(clientSurface);
      assert.equal(
        execFileSync(process.execPath, args, { encoding: "utf8" }),
        text,
      );
      return text;
    }

    for (const clientSurface of [undefined, "desktop"] as const) {
      const desktop = clientSurface === "desktop";
      for (const topic of ["standard-scan", "diff-scan", "deep-scan"]) {
        const text = await instructions(topic, clientSurface);
        assert.match(text, /get_codex_security_scan_context/);
        assert.equal(text.includes("::code-comment"), desktop);
        assert.equal(
          text.includes("complete_codex_security_scan"),
          topic !== "deep-scan",
        );
        assert.equal(
          text.includes("record_codex_security_scan_draft"),
          topic !== "deep-scan",
        );
        assert.equal(
          text.includes("start_codex_security_deep_scan"),
          topic === "deep-scan",
        );
        assert.equal(
          text.includes("start_codex_security_standard_scan"),
          topic === "standard-scan" && !desktop,
        );
        assert.equal(
          text.includes("start_codex_security_prompt_only_scan"),
          topic === "diff-scan" || (topic === "standard-scan" && desktop),
        );
      }
    }
    const command = await instructions("scope-binding", "desktop");
    assert.match(command, /--helper bind-repo-scopes/);
    assert.equal(command.includes("cmd.exe"), process.platform === "win32");
    assert.doesNotMatch(command, /::code-comment/);

    const invalid = await server.callTool(id, {
      name,
      arguments: { topic: "../plugin-files" },
    });
    assert.ok(invalid.result?.isError || invalid.error);
  } finally {
    await server.stop();
  }
});
