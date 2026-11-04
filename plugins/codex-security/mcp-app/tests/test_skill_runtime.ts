import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm, symlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { assertNoError } from "./assertions.ts";
import { startRpcServer } from "./support/rpc-server.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const plugin = resolve(
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
    join(import.meta.dirname, "../../../../sdk/typescript/_bundled_plugin"),
);

test("packaged MCP and standalone reader select runtime instructions", async (t) => {
  const root = await temporaryDirectory("skill-runtime-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const linked = join(root, "linked plugin");
  await symlink(plugin, linked, "junction");
  const reader = join(linked, "scripts", "skill_runtime.mjs");
  const server = startRpcServer({
    command: process.execPath,
    args: [join(plugin, "mcp", "server.mjs"), "--stdio"],
    env: { ...process.env, CODEX_SECURITY_PLUGIN_ROOT: plugin },
  });
  t.after(() => server.stop());
  assertNoError(await server.initialize("codex-mcp-client"));

  let id = 2;
  const instructions = (topic: string, clientSurface?: "desktop") =>
    server.callTool(id++, {
      name: "get_codex_security_skill_instructions",
      arguments: { topic, clientSurface },
    });
  for (const surface of [undefined, "desktop"] as const) {
    for (const [topic, start] of [
      ["standard-scan", surface ? "prompt_only" : "standard"],
      ["diff-scan", "prompt_only"],
      ["deep-scan", "deep"],
    ] as const) {
      const response = await instructions(topic, surface);
      assertNoError(response);
      const text: string = response.result.content[0].text;
      assert.match(text, /get_codex_security_scan_context/);
      assert.equal(text.includes("::code-comment"), surface === "desktop");
      assert.deepEqual(
        new Set(text.match(/\bstart_codex_security_\w+_scan\b/g)),
        new Set([`start_codex_security_${start}_scan`]),
      );
      for (const tool of [
        "record_codex_security_scan_draft",
        "complete_codex_security_scan",
      ])
        assert.equal(text.includes(tool), topic !== "deep-scan", tool);
      if (topic === "standard-scan") {
        const args = surface ? [reader, topic, surface] : [reader, topic];
        assert.equal(
          execFileSync(process.execPath, args, { encoding: "utf8" }),
          text,
        );
      }
    }
  }
  const command = await instructions("scope-binding", "desktop");
  assertNoError(command);
  const text: string = command.result.content[0].text;
  assert.match(text, /--helper bind-repo-scopes/);
  assert.equal(text.includes("cmd.exe"), process.platform === "win32");
  assert.doesNotMatch(text, /::code-comment/);

  const invalid = await instructions("../plugin-files");
  assert.ok(invalid.result?.isError || invalid.error);
});
