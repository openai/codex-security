import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, join, relative, resolve } from "node:path";
import test from "node:test";
import { assertNoError } from "./assertions.ts";
import { startRpcServer } from "./support/rpc-server.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const source =
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
  resolve(import.meta.dirname, "../../../../sdk/typescript/_bundled_plugin");

test("repeated MCP launches leave the installed plugin unchanged", async (t) => {
  const runtime = await temporaryDirectory(
    "codex-security-plugin-bytecode-",
    true,
  );
  t.after(() => rm(runtime, { recursive: true, force: true }));
  const output = join(runtime, "plugin with spaces");
  await cp(source, output, {
    recursive: true,
    filter: (file) => basename(file) !== "__pycache__",
  });
  const windows = process.platform === "win32";
  const launcher = `launch_codex_security_mcp${windows ? ".cmd" : ""}`;
  const snapshot = async () => {
    const files = await readdir(output, {
      recursive: true,
      withFileTypes: true,
    });
    const hashes: Record<string, string> = {};
    for (const file of files.filter((file) => file.isFile())) {
      const name = join(file.parentPath, file.name);
      hashes[relative(output, name)] = createHash("sha256")
        .update(await readFile(name))
        .digest("hex");
    }
    return hashes;
  };
  const before = await snapshot();
  const target = join(runtime, "target");
  await mkdir(target);
  await writeFile(join(target, "example.py"), "value = 1\n");
  for (let launch = 0; launch < 2; launch++) {
    const server = startRpcServer({
      command: windows ? (process.env.ComSpec ?? "cmd.exe") : "sh",
      args: windows
        ? ["/d", "/s", "/c", `scripts\\${launcher} --stdio`]
        : [`scripts/${launcher}`, "--stdio"],
      cwd: output,
      env: {
        ...process.env,
        CODEX_MCP_NODE_PATH: process.execPath,
        CODEX_SECURITY_PLUGIN_ROOT: output,
        CODEX_SECURITY_STATE_DIR: join(runtime, "state"),
        CODEX_SECURITY_SCAN_ROOT: join(runtime, "scans"),
        PYTHONDONTWRITEBYTECODE: "",
      },
    });
    try {
      assertNoError(await server.initialize("plugin-bytecode-test"));
      assertNoError(
        await server.callTool(2, {
          name: "inspect_codex_security_target",
          arguments: { targetPath: target },
        }),
      );
      assertNoError(
        await server.callTool(3, {
          name: "list_codex_security_scans",
          arguments: {},
        }),
      );
    } finally {
      await server.stop();
    }
    assert.deepEqual(
      await snapshot(),
      before,
      "MCP helpers must leave plugin files unchanged",
    );
  }
});
