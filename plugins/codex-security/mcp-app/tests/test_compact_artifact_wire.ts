import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { encodePosixPath } from "../src/helpers/posix-path.ts";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { registerCompactArtifactTools } = await importSource(
  fileURLToPath(
    new URL("../src/server/compact-artifact-tools.ts", import.meta.url),
  ),
  { loader: { ".md": "text" } },
);
const sdkRequire = createRequire(
  new URL("../../../../sdk/typescript/package.json", import.meta.url),
);
const nativeCli = sdkRequire.resolve("@openai/codex/bin/codex.js");

for (const raw of [false, true]) {
  test(
    `compact inventory survives native MCP transport with ${raw ? "raw POSIX" : "Unicode"} names`,
    { skip: raw && process.platform === "win32", timeout: 30_000 },
    async () => {
      const root = await temporaryDirectory("compact-artifact-wire-", true);
      try {
        const scanDir = path.join(root, "scan");
        const repository = path.join(root, "repository");
        const inventoryDir = path.join(scanDir, "artifacts", "02_discovery");
        await mkdir(inventoryDir, { recursive: true });
        await mkdir(repository);
        const inventory = raw
          ? Buffer.concat([
              Buffer.from("./name-"),
              Buffer.from([0xff]),
              Buffer.from(".ts\n"),
            ])
          : Buffer.from("./normal.ts\n./emoji-😀.ts\n");
        await writeFile(
          path.join(inventoryDir, "in_scope_files.txt"),
          inventory,
        );
        const callbacks = new Map<
          string,
          (input: unknown, context: unknown) => Promise<CallToolResult>
        >();
        registerCompactArtifactTools(
          {
            registerTool(
              name: string,
              _schema: unknown,
              callback: (
                input: unknown,
                context: unknown,
              ) => Promise<CallToolResult>,
            ) {
              callbacks.set(name, callback);
            },
          } as unknown as McpServer,
          {
            pluginRoot: path.resolve(import.meta.dirname, "../.."),
            resolveScanRoot: async () => root,
            runWorkbench: async (args: string[]) => {
              assert.deepEqual(args, [
                "get-scan",
                "--scan-id",
                "11111111-1111-4111-8111-111111111111",
              ]);
              return {
                scan: {
                  scanId: args[2],
                  scanDir,
                  targetPath: repository,
                  mode: "diff",
                  status: "running",
                  handoffClaimToken: "synthetic-claim",
                },
              };
            },
          },
        );
        const result = await callbacks.get("list_codex_security_review_items")!(
          {
            scanId: "11111111-1111-4111-8111-111111111111",
            handoffClaimToken: "synthetic-claim",
          },
          {},
        );
        const received = await throughNativeMcp(root, result);
        const content = received.content[0];
        assert.equal(content?.type, "text");
        assert.ok(content && content.type === "text");
        const parsed = JSON.parse(content.text) as {
          items: { path: string }[];
        };
        if (raw) {
          assert.equal(received.structuredContent, undefined);
          assert.deepEqual(
            encodePosixPath(parsed.items[0]!.path + "\n"),
            inventory,
          );
        } else {
          assert.deepEqual(parsed, {
            items: [{ path: "./normal.ts" }, { path: "./emoji-😀.ts" }],
          });
          assert.deepEqual(received.structuredContent, parsed);
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}

async function throughNativeMcp(
  root: string,
  result: CallToolResult,
): Promise<CallToolResult> {
  const responsePath = path.join(root, "response.json");
  const serverPath = path.join(root, "mcp-fixture.mjs");
  const codexHome = path.join(root, "codex-home");
  await mkdir(codexHome, { mode: 0o700 });
  await writeFile(responsePath, JSON.stringify(result));
  await writeFile(
    serverPath,
    `
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const result = JSON.parse(readFileSync(process.argv[2], 'utf8'));
createInterface({input: process.stdin}).on('line', line => {
  const request = JSON.parse(line);
  if (request.id === undefined) return;
  const value = request.method === 'initialize'
    ? {protocolVersion: request.params.protocolVersion, capabilities: {tools: {}}, serverInfo: {name: 'fixture', version: '1'}}
    : request.method === 'tools/list'
      ? {tools: [{name: 'inventory', description: 'Synthetic inventory', inputSchema: {type: 'object', properties: {}}}]}
      : request.method === 'tools/call' ? result : {};
  process.stdout.write(JSON.stringify({jsonrpc: '2.0', id: request.id, result: value}) + '\\n');
});
`,
  );
  const child = spawn(
    process.execPath,
    [
      nativeCli,
      "app-server",
      "--stdio",
      "-c",
      "features.plugins=false",
      "-c",
      `mcp_servers.fixture.command=${JSON.stringify(process.execPath)}`,
      "-c",
      `mcp_servers.fixture.args=${JSON.stringify([serverPath, responsePath])}`,
      "-c",
      "mcp_servers.fixture.tool_timeout_sec=3",
    ],
    {
      cwd: root,
      env: { ...process.env, CODEX_HOME: codexHome },
      windowsHide: true,
    },
  );
  const closed = once(child, "close");
  const lines = createInterface({ input: child.stdout });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  const iterator = lines[Symbol.asyncIterator]();
  const timer = setTimeout(() => child.kill("SIGKILL"), 20_000);
  let id = 0;
  const request = async (method: string, params: unknown) => {
    const identifier = ++id;
    child.stdin.write(
      JSON.stringify({ id: identifier, method, params }) + "\n",
    );
    while (true) {
      const line = await iterator.next();
      if (line.done) throw new Error(`Native MCP transport closed: ${stderr}`);
      const response = JSON.parse(line.value);
      if (response.id !== identifier) continue;
      if (response.error) throw new Error(JSON.stringify(response.error));
      return response.result;
    }
  };
  try {
    await request("initialize", {
      clientInfo: { name: "compact-artifact-fixture", version: "1" },
      capabilities: { experimentalApi: true },
    });
    child.stdin.write(JSON.stringify({ method: "initialized" }) + "\n");
    const started = await request("thread/start", {
      cwd: root,
      ephemeral: true,
      approvalPolicy: "never",
      sandbox: "read-only",
    });
    return await request("mcpServer/tool/call", {
      threadId: started.thread.id,
      server: "fixture",
      tool: "inventory",
      arguments: {},
    });
  } finally {
    clearTimeout(timer);
    lines.close();
    child.kill();
    const force = setTimeout(() => child.kill("SIGKILL"), 3_000);
    try {
      await closed;
    } finally {
      clearTimeout(force);
    }
  }
}
