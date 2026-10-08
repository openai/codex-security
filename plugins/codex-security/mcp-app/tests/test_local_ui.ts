import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerLocalUi } from "../src/server/local-ui.ts";

test("a supplied UI document is read through the owning server without touching scan storage", async () => {
  const directory = await mkdtemp(join(tmpdir(), "security-ui-"));
  const server = new McpServer({ name: "test", version: "1" });
  const client = new Client({ name: "test", version: "1" });
  try {
    const document = "<!doctype html><title>Synthetic workbench</title>";
    await writeFile(join(directory, "local.html"), document);
    registerLocalUi(server, directory);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    const { tools } = await client.listTools();
    assert.equal(tools.length, 1);
    assert.deepEqual(tools[0]._meta?.ui, {
      resourceUri: "ui://codex-security/local.html",
      visibility: ["app"],
    });
    const result = await client.readResource({
      uri: "ui://codex-security/local.html",
    });
    assert.ok("text" in result.contents[0]);
    assert.equal(result.contents[0].text, document);
    assert.deepEqual(result.contents[0]._meta, {
      ui: { csp: { connectDomains: [], resourceDomains: [] } },
    });
    assert.equal(result.contents[0].mimeType, "text/html;profile=mcp-app");
  } finally {
    await client.close();
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a distribution without a UI keeps its original tool inventory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "security-ui-"));
  const server = new McpServer({ name: "test", version: "1" });
  const client = new Client({ name: "test", version: "1" });
  try {
    server.registerTool("existing", { inputSchema: {} }, async () => ({
      content: [],
    }));
    registerLocalUi(server, directory);
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    assert.deepEqual(
      (await client.listTools()).tools.map(({ name }) => name),
      ["existing"],
    );
  } finally {
    await client.close();
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});
