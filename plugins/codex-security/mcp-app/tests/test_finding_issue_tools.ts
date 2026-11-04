import assert from "node:assert/strict";
import { cp, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { TextContent } from "@modelcontextprotocol/sdk/types.js";
import { applicationRoot, buildServer } from "./build-server.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const pluginRoot = path.resolve(applicationRoot, "..");
const runtimePluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : path.resolve(applicationRoot, "../../../sdk/typescript/_bundled_plugin");
const root = await temporaryDirectory("codex-security-finding-issues-mcp-");
const scanDirectory = path.join(root, "scan");
const stateDirectory = path.join(root, "state");
const bundle = path.join(root, "server.cjs");
const client = new Client({ name: "finding-issues-test", version: "1.0.0" });

try {
  await cp(path.join(pluginRoot, "examples", "completed-scan"), scanDirectory, {
    recursive: true,
  });
  await buildServer(bundle, { target: "node20" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [bundle, "--stdio"],
      cwd: applicationRoot,
      env: {
        ...process.env,
        CODEX_SECURITY_PLUGIN_ROOT: runtimePluginRoot,
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      } as Record<string, string>,
    }),
  );
  const findingsPath = path.join(scanDirectory, "findings.json");
  const findingsBytes = await readFile(findingsPath, "utf8");
  const { findingId, occurrenceId } = JSON.parse(findingsBytes).findings[0];
  const manifestBytes = await readFile(
    path.join(scanDirectory, "scan-manifest.json"),
  );
  const source = { scanDirectory, findingIds: [findingId] };
  const jira = { type: "jira", cloudId: "example-site", projectId: "10001" };
  const linear = { type: "linear", teamId: "example-team" };
  const receipt = {
    findingId,
    occurrenceId,
    issueIdentifier: "APP-1",
    operation: "create",
  };

  const tools = (await client.listTools()).tools;
  for (const name of [
    "get_codex_security_finding_issues",
    "record_codex_security_finding_issues",
  ]) {
    const tool = tools.find((entry) => entry.name === name);
    assert.ok(tool, `Missing model-visible tool ${name}`);
    assert.deepEqual(tool._meta?.ui, { visibility: ["model"] });
    assert.equal(
      Object.hasOwn(tool.inputSchema.properties ?? {}, "requireHistory"),
      false,
    );
  }
  const empty = await call("get_codex_security_finding_issues", {
    ...source,
    destination: jira,
  });
  assert.deepEqual(empty.receipts, []);
  await assert.rejects(stat(path.join(stateDirectory, "workbench.sqlite3")), {
    code: "ENOENT",
  });

  const accepted = await call("record_codex_security_finding_issues", {
    ...source,
    destination: jira,
    receipts: [receipt],
  });
  assert.equal(accepted.receipts.length, 1);
  assert.equal(accepted.receipts[0].issueIdentifier, "APP-1");
  assert.equal(accepted.receipts[0].readback, undefined);
  const readback = {
    status: "failed",
    error: `Issue read access denied. ${"x".repeat(4 * 1024 * 1024)}`,
  };
  await call("record_codex_security_finding_issues", {
    ...source,
    destination: jira,
    receipts: [{ ...receipt, readback }],
  });
  const saved = await call("get_codex_security_finding_issues", {
    ...source,
    destination: jira,
  });
  assert.equal(
    saved.receipts.length,
    1,
    "Readback must update the accepted receipt.",
  );
  assert.equal(saved.receipts[0].operation, "create");
  assert.deepEqual(saved.receipts[0].readback, readback);
  assert.deepEqual(
    (
      await call("get_codex_security_finding_issues", {
        ...source,
        destination: { ...jira, cloudId: "another-site" },
      })
    ).receipts,
    [],
  );

  await call("record_codex_security_finding_issues", {
    ...source,
    destination: linear,
    receipts: [
      { ...receipt, operation: "reuse", readback: { status: "verified" } },
    ],
  });
  const reused = await call("get_codex_security_finding_issues", {
    ...source,
    destination: linear,
  });
  assert.equal(reused.receipts.length, 1);
  assert.equal(reused.receipts[0].operation, "reuse");
  assert.deepEqual(reused.receipts[0].readback, { status: "verified" });
  assert.deepEqual(
    await readFile(path.join(scanDirectory, "scan-manifest.json")),
    manifestBytes,
  );
  assert.equal(await readFile(findingsPath, "utf8"), findingsBytes);

  await writeFile(findingsPath, findingsBytes + "\n");
  for (const [name, input] of [
    ["get_codex_security_finding_issues", { ...source, destination: jira }],
    [
      "record_codex_security_finding_issues",
      { ...source, destination: jira, receipts: [receipt] },
    ],
  ] as const) {
    const result = await client.callTool({ name, arguments: input });
    assert.equal(
      result.isError,
      true,
      "Changed sealed artifacts must fail before association access.",
    );
    assert.match(
      (result.content as TextContent[])[0].text,
      /sealed artifact changed/,
    );
  }
} finally {
  await client.close();
  await rm(root, { recursive: true, force: true });
}

async function call(name: string, input: Record<string, unknown>) {
  const result = await client.callTool({ name, arguments: input });
  assert.notEqual(
    result.isError,
    true,
    (result.content as TextContent[])[0]?.text,
  );
  return result.structuredContent as {
    receipts: {
      issueIdentifier: string;
      operation: string;
      readback?: { status: string; error?: string };
    }[];
  };
}
