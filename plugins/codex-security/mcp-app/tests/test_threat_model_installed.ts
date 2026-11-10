import assert from "node:assert/strict";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { startRpcServer } from "./support/rpc-server.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const source =
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
  resolve(import.meta.dirname, "../../../../sdk/typescript/_bundled_plugin");

test("installed worker MCP saves threat models without Python", async (t) => {
  const root = await temporaryDirectory("threatmodel-installed-", true);
  t.after(() => rm(root, { recursive: true, force: true }));
  const pluginRoot = join(root, "installed plugin");
  await cp(source, pluginRoot, { recursive: true });
  const artifactRoot = join(root, "artifacts");
  const repoRoot = join(root, "repository");
  const emptyPath = join(root, "empty-path");
  await Promise.all(
    [artifactRoot, repoRoot, emptyPath].map((path) =>
      mkdir(path, { recursive: true }),
    ),
  );
  const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
  const server = startRpcServer({
    command: process.execPath,
    args: [join(pluginRoot, "mcp", "server.mjs"), "--artifact-writer"],
    cwd: root,
    env: {
      ...process.env,
      PATH: emptyPath,
      PYTHON: join(emptyPath, "python"),
      CODEX_SECURITY_PYTHON_COMMAND: join(emptyPath, "python"),
      XDG_CACHE_HOME: join(root, "cache"),
      CODEX_SECURITY_PLUGIN_ROOT: pluginRoot,
      CODEX_SECURITY_ARTIFACT_ROOT: artifactRoot,
      CODEX_SECURITY_REPO_ROOT: repoRoot,
      CODEX_SECURITY_ARTIFACT_LAYOUT: "worker",
      CODEX_SECURITY_SCAN_ID: scanId,
    },
  });
  try {
    await server.initialize("threatmodel-installed");
    const content = "# Saved model\r\n\r\n    Preserve  spacing.\r\n";
    const threatModel = {
      summary: "Legacy structured model.",
      format: "markdown",
      content,
      origin: false,
      scope: { includePaths: ["src/[api]"] },
    };
    const draft = {
      scanId,
      complete: false,
      findings: [],
      reviewState: { surfaces: [], explicitExclusions: [], deferred: [] },
    };
    const result = await server.callSuccessfulTool(2, {
      name: "record_codex_security_scan_draft",
      arguments: { ...draft, threatModel },
    });
    assert.equal(result.structuredContent.warnings, undefined);
    const documentPath = join(artifactRoot, "threatmodel.md");
    const document = await readFile(documentPath, "utf8");
    assert.ok(document.startsWith(content));
    assert.match(document, /Model origin: not recorded\n/);
    assert.match(document, /Model scope: src\/\\\[api\\\]\n/);
    assert.match(document, /provisional/);
    await server.callSuccessfulTool(3, {
      name: "record_codex_security_scan_draft",
      arguments: draft,
    });
    assert.equal(await readFile(documentPath, "utf8"), document);
    assert.deepEqual(
      JSON.parse(await readFile(join(artifactRoot, "result.json"), "utf8"))
        .threatModel,
      threatModel,
    );
  } finally {
    await server.stop();
  }
});
