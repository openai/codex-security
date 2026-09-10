import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createRequire } from "node:module";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const applicationRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pluginRoot = path.dirname(applicationRoot);
const python = process.env.PYTHON || "python3";
const exec = promisify(execFile);
const fixture = await fs.realpath(await fs.mkdtemp(path.join(tmpdir(), "codex-security-storage-regressions-")));
const repository = path.join(fixture, "repository");
const bundle = path.join(fixture, "server.cjs");
const helpers = path.join(fixture, "helpers.cjs");
const environment = { ...process.env, CODEX_SECURITY_STATE_DIR: path.join(fixture, "state"), CODEX_HOME: path.join(fixture, "home") };
delete environment.CODEX_SECURITY_SCAN_ROOT;
delete environment.PYTHONSAFEPATH;
const clients = [];
const temporaryDirectories = [];

await fs.mkdir(repository);
await fs.writeFile(path.join(repository, "example.py"), "value = 1\n");
await build({
  bundle: true,
  define: { __dirname: JSON.stringify(applicationRoot), "import.meta.url": "__filename" },
  entryPoints: [path.join(applicationRoot, "main.ts")],
  external: ["fsevents"], format: "cjs", loader: { ".md": "text" },
  logLevel: "silent", outfile: bundle, platform: "node"
});
await build({
  bundle: true, format: "cjs", platform: "node", logLevel: "silent", outfile: helpers,
  stdin: { resolveDir: applicationRoot, contents: `
    export { saveCodexSecurityArtifact, standaloneArtifactContext } from './src/artifact-storage.ts';
    export { createScanArtifactContext } from './src/artifact-context.ts';
  ` }
});
const { saveCodexSecurityArtifact, standaloneArtifactContext, createScanArtifactContext } = createRequire(import.meta.url)(helpers);

async function workbench(args, input, launcher) {
  const command = launcher
    ? [launcher, path.join(pluginRoot, "scripts/workbench_db.py"), ...args]
    : [path.join(pluginRoot, "scripts/workbench_db.py"), ...args];
  const execution = exec(python, command, { cwd: pluginRoot, env: environment, maxBuffer: 4 * 1024 * 1024 });
  execution.child.stdin.on("error", () => {});
  execution.child.stdin.end(input);
  return JSON.parse((await execution).stdout);
}

async function connect(overrides = {}) {
  const client = new Client({ name: "artifact-regression-test", version: "1.0.0" });
  clients.push(client);
  const env = { ...environment, ...overrides };
  for (const key of Object.keys(env)) if (env[key] === undefined) delete env[key];
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [bundle, "--stdio"], cwd: repository, env }));
  return async (name, args) => {
    const result = await client.callTool({ name, arguments: args, _meta: { "openai/threadId": "artifact-regression-owner" } });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return result.structuredContent;
  };
}

try {
  await test("a save captured before sealing cannot create directories after sealing", async () => {
    const call = await connect();
    const { scanId, scanDir, handoffClaimToken } = await call("start_codex_security_standard_scan", { targetPath: repository });
    const identity = { scanId, handoffClaimToken };
    const context = await createScanArtifactContext(scanId, workbench, { requireRunning: true, requireClaim: true, handoffClaimToken });
    const scratch = await saveCodexSecurityArtifact(context, { ...identity, storage: "temporary" }, workbench);
    temporaryDirectories.push(scratch.directory);
    await call("record_codex_security_scan_draft", {
      ...identity, findings: [], threatModel: { summary: "Synthetic test target" },
      coverage: { completeness: "complete", surfaces: [{ id: "source", label: "Source", disposition: "not_applicable", receiptRefs: [] }], explicitExclusions: [], deferred: [] }
    });
    await workbench(["prepare-scan-completion", "--scan-id", scanId, "--claim-token", handoffClaimToken]);
    await assert.rejects(() => saveCodexSecurityArtifact(context, {
      ...identity, storage: "persistent", path: "artifacts/after-seal/proof.txt", content: "rejected"
    }, workbench), /sealed|stopped/);
    await assert.rejects(fs.stat(path.join(scanDir, "artifacts/after-seal")), { code: "ENOENT" });
  });

  for (const storage of ["temporary", "persistent"]) {
    await test(`${storage} publication stays bound to its opened parent during replacement`, { skip: process.platform === "win32" }, async () => {
      const context = await standaloneArtifactContext(repository, workbench, true, path.join(fixture, `swap-${storage}`));
      const location = { targetPath: repository, storage };
      const { directory } = await saveCodexSecurityArtifact(context, location, workbench);
      if (storage === "temporary") temporaryDirectories.push(directory);
      const parent = path.join(directory, "artifacts", "nested");
      const moved = path.join(directory, "artifacts", "original");
      const outside = path.join(fixture, `outside-${storage}`);
      const marker = path.join(fixture, `swapped-${storage}`);
      await fs.mkdir(parent, { recursive: true });
      await fs.mkdir(outside);
      await fs.writeFile(path.join(outside, "proof.bin"), "outside remains unchanged");
      // Both writers execute real I/O. Pause at their acquired parent/lock to
      // deterministically replace the pathname without relying on race timing.
      const launcher = path.join(fixture, `swap-${storage}.py`);
      await fs.writeFile(launcher, `
import os, runpy, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import finalize_scan_contract as finalizer
original_open = finalizer._open_scan_local_directory
def open_then_replace(root_fd, parts, *, create):
    descriptor = original_open(root_fd, parts, create=create)
    if parts == ("artifacts", "nested"):
        os.rename(${JSON.stringify(parent)}, ${JSON.stringify(moved)})
        os.symlink(${JSON.stringify(outside)}, ${JSON.stringify(parent)})
        Path(${JSON.stringify(marker)}).write_text("python")
    return descriptor
finalizer._open_scan_local_directory = open_then_replace
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`);
      const originalOpen = fs.open;
      fs.open = async (...args) => {
        const handle = await originalOpen(...args);
        if (args[0] === path.join(parent, "proof.bin.lock")) {
          await fs.rename(parent, moved);
          await fs.symlink(outside, parent);
          await fs.writeFile(marker, "javascript");
        }
        return handle;
      };
      try {
        await saveCodexSecurityArtifact(context, { ...location, path: "artifacts/nested/proof.bin", content: "new artifact" },
          (args, input) => workbench(args, input, launcher));
      } finally {
        fs.open = originalOpen;
      }
      assert.ok(await fs.readFile(marker, "utf8"), "the directory replacement must actually run");
      assert.equal(await fs.readFile(path.join(outside, "proof.bin"), "utf8"), "outside remains unchanged");
      assert.equal(await fs.readFile(path.join(moved, "proof.bin"), "utf8"), "new artifact");
    });
  }

  for (const variable of ["CODEX_SECURITY_SCAN_ROOT", "CODEX_SECURITY_STATE_DIR"]) {
    await test(`${variable} keeps the workbench base when MCP starts in another directory`, async () => {
      const relative = `.${path.basename(fixture)}-${variable}`;
      const destination = path.join(pluginRoot, relative);
      temporaryDirectories.push(destination);
      const call = await connect({
        CODEX_SECURITY_STATE_DIR: path.join(fixture, `state-${variable}`),
        [variable]: relative
      });
      const { scanDir } = await call("start_codex_security_standard_scan", { targetPath: repository });
      const expected = variable === "CODEX_SECURITY_SCAN_ROOT" ? destination : path.join(destination, "scans");
      assert.ok(scanDir.startsWith(path.join(expected, "repository") + path.sep), scanDir);
      if (variable === "CODEX_SECURITY_STATE_DIR") assert.ok((await fs.stat(path.join(destination, "workbench.sqlite3"))).isFile());
      const saved = await call("save_codex_security_artifact", {
        targetPath: repository, storage: "persistent", path: "threat_model.md", content: "relative root"
      });
      assert.ok(saved.directory.startsWith(expected + path.sep), saved.directory);
      assert.equal(await fs.readFile(saved.path, "utf8"), "relative root");
    });
  }
} finally {
  for (const client of clients) await client.close();
  for (const directory of temporaryDirectories) await fs.rm(directory, { recursive: true, force: true });
  await fs.rm(fixture, { recursive: true, force: true });
}
