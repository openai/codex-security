import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createRequire } from "node:module";
import { promises as fs } from "node:fs";
import { tmpdir, userInfo } from "node:os";
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
  nodePaths: [fileURLToPath(new URL("../node_modules", import.meta.url))],
  define: { __dirname: JSON.stringify(applicationRoot), "import.meta.url": "__filename" },
  entryPoints: [path.join(applicationRoot, "main.ts")],
  external: ["fsevents"], format: "cjs", loader: { ".md": "text" },
  logLevel: "silent", outfile: bundle, platform: "node"
});
await build({
  bundle: true, format: "cjs", platform: "node", logLevel: "silent", outfile: helpers,
  stdin: { resolveDir: applicationRoot, contents: `
    export { readCodexSecurityArtifact, saveCodexSecurityArtifact, standaloneArtifactContext } from './src/artifact-storage.ts';
    export { createScanArtifactContext } from './src/artifact-context.ts';
  ` }
});
const { readCodexSecurityArtifact, saveCodexSecurityArtifact, standaloneArtifactContext, createScanArtifactContext } = createRequire(import.meta.url)(helpers);

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
  await test("binary imports and readback preserve files larger than the workbench JSON buffer", async () => {
    const call = await connect();
    const location = { targetPath: repository };
    const scratch = await call("save_codex_security_artifact", { ...location, storage: "temporary" });
    temporaryDirectories.push(scratch.directory);
    const binary = Buffer.alloc(3 * 1024 * 1024 + 1, 0xa5);
    const sourcePath = path.join(scratch.directory, "large.bin");
    await fs.writeFile(sourcePath, binary);
    const saved = await call("save_codex_security_artifact", {
      ...location, storage: "persistent", path: "artifacts/large.bin", sourcePath
    });
    assert.deepEqual(await fs.readFile(saved.path), binary);
    const read = await call("read_codex_security_artifact", {
      ...location, storage: "persistent", path: saved.relativePath, encoding: "base64"
    });
    assert.deepEqual(Buffer.from(read.content, "base64"), binary);
  });

  for (const reader of ["import", "temporary", "persistent"]) {
    for (const replacement of ["parent", "file"]) {
      await test(`${reader} reads stay bound when the ${replacement} is replaced`, { skip: process.platform === "win32" }, async () => {
        const context = await standaloneArtifactContext(repository, workbench, true, path.join(fixture, `read-${reader}-${replacement}`), "persistent");
        const storage = reader === "import" ? "temporary" : reader;
        const artifact = "artifacts/nested/proof.bin";
        const source = await saveCodexSecurityArtifact(context, { storage, path: artifact, content: "original evidence" }, workbench);
        if (storage === "temporary") temporaryDirectories.push(source.directory);
        const parent = path.dirname(source.path);
        const moved = path.join(path.dirname(parent), "original");
        const outside = path.join(fixture, `outside-read-${reader}-${replacement}`);
        const marker = path.join(fixture, `read-swapped-${reader}-${replacement}`);
        await fs.mkdir(outside);
        await fs.writeFile(path.join(outside, "proof.bin"), "unrelated outside bytes");
        const launcher = path.join(fixture, `read-${reader}-${replacement}.py`);
        await fs.writeFile(launcher, `
import os, runpy, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent))
import finalize_scan_contract as finalizer
original_open = finalizer._open_scan_local_directory
def open_then_replace(root_fd, parts, *, create):
    descriptor = original_open(root_fd, parts, create=create)
    if not create and parts == ("artifacts", "nested"):
        if ${JSON.stringify(replacement)} == "parent":
            os.rename(${JSON.stringify(parent)}, ${JSON.stringify(moved)})
            os.symlink(${JSON.stringify(outside)}, ${JSON.stringify(parent)})
        else:
            os.unlink(${JSON.stringify(source.path)})
            os.symlink(${JSON.stringify(path.join(outside, "proof.bin"))}, ${JSON.stringify(source.path)})
        Path(${JSON.stringify(marker)}).write_text("python")
    return descriptor
finalizer._open_scan_local_directory = open_then_replace
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`);
        const run = (args, input) => workbench(args, input, launcher);
        const read = async () => {
          if (reader === "import") {
            const saved = await saveCodexSecurityArtifact(context, {
              storage: "persistent", path: "artifacts/imported.bin", sourcePath: source.path
            }, run);
            return await fs.readFile(saved.path, "utf8");
          }
          return (await readCodexSecurityArtifact(context, { storage, path: artifact, encoding: "utf8" }, run)).content;
        };
        if (replacement === "file") await assert.rejects(read, /expected a (?:regular|file inside)/);
        else assert.equal(await read(), "original evidence");
        assert.equal(await fs.readFile(marker, "utf8"), "python");
        assert.equal(await fs.readFile(path.join(outside, "proof.bin"), "utf8"), "unrelated outside bytes");
      });
    }
  }

  for (const writer of ["mcp", "workbench"]) {
    await test(`${writer} rejects reserved artifact names and their descendants`, async () => {
      const call = await connect();
      const { scanId, handoffClaimToken } = await call("start_codex_security_standard_scan", { targetPath: repository });
      for (const reserved of [
        "artifacts/02_discovery/candidate_ledger.jsonl",
        "artifacts/02_discovery/in_scope_files.txt",
        "artifacts/01_context/false_positive_feedback.json",
        "artifacts/deep_discovery"
      ]) {
        for (const suffix of ["/note.txt", ""]) {
          const artifact = reserved + suffix;
          await assert.rejects(() => writer === "mcp"
            ? call("save_codex_security_artifact", { scanId, handoffClaimToken, storage: "persistent", path: artifact, content: "reserved" })
            : workbench(["save-scan-artifact", "--scan-id", scanId, "--claim-token", handoffClaimToken, "--artifact-path", artifact], "reserved"),
          /canonical artifacts/);
        }
        const artifact = reserved + ".backup";
        const saved = writer === "mcp"
          ? await call("save_codex_security_artifact", { scanId, handoffClaimToken, storage: "persistent", path: artifact, content: "allowed sibling" })
          : await workbench(["save-scan-artifact", "--scan-id", scanId, "--claim-token", handoffClaimToken, "--artifact-path", artifact], "allowed sibling");
        assert.equal(await fs.readFile(saved.path, "utf8"), "allowed sibling");
      }
    });
  }

  for (const kind of ["missing", "blocked", "alias", "read-only"]) {
    await test(`standalone temporary storage works with persistent root: ${kind}`, { skip: kind === "read-only" && process.platform === "win32" }, async () => {
      const parent = path.join(fixture, `temporary-${kind}`);
      let scanRoot = path.join(parent, "scans");
      if (kind === "blocked") await fs.writeFile(parent, "unavailable storage");
      if (kind === "alias" || kind === "read-only") await fs.mkdir(parent);
      if (kind === "alias") {
        const alias = path.join(fixture, "temporary-alias-link");
        await fs.symlink(parent, alias, process.platform === "win32" ? "junction" : "dir");
        scanRoot = path.join(alias, "scans");
      }
      if (kind === "read-only") await fs.chmod(parent, 0o500);
      try {
        const overrides = { CODEX_SECURITY_SCAN_ROOT: scanRoot };
        let call = await connect(overrides);
        const location = { targetPath: repository, storage: "temporary" };
        const { directory } = await call("save_codex_security_artifact", location);
        temporaryDirectories.push(directory);
        assert.equal(path.dirname(directory), await fs.realpath(tmpdir()));
        const saved = await call("save_codex_security_artifact", { ...location, path: "note.txt", content: "temporary evidence\n" });
        assert.equal(saved.directory, directory);
        assert.equal(await fs.readFile(saved.path, "utf8"), "temporary evidence\n");
        await clients.at(-1).close();
        call = await connect(overrides);
        assert.equal((await call("read_codex_security_artifact", { ...location, path: "note.txt" })).content, "temporary evidence\n");
        if (kind === "blocked") {
          assert.equal(await fs.readFile(parent, "utf8"), "unavailable storage");
          await fs.unlink(parent);
        } else {
          await assert.rejects(fs.stat(scanRoot), { code: "ENOENT" });
        }
        if (kind === "read-only") await fs.chmod(parent, 0o700);
        const imported = await call("save_codex_security_artifact", {
          targetPath: repository, storage: "persistent", path: "artifacts/note.txt", sourcePath: saved.path
        });
        assert.equal(await fs.readFile(imported.path, "utf8"), "temporary evidence\n");
        assert.equal((await call("read_codex_security_artifact", { ...location, path: "note.txt" })).directory, directory);
      } finally {
        if (kind === "read-only") await fs.chmod(parent, 0o700);
      }
    });
  }

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
      const context = await standaloneArtifactContext(repository, workbench, true, path.join(fixture, `swap-${storage}`), storage);
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
      // Replace the pathname after Python opens the parent, using real I/O
      // without relying on race timing.
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
      await saveCodexSecurityArtifact(context, { ...location, path: "artifacts/nested/proof.bin", content: "new artifact" },
        (args, input) => workbench(args, input, launcher));
      assert.equal(await fs.readFile(marker, "utf8"), "python");
      assert.equal(await fs.readFile(path.join(outside, "proof.bin"), "utf8"), "outside remains unchanged");
      assert.equal(await fs.readFile(path.join(moved, "proof.bin"), "utf8"), "new artifact");
    });
  }

  for (const variable of ["CODEX_SECURITY_SCAN_ROOT", "CODEX_SECURITY_STATE_DIR", "CODEX_HOME"]) {
    await test(`${variable} expands named-user paths for scans and standalone artifacts`, { skip: process.platform === "win32" }, async () => {
      const account = userInfo();
      const destination = path.join(fixture, `named-${variable}`);
      const configured = `~${account.username}/${path.relative(account.homedir, destination)}`;
      temporaryDirectories.push(path.resolve(pluginRoot, configured));
      const state = variable === "CODEX_HOME"
        ? path.join(destination, "state", "plugins", "codex-security")
        : variable === "CODEX_SECURITY_STATE_DIR" ? destination : path.join(fixture, `named-state-${variable}`);
      const expected = variable === "CODEX_SECURITY_SCAN_ROOT" ? destination : path.join(state, "scans");
      const call = await connect({
        CODEX_SECURITY_STATE_DIR: variable === "CODEX_HOME" ? undefined : state,
        [variable]: configured
      });
      const { scanDir } = await call("start_codex_security_standard_scan", { targetPath: repository });
      assert.ok(scanDir.startsWith(path.join(expected, "repository") + path.sep), scanDir);
      assert.ok((await fs.stat(path.join(state, "workbench.sqlite3"))).isFile());
      const location = { targetPath: repository, storage: "persistent", path: "threat_model.md" };
      const saved = await call("save_codex_security_artifact", { ...location, content: "named-user root\n" });
      assert.ok(saved.directory.startsWith(expected + path.sep), saved.directory);
      assert.equal(await fs.readFile(saved.path, "utf8"), "named-user root\n");
      assert.equal((await call("read_codex_security_artifact", location)).content, "named-user root\n");
    });

    await test(`${variable} keeps the workbench base when MCP starts in another directory`, async () => {
      const relative = `.${path.basename(fixture)}-${variable}`;
      const destination = path.join(pluginRoot, relative);
      temporaryDirectories.push(destination);
      const call = await connect({
        CODEX_SECURITY_STATE_DIR: variable === "CODEX_HOME" ? undefined : path.join(fixture, `state-${variable}`),
        [variable]: relative
      });
      const { scanDir } = await call("start_codex_security_standard_scan", { targetPath: repository });
      const expected = variable === "CODEX_SECURITY_SCAN_ROOT" ? destination
        : variable === "CODEX_SECURITY_STATE_DIR" ? path.join(destination, "scans")
        : path.join(destination, "state", "plugins", "codex-security", "scans");
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
