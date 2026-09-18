import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const applicationRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pluginRoot = path.resolve(applicationRoot, "..");
const bundledPluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : path.resolve(applicationRoot, "../../../sdk/typescript/_bundled_plugin");
const originalContextText = "Loaded Codex Security scan context.";
const temporaryRoot = await realpath(await mkdtemp(path.join(tmpdir(), "codex-security-scan-guidance-")));

try {
  const sourceRuntime = path.join(temporaryRoot, "server.cjs");
  await build({
    bundle: true,
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": "__filename"
    },
    entryPoints: [path.join(applicationRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    logOverride: { "empty-import-meta": "silent" },
    outfile: sourceRuntime,
    platform: "node",
    target: "node20"
  });

  await testScanGuidance(sourceRuntime, pluginRoot, "source");
  await testScanGuidance(
    path.join(bundledPluginRoot, "mcp", "server.mjs"),
    bundledPluginRoot,
    "shipped"
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function testScanGuidance(runtime, runtimePluginRoot, runtimeLabel) {
  const fixtureRoot = path.join(temporaryRoot, runtimeLabel);
  const repoRoot = path.join(fixtureRoot, "repository");
  const stateRoot = path.join(fixtureRoot, "state");
  const scanRoot = path.join(fixtureRoot, "scans");
  await Promise.all([
    mkdir(path.join(repoRoot, "web"), { recursive: true }),
    mkdir(path.join(repoRoot, "ignored"), { recursive: true }),
    mkdir(stateRoot, { recursive: true }),
    mkdir(scanRoot, { recursive: true })
  ]);
  await Promise.all([
    writeFile(path.join(repoRoot, "web", "handler.py"), "# Rust unsafe review: native/lib.rs\n"),
    writeFile(path.join(repoRoot, "ignored", "library.rs"), "pub fn ignored() {}\n"),
    writeFile(path.join(repoRoot, ".gitignore"), "ignored/\n")
  ]);
  const git = (...arguments_) => execFileSync("git", [
    "-c", "user.name=Fixture",
    "-c", "user.email=fixture@example.com",
    ...arguments_
  ], { cwd: repoRoot, encoding: "utf8" }).trim();
  git("init", "-q");
  git("add", ".");
  git("commit", "-qm", "non-Rust fixture");

  const client = new Client({ name: "codex-security-scan-guidance-test", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [runtime, "--stdio"],
    cwd: applicationRoot,
    env: {
      ...process.env,
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
      CODEX_SECURITY_STATE_DIR: stateRoot
    }
  });
  await client.connect(transport);
  try {
    const nonRust = await startScan("non-rust-repository", ".");
    await checkContext(nonRust, false);

    // An empty, untracked Rust file is enough: guidance follows inventory paths,
    // not Rust syntax, unsafe keywords, or only committed source.
    await mkdir(path.join(repoRoot, "native"));
    const rustPath = path.join(repoRoot, "native", "lib.rs");
    await writeFile(rustPath, "");
    const mixed = await startScan("mixed-repository", ".");
    await checkContext(mixed, true);

    const nonRustScope = await startScan("non-rust-subdirectory", "web");
    await checkContext(nonRustScope, false);

    const nonRustFiles = await registerScan("non-rust-sdk-paths", ["web/handler.py", ".gitignore"]);
    await checkContext(nonRustFiles, false);

    const rustFile = await registerScan("rust-single-file", ["native/lib.rs"]);
    const emptySourceContext = await checkContext(rustFile, true);
    await writeFile(rustPath, "pub unsafe fn changed_source() {}\n");
    const changedSourceContext = await checkContext(rustFile, true);
    assert.deepEqual(
      changedSourceContext.content,
      emptySourceContext.content,
      `${runtimeLabel}: changing source contents must not change guidance`
    );
    await writeFile(rustPath, "");

    requireSuccessfulTool(await rustFile.call("record_codex_security_scan_draft", {
      scanId: rustFile.scanId,
      handoffClaimToken: rustFile.handoffClaimToken,
      findings: [],
      coverage: {
        completeness: "complete",
        surfaces: [{ label: "Rust source fixture", disposition: "rejected" }],
        explicitExclusions: [],
        deferred: []
      }
    }), `${runtimeLabel}: record completed fixture draft`);
    const completed = requireSuccessfulTool(await rustFile.call("complete_codex_security_scan", {
      scanId: rustFile.scanId,
      handoffClaimToken: rustFile.handoffClaimToken
    }), `${runtimeLabel}: complete fixture scan`);
    assert.equal(completed.scan.progress.status, "complete");
    await rm(repoRoot, { recursive: true, force: true });
    const historical = await checkContext(rustFile, false);
    assert.equal(historical.structuredContent.scan.progress.status, "complete");
  } finally {
    await client.close();
  }

  async function startScan(label, scope) {
    const threadId = `scan-guidance-${runtimeLabel}-${label}`;
    const call = (name, arguments_) => client.callTool({
      name,
      arguments: arguments_,
      _meta: { "openai/threadId": threadId }
    });
    const selection = { targetPath: repoRoot, scope, mode: "standard" };
    const opened = requireSuccessfulTool(
      await call("open_codex_security_workspace", selection),
      `${runtimeLabel}/${label}: open workspace`
    );
    const sessionId = opened.workspace.id;
    requireSuccessfulTool(
      await call("submit_codex_security_setup", { ...selection, sessionId }),
      `${runtimeLabel}/${label}: submit setup`
    );
    const started = requireSuccessfulTool(
      await call("start_codex_security_scan", { sessionId }),
      `${runtimeLabel}/${label}: start scan`
    );
    const scanId = started.workspace.results.scanId;
    const handoffClaimToken = randomUUID();
    requireSuccessfulTool(await call("claim_codex_security_scan_handoff_delivery", {
      scanId,
      claimToken: handoffClaimToken
    }), `${runtimeLabel}/${label}: claim handoff`);
    requireSuccessfulTool(await call("attach_codex_security_scan_continuation_thread", {
      scanId,
      claimToken: handoffClaimToken,
      threadId
    }), `${runtimeLabel}/${label}: attach owner`);
    return { call, label, scanId, handoffClaimToken };
  }

  async function registerScan(label, paths) {
    const scanDirectory = path.join(scanRoot, label);
    await mkdir(scanDirectory, { mode: 0o700 });
    const threadId = `scan-guidance-${runtimeLabel}-${label}`;
    const workbench = (...arguments_) => JSON.parse(execFileSync(
      process.env.PYTHON?.trim() || "python3",
      [path.join(runtimePluginRoot, "scripts", "workbench_db.py"), ...arguments_],
      {
        encoding: "utf8",
        env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateRoot }
      }
    ));
    const registered = workbench(
      "register-cli-scan",
      "--scan-dir", scanDirectory,
      "--repository", repoRoot,
      "--recipe-json", JSON.stringify({
        config: {},
        mode: "standard",
        repository: repoRoot,
        target: { kind: "paths", paths }
      })
    );
    workbench("set-scan-thread", "--scan-id", registered.scanId, "--thread-id", threadId);
    const call = (name, arguments_) => client.callTool({
      name,
      arguments: arguments_,
      _meta: { "openai/threadId": threadId }
    });
    return { call, label, scanId: registered.scanId };
  }

  async function checkContext(scan, expectsRustGuidance) {
    const label = `${runtimeLabel}/${scan.label}`;
    const context = await scan.call("get_codex_security_scan_context", {
      scanId: scan.scanId,
      handoffClaimToken: scan.handoffClaimToken
    });
    const structured = requireSuccessfulTool(context, `${label}: load context`);
    assert.equal(context.content.length, 1, `${label}: preserve one text block`);
    assert.equal(context.content[0].type, "text");
    const text = context.content[0].text;
    if (expectsRustGuidance) {
      assert.ok(text.startsWith(`${originalContextText}\n\n`), `${label}: append to original text`);
      const skillPath = path.join(runtimePluginRoot, "skills", "unsafe-rust-review", "SKILL.md");
      assert.ok(path.isAbsolute(skillPath));
      assert.ok(
        text.match(/"(?:[^"\\]|\\.)*"/g)?.some((quoted) => JSON.parse(quoted) === skillPath),
        `${label}: name the runtime's absolute Rust skill path`
      );
      const guidance = text.slice(originalContextText.length);
      assert.match(guidance, /supplement/i, `${label}: methodology supplements the scan workflow`);
      assert.match(guidance, /read/i, `${label}: instruct the reviewer to read the methodology`);
    } else {
      assert.equal(text, originalContextText, `${label}: preserve original context text exactly`);
    }

    const persisted = requireSuccessfulTool(
      await scan.call("get_codex_security_scan", { scanId: scan.scanId }),
      `${label}: read persisted scan`
    );
    delete persisted.scan.handoffClaimToken;
    delete persisted.workspace.results.handoffClaimToken;
    assert.deepEqual(structured, persisted, `${label}: preserve the structured context contract`);
    return context;
  }
}

function requireSuccessfulTool(result, label) {
  assert.notEqual(result.isError, true, `${label}: ${result.content?.[0]?.text ?? "tool failed"}`);
  assert.ok(result.structuredContent, `${label}: missing structured result`);
  return result.structuredContent;
}
