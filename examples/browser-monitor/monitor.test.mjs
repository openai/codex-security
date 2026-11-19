import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { get } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { text } from "node:stream/consumers";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const demo = [fileURLToPath(new URL("monitor.mjs", import.meta.url)), "--demo"];

async function startMonitor(t, args = demo) {
  const child = spawn(process.execPath, args, {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const exited = once(child, "close");
  t.after(async () => {
    child.kill();
    await exited;
  });
  const stderr = text(child.stderr);
  const [line] = await Promise.race([
    once(createInterface({ input: child.stdout }), "line"),
    exited.then(async () => {
      throw new Error(`Monitor exited before listening: ${await stderr}`);
    }),
  ]);
  const match = /^Monitor: (http:\/\/127\.0\.0\.1:\d+\/\w+\/)$/.exec(line);
  assert.ok(match, line);
  const url = match[1];
  const snapshot = async () => (await fetch(`${url}state`)).json();
  return { child, exited, url, stderr, snapshot };
}

async function startScan(t, repository, config) {
  const root = await mkdtemp(join(tmpdir(), "browser-monitor-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const example = join(root, "example");
  const sdk = join(example, "node_modules", "@openai", "codex-security");
  await mkdir(sdk, { recursive: true });
  for (const name of ["monitor.mjs", "monitor.html"]) {
    await copyFile(new URL(name, import.meta.url), join(example, name));
  }
  await writeFile(
    join(sdk, "index.js"),
    `let calls = 0;
    exports.loadProjectConfig = file => ({ options: { scanPromptFile: file } });
    exports.CodexSecurity = class {
      run(repo, options) {
        options.onMeasurement({ coverage: "partial", usage: { total_tokens: 0 }, cost: null });
        if (options.scanPromptFile !== "success.yaml") {
          throw new Error(repo + "\\u001b[2J" + options.scanPromptFile);
        }
        options.onProgress({ phase: "discovery", reviewItems: { completed: 2, total: 4 } });
        options.onDeepProgress({ completed: 1, active: 0, maximum: 2 });
        options.onLifecycle({ scanId: "scan-" + ++calls, status: "completed" });
        options.onWarning("source changed");
        return {
          manifest: { scan: {
            target: { headRevision: "abc123" }, warnings: ["source changed", "partial coverage"]
          } },
          reportPath: "report.md",
          findings: { findings: [] },
        };
      }
      close() {}
    };`,
  );
  const alias = join(root, "alias");
  await symlink(example, alias, "junction");
  return startMonitor(t, [join(alias, "monitor.mjs"), repository, config]);
}

test("SDK callbacks and completed results survive reloading the same scan", async (t) => {
  const { snapshot, url } = await startScan(t, "source", "success.yaml");
  const state = await snapshot();
  assert.equal(state.status, "completed");
  assert.ok(state.finishedAt);
  assert.deepEqual(state.lifecycle, { scanId: "scan-1", status: "completed" });
  assert.equal(state.progress.reviewItems.completed, 2);
  assert.equal(state.deepProgress.completed, 1);
  assert.equal(state.measurement.cost, null);
  assert.equal(state.revision, "abc123");
  assert.deepEqual(state.warnings, ["source changed", "partial coverage"]);
  assert.deepEqual(state.findings, []);
  assert.equal(state.reportPath, "report.md");
  await fetch(url);
  assert.deepEqual(await snapshot(), state);
});

test("SDK failure retains the original paths and measurement, escaping controls on stderr", async (t) => {
  const repo = "~/source";
  const file = "link/../scan.yaml";
  const { child, exited, snapshot, stderr } = await startScan(t, repo, file);
  const state = await snapshot();
  child.kill();
  await exited;
  assert.equal(state.status, "failed");
  assert.ok(state.finishedAt);
  assert.equal(state.findings, null);
  assert.equal(state.measurement.usage.total_tokens, 0);
  assert.equal(state.error, `${repo}\u001b[2J${file}`);
  const diagnostic = await stderr;
  assert.ok(diagnostic.includes(`${repo}\\u001b[2J${file}`));
  assert.ok(!diagnostic.includes("\u001b"));
});

for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  test(
    `demo entrypoint cancels and closes on ${signal}`,
    { skip: process.platform === "win32" && "requires POSIX signal delivery" },
    async (t) => {
      const { child, exited, url, snapshot } = await startMonitor(t);
      const state = await snapshot();
      assert.equal(state.demo, true);
      assert.equal(state.status, "running");
      child.kill(signal);
      assert.deepEqual(await exited, [code, null]);
      await assert.rejects(fetch(url));
    },
  );
}

test("loopback server only serves reads on its private paths", async (t) => {
  const { url } = await startMonitor(t);
  const html = await fetch(url);
  assert.equal(html.status, 200);
  assert.equal(html.headers.get("cache-control"), "no-store");
  assert.match(
    html.headers.get("content-security-policy"),
    /frame-ancestors 'none'/,
  );
  assert.doesNotMatch(await html.text(), /__NONCE__/);
  assert.equal((await fetch(url, { method: "POST" })).status, 405);
  assert.equal((await fetch(`${url}patch`)).status, 404);
  assert.equal((await fetch(new URL("/", url))).status, 404);
  const [response] = await once(
    get(url, { headers: { Host: "other.example.test" } }),
    "response",
  );
  response.resume();
  assert.equal(response.statusCode, 403);
  const foreign = await fetch(`${url}state`, {
    headers: { Origin: "https://other.example.test" },
  });
  assert.equal(foreign.status, 403);
});

test("browser follows progress, retries disconnects and stops at the final snapshot", async () => {
  const nodes = {};
  const node = () => ({
    textContent: "",
    children: [],
    append(...items) {
      this.children.push(...items);
    },
    set innerHTML(_) {
      throw new Error("Untrusted text must not become HTML");
    },
  });
  const title = '<img src=x onerror="globalThis.injected=true">';
  const state = {
    status: "running",
    repository: "Synthetic repository",
    warnings: [title],
    startedAt: "2026-01-01T00:00:00Z",
    progress: {
      phase: "discovery",
      filesCompleted: 1,
      filesTotal: 3,
      reviewItems: { completed: 0, total: 0 },
    },
    measurement: {
      coverage: "partial",
      observedAt: "2026-01-01T00:01:00Z",
      usage: { total_tokens: 0 },
      cost: { estimatedUsd: 0 },
    },
  };
  const html = await readFile(new URL("monitor.html", import.meta.url), "utf8");
  const pending = [];
  const refresh = () => pending.shift()();
  let connected = true;
  await runInNewContext(
    html.match(/<script nonce="__NONCE__">([\s\S]*?)<\/script>/)[1],
    {
      document: {
        getElementById: (id) => (nodes[id] ??= node()),
        createElement: node,
      },
      fetch: async () => {
        if (!connected) throw new Error("Synthetic disconnect");
        return { ok: true, json: async () => state };
      },
      setTimeout: (callback) => pending.push(callback),
    },
  );
  assert.equal(nodes.progress.textContent, "Files: 1 / 3");
  assert.equal(nodes.tokens.textContent, "0");
  assert.equal(nodes.cost.textContent, "$0.0000");
  assert.match(nodes.measurement.textContent, /partial/);
  assert.equal(nodes.warnings.textContent, `Warnings\n${title}`);

  connected = false;
  await refresh();
  assert.match(nodes.connection.textContent, /disconnected/);
  assert.equal(nodes.status.textContent, "running");

  connected = true;
  state.measurement.cost = { estimatedUsdRange: { min: 1, max: null } };
  state.progress.reviewItems = { completed: 2, total: 4 };
  state.deepProgress = {
    completed: 3,
    active: 0,
    maximum: 8,
    consolidating: true,
  };
  await refresh();
  assert.equal(nodes.connection.textContent, "");
  assert.equal(nodes.cost.textContent, "≥ $1.0000");
  assert.equal(nodes.progress.textContent, "Review items: 2 / 4");
  assert.match(nodes.deep.textContent, /3 completed, 0 active, cap 8/);
  assert.equal(nodes.phase.textContent, "consolidating results");

  state.measurement = null;
  state.revision = "synthetic-revision";
  state.findings = [
    {
      title,
      summary: title,
      severity: { level: "high" },
      locations: [{ path: title, startLine: 42 }],
    },
  ];
  state.status = "completed";
  state.finishedAt = "2026-01-01T00:01:00Z";
  await refresh();
  assert.equal(nodes.tokens.textContent, "Unknown");
  assert.equal(nodes.cost.textContent, "Unknown");
  assert.equal(nodes.elapsed.textContent, "1m 0s");
  assert.match(nodes.revision.textContent, /synthetic-revision/);
  assert.equal(
    nodes.findings.children[0].children[0].textContent,
    `HIGH · ${title}`,
  );
  assert.equal(pending.length, 0);
});
