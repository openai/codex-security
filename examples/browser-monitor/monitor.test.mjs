import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { get } from "node:http";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { createMonitor, observeScan } from "./monitor.mjs";

test(
  "demo entrypoint starts without SDK access and Ctrl+C cancels and closes it",
  {
    skip:
      process.platform === "win32"
        ? "process.kill does not deliver console Ctrl+C on Windows"
        : false,
  },
  async (t) => {
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL("monitor.mjs", import.meta.url)), "--demo"],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const exited = once(child, "exit");
    t.after(() => child.kill());
    let output = "";
    const url = await new Promise((done, fail) => {
      child.once("error", fail);
      child.once("exit", () =>
        fail(new Error(`Demo exited before listening: ${output}`)),
      );
      child.stdout.on("data", (chunk) => {
        output += chunk;
        const match = /Monitor: (http:\/\/127\.0\.0\.1:\d+\/\w+\/)/.exec(
          output,
        );
        if (match) done(match[1]);
      });
    });
    const response = await fetch(`${url}state`);
    const state = await response.json();
    assert.equal(state.demo, true);
    assert.equal(state.status, "running");
    child.kill("SIGINT");
    const [code, signal] = await exited;
    assert.equal(signal, null);
    assert.equal(code, 130);
    await assert.rejects(fetch(url));
  },
);

test("loopback monitor observes one scan, preserves unknown usage, and serves no actions", async (t) => {
  const monitor = await createMonitor("Synthetic repository");
  t.after(() => {
    monitor.server.closeAllConnections();
    return new Promise((done) => monitor.server.close(done));
  });
  let callbacks;
  let finish;
  let calls = 0;
  const security = {
    run(repository, options) {
      assert.equal(repository, "Synthetic repository");
      assert.equal(options.auth, "chatgpt");
      calls++;
      callbacks = options;
      return new Promise((done) => {
        finish = done;
      });
    },
  };
  const pending = observeScan(
    security,
    "Synthetic repository",
    { auth: "chatgpt" },
    monitor.state,
  );
  const snapshot = async () => (await fetch(`${monitor.url}state`)).json();
  assert.equal((await snapshot()).status, "running");
  assert.equal((await snapshot()).measurement, null);
  assert.equal((await snapshot()).findings, null);
  const html = await fetch(monitor.url);
  assert.equal(html.status, 200);
  assert.equal(html.headers.get("cache-control"), "no-store");
  assert.match(
    html.headers.get("content-security-policy"),
    /frame-ancestors 'none'/,
  );
  assert.doesNotMatch(await html.text(), /__NONCE__/);
  assert.equal((await fetch(monitor.url, { method: "POST" })).status, 405);
  assert.equal((await fetch(`${monitor.url}patch`)).status, 404);
  assert.equal((await fetch(new URL("/", monitor.url))).status, 404);
  const reboundStatus = await new Promise((done, fail) => {
    get(
      monitor.url,
      { headers: { Host: "other.example.test" } },
      (response) => {
        response.resume();
        done(response.statusCode);
      },
    ).once("error", fail);
  });
  assert.equal(reboundStatus, 403);
  assert.equal(
    (
      await fetch(`${monitor.url}state`, {
        headers: { Origin: "https://other.example.test" },
      })
    ).status,
    403,
  );
  callbacks.onProgress({
    phase: "discovery",
    reviewItems: { completed: 2, total: 4 },
  });
  callbacks.onMeasurement({
    coverage: "partial",
    observedAt: "2026-01-01T00:00:00Z",
    usage: { total_tokens: 0 },
    cost: null,
  });
  callbacks.onLifecycle({ scanId: "synthetic-scan", status: "running" });
  assert.equal((await snapshot()).measurement.cost, null);
  assert.equal((await snapshot()).measurement.usage.total_tokens, 0);
  assert.equal((await snapshot()).progress.reviewItems.completed, 2);
  finish({ findings: { findings: [] }, reportPath: "synthetic/report.md" });
  await pending;
  assert.equal((await snapshot()).status, "completed");
  assert.deepEqual((await snapshot()).findings, []);
  assert.ok((await snapshot()).finishedAt);
  await fetch(monitor.url);
  assert.equal(calls, 1);
});

test("failure and cancellation retain the last observations and original diagnostic", async () => {
  for (const aborted of [false, true]) {
    const controller = new AbortController();
    if (aborted) controller.abort();
    const state = {};
    const error = new Error("Synthetic failure <script>example()</script>");
    await assert.rejects(
      observeScan(
        {
          async run(_, options) {
            options.onMeasurement({
              coverage: "partial",
              usage: { total_tokens: 123 },
            });
            throw error;
          },
        },
        "Synthetic repository",
        { signal: controller.signal },
        state,
      ),
      (actual) => actual === error,
    );
    assert.equal(state.status, aborted ? "canceled" : "failed");
    assert.equal(state.error, error.message);
    assert.equal(state.measurement.usage.total_tokens, 123);
    assert.ok(state.finishedAt);
  }
});

test("browser renders findings as text, distinguishes zero and unknown, and retains a disconnected snapshot", async () => {
  const nodes = new Map();
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
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, node());
      return nodes.get(id);
    },
    createElement: node,
  };
  const title = '<img src=x onerror="globalThis.injected=true">';
  const state = {
    status: "completed",
    repository: "Synthetic repository",
    demo: true,
    startedAt: "2026-01-01T00:00:00Z",
    finishedAt: "2026-01-01T00:01:00Z",
    progress: { phase: "reporting", reviewItems: { completed: 2, total: 4 } },
    measurement: {
      coverage: "partial",
      observedAt: "2026-01-01T00:01:00Z",
      usage: { total_tokens: 0 },
      cost: { estimatedUsd: 0 },
    },
    findings: [
      {
        title,
        summary: title,
        severity: { level: "high" },
        locations: [{ path: title, startLine: 42 }],
      },
    ],
    lifecycle: null,
    error: title,
    reportPath: "synthetic/report.md",
  };
  const html = await readFile(new URL("monitor.html", import.meta.url), "utf8");
  let scheduled;
  let connected = true;
  const context = {
    document,
    fetch: async () => {
      if (!connected) throw new Error("Synthetic disconnect");
      return { ok: true, json: async () => state };
    },
    setTimeout: (callback) => {
      scheduled = callback;
    },
    setInterval: () => {},
  };
  runInNewContext(
    html.match(/<script nonce="__NONCE__">([\s\S]*?)<\/script>/)[1],
    context,
  );
  await new Promise(setImmediate);
  assert.equal(nodes.get("tokens").textContent, "0");
  assert.equal(nodes.get("cost").textContent, "$0.0000");
  assert.equal(nodes.get("elapsed").textContent, "1m 0s");
  assert.equal(nodes.get("progress").textContent, "Review items: 2 / 4");
  assert.match(nodes.get("measurement").textContent, /partial/);
  assert.equal(nodes.get("error").textContent, title);
  assert.equal(
    nodes.get("findings").children[0].children[0].children[0].textContent,
    `HIGH · ${title}`,
  );
  assert.equal(context.injected, undefined);
  state.measurement.cost = { estimatedUsdRange: { min: 1, max: null } };
  await scheduled();
  assert.equal(nodes.get("cost").textContent, "≥ $1.0000");
  state.measurement = null;
  await scheduled();
  assert.equal(nodes.get("tokens").textContent, "Unknown");
  assert.equal(nodes.get("cost").textContent, "Unknown");
  assert.equal(nodes.get("findings").children.length, 1);
  connected = false;
  await scheduled();
  assert.match(nodes.get("connection").textContent, /disconnected/);
  assert.equal(nodes.get("status").textContent, "completed");
});
