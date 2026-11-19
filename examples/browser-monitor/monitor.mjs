import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { setTimeout } from "node:timers/promises";
import { format } from "node:util";

async function loadClient(configFile) {
  const { CodexSecurity, loadProjectConfig } =
    await import("@openai/codex-security");
  const { config, options } = await loadProjectConfig(configFile);
  return { security: new CodexSecurity(config), options };
}

async function runScan({ security, options }, state, signal) {
  const record = (field) => (value) => {
    state[field] = value;
  };
  function onWarning(message) {
    if (!state.warnings.includes(message)) state.warnings.push(message);
  }
  const result = await security.run(state.repository, {
    ...options,
    signal,
    onProgress: record("progress"),
    onDeepProgress: record("deepProgress"),
    onLifecycle: record("lifecycle"),
    onMeasurement: record("measurement"),
    onWarning,
  });
  const { target, warnings = [] } = result.manifest.scan;
  for (const warning of warnings) onWarning(warning);
  state.revision = target.revision ?? target.headRevision ?? null;
  state.findings = result.findings.findings;
  state.reportPath = result.reportPath;
  if (
    options.failureSeverity &&
    result.hasFindingsAtOrAbove(options.failureSeverity)
  ) {
    process.exitCode = 1;
  }
}

async function runDemo(state, signal) {
  state.lifecycle = { scanId: "synthetic-demo", status: "running" };
  const phases = ["preflight", "discovery", "reporting"];
  for (const [index, phase] of phases.entries()) {
    state.progress = { phase, filesCompleted: index, filesTotal: 2 };
    state.measurement = {
      coverage: "partial",
      observedAt: new Date().toISOString(),
      usage: { total_tokens: (index + 1) * 1000 },
      cost: { estimatedUsd: (index + 1) * 0.01 },
    };
    await setTimeout(1500, undefined, { signal });
  }
  state.lifecycle.status = "completed";
  state.findings = [
    {
      title: "Synthetic cross-workspace invoice access",
      summary: "An invoice lookup accepts another workspace’s invoice ID.",
      severity: { level: "high" },
      locations: [{ path: "app/invoices.mjs", startLine: 42 }],
    },
  ];
}

async function serveMonitor(state) {
  const nonce = randomBytes(24).toString("hex");
  const prefix = `/${randomBytes(24).toString("hex")}/`;
  const html = (
    await readFile(new URL("monitor.html", import.meta.url), "utf8")
  ).replaceAll("__NONCE__", nonce);
  const server = createServer(serve);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const host = `127.0.0.1:${server.address().port}`;
  const origin = `http://${host}`;

  function serve(request, response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`,
    );
    if (
      request.headers.host !== host ||
      (request.headers.origin !== undefined &&
        request.headers.origin !== origin)
    ) {
      response.writeHead(403).end();
    } else if (request.method !== "GET") {
      response.writeHead(405, { Allow: "GET" }).end();
    } else if (request.url === prefix) {
      response
        .writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
        .end(html);
    } else if (request.url === `${prefix}state`) {
      response
        .writeHead(200, { "Content-Type": "application/json; charset=utf-8" })
        .end(JSON.stringify(state));
    } else {
      response.writeHead(404).end();
    }
  }
  return { server, url: origin + prefix };
}

function reportError(error) {
  process.exitCode = 2;
  // Match the CLI's multiline terminal escaping after formatting nested causes.
  const diagnostic = format(error).replaceAll(
    /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\p{Bidi_Control}]/gu,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  console.error(diagnostic);
}

async function main() {
  const [repository, configFile, ...extra] = process.argv.slice(2);
  const demo = repository === "--demo";
  if (extra.length || (demo ? configFile : !repository || !configFile)) {
    throw new Error(
      "Usage: node monitor.mjs --demo | <repository> <trusted-project-config>",
    );
  }
  const client = demo ? null : await loadClient(configFile);
  const state = {
    repository: demo ? "Synthetic demo" : repository,
    demo,
    status: "running",
    startedAt: new Date().toISOString(),
    finishedAt: null,
    progress: null,
    deepProgress: null,
    lifecycle: null,
    measurement: null,
    revision: null,
    warnings: [],
    findings: null,
    reportPath: null,
    error: null,
  };
  const { server, url } = await serveMonitor(state);
  const controller = new AbortController();
  function stop(signal) {
    if (state.status === "running") {
      process.exitCode = signal === "SIGINT" ? 130 : 143;
      controller.abort();
    }
    server.close();
    server.closeAllConnections();
  }
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  console.log(`Monitor: ${url}`);
  console.log("Press Ctrl+C to stop the scan and server.");
  try {
    if (demo) await runDemo(state, controller.signal);
    else await runScan(client, state, controller.signal);
    state.status = "completed";
  } catch (error) {
    state.status = controller.signal.aborted ? "canceled" : "failed";
    state.error = error instanceof Error ? error.message : String(error);
    if (!controller.signal.aborted) reportError(error);
  } finally {
    state.finishedAt = new Date().toISOString();
    await client?.security.close();
  }
}

main().catch(reportError);
