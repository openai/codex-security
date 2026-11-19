import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { setTimeout } from "node:timers/promises";
import { pathToFileURL } from "node:url";

export async function createMonitor(repository, demo = false) {
  const nonce = randomBytes(24).toString("hex");
  const prefix = `/${randomBytes(24).toString("hex")}/`;
  const html = (
    await readFile(new URL("monitor.html", import.meta.url), "utf8")
  ).replaceAll("__NONCE__", nonce);
  const state = {
    repository,
    demo,
    status: "waiting",
    startedAt: null,
    finishedAt: null,
    progress: null,
    lifecycle: null,
    measurement: null,
    findings: null,
    reportPath: null,
    error: null,
  };
  const server = createServer((request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`,
    );
    if (
      request.headers.host !== new URL(origin).host ||
      (request.headers.origin && request.headers.origin !== origin)
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
  });
  await new Promise((done, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", done);
  });
  return {
    server,
    state,
    url: `http://127.0.0.1:${server.address().port}${prefix}`,
  };
}

export async function observeScan(security, repository, options, state) {
  state.status = "running";
  state.startedAt = new Date().toISOString();
  try {
    const result = await security.run(repository, {
      ...options,
      onProgress: (progress) => {
        state.progress = progress;
      },
      onLifecycle: (lifecycle) => {
        state.lifecycle = lifecycle;
      },
      onMeasurement: (measurement) => {
        state.measurement = measurement;
      },
    });
    state.findings = result.findings.findings;
    state.reportPath = result.reportPath;
    state.status = "completed";
    return result;
  } catch (error) {
    state.status = options.signal?.aborted ? "canceled" : "failed";
    state.error = error instanceof Error ? error.message : String(error);
    throw error;
  } finally {
    state.finishedAt = new Date().toISOString();
  }
}

export function demoSecurity() {
  return {
    async run(repository, { onProgress, onMeasurement, onLifecycle, signal }) {
      onLifecycle({ scanId: "synthetic-demo", status: "running" });
      for (const [index, phase] of [
        "preflight",
        "discovery",
        "reporting",
      ].entries()) {
        onProgress({ phase, filesCompleted: index, filesTotal: 3 });
        onMeasurement({
          coverage: "partial",
          observedAt: new Date().toISOString(),
          usage: { total_tokens: (index + 1) * 1000 },
          cost: { estimatedUsd: (index + 1) * 0.01 },
        });
        await setTimeout(1500, undefined, { signal });
      }
      onLifecycle({ scanId: "synthetic-demo", status: "completed" });
      return {
        reportPath: "Synthetic demo — no report written",
        findings: {
          findings: [
            {
              title: "Synthetic cross-workspace invoice access",
              summary:
                "An example finding for previewing the monitor. No repository was scanned.",
              severity: { level: "high" },
              locations: [{ path: "app/invoices.mjs", startLine: 42 }],
            },
          ],
        },
      };
    },
    async close() {},
  };
}

async function main() {
  const [repository, configFile, ...extra] = process.argv.slice(2);
  const demo = repository === "--demo";
  if (extra.length || (demo ? configFile : !repository || !configFile)) {
    throw new Error(
      "Usage: node monitor.mjs --demo | <repository> <trusted-project-config>",
    );
  }
  let security;
  let options = {};
  if (demo) {
    security = demoSecurity();
  } else {
    const { CodexSecurity, loadProjectConfig } =
      await import("@openai/codex-security");
    const loaded = await loadProjectConfig(resolve(configFile));
    security = new CodexSecurity(loaded.config);
    options = loaded.options;
  }
  const target = demo ? "Synthetic demo" : resolve(repository);
  const controller = new AbortController();
  const monitor = await createMonitor(target, demo);
  const stop = () => {
    if (monitor.state.status === "running") process.exitCode = 130;
    controller.abort();
    monitor.server.close();
    monitor.server.closeAllConnections();
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  console.log(`Monitor: ${monitor.url}`);
  console.log(
    "Read-only browser view. Press Ctrl+C to stop the scan and server.",
  );
  try {
    const result = await observeScan(
      security,
      target,
      { ...options, signal: controller.signal },
      monitor.state,
    );
    if (
      options.failureSeverity &&
      result.hasFindingsAtOrAbove(options.failureSeverity)
    )
      process.exitCode = 1;
  } catch (error) {
    if (!controller.signal.aborted) {
      process.exitCode = 2;
      console.error(error);
    }
  } finally {
    await security.close();
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 2;
  });
}
