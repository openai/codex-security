import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const entrypoint = fileURLToPath(new URL("../server.ts", import.meta.url));
const bundle = await build({
  bundle: true,
  entryPoints: [entrypoint],
  define: { __dirname: JSON.stringify(dirname(entrypoint)) },
  format: "cjs",
  platform: "node",
  write: false,
  plugins: [
    {
      name: "native-stop-boundaries",
      setup(build) {
        const modules = {
          "@modelcontextprotocol/sdk/server/mcp.js": `
          export class McpServer {
            server = {};
            tools = new Map();
            registerTool(name, _config, handler) { this.tools.set(name, handler); }
            async close() {}
          }`,
          "./src/native-scan.js": `
          export class NativeScanHost {
            run(...args) { return fixture.run(...args); }
            cancel(...args) { return fixture.cancel(...args); }
            wait(...args) { return fixture.wait(...args); }
            async close() {}
          }`,
          "./src/python_command.js": `
          export async function resolvePythonCommand() { return "fixture-python"; }
          export function missingPythonHelperMessage() {}
          export async function runPythonWithInput() { throw new Error("unexpected artifact Python invocation"); }
          export function workbenchCommandTimeout() { return 30000; }`,
          "../../../sdk/typescript/src/scan-execution.js": `
          export const ScanPermissionError = fixture.ScanPermissionError;
          export const acquireScanExecution = (...args) => fixture.acquire?.(...args) ?? Promise.resolve(() => {});`,
          "node:child_process": `
          import { PassThrough } from "node:stream";
          export function execFile() {}
          execFile[Symbol.for("nodejs.util.promisify.custom")] = () => {
            const stdin = new PassThrough();
            let input = "";
            const result = new Promise((resolve, reject) => {
              stdin.on("data", chunk => { input += chunk; });
              stdin.on("end", () => Promise.resolve().then(() => fixture.workbench(JSON.parse(input.split("\\n")[0]).flatMap(argument => {
                  const split = argument.startsWith("--") ? argument.indexOf("=") : -1;
                  return split < 0 ? [argument] : [argument.slice(0, split), argument.slice(split + 1)];
                })))
                .then(value => resolve({ stdout: JSON.stringify(value) }), reject));
            });
            return Object.assign(result, { child: { stdin } });
          };`,
        };
        build.onResolve({ filter: /.*/ }, ({ path }) =>
          Object.hasOwn(modules, path)
            ? { path, namespace: "fixture" }
            : path.endsWith("/python_command.js")
              ? { path: "./src/python_command.js", namespace: "fixture" }
              : undefined,
        );
        build.onLoad({ filter: /.*/, namespace: "fixture" }, ({ path }) => ({
          contents: modules[path],
        }));
      },
    },
  ],
});

function serverFor(fixture) {
  fixture.ScanPermissionError = class ScanPermissionError extends Error {};
  const workbench = fixture.workbench.bind(fixture);
  fixture.workbench = (args) =>
    args[0] === "database-info"
      ? Promise.resolve({ databasePath: "/synthetic/state/workbench.sqlite3" })
      : workbench(args);
  const module = { exports: {} };
  new Function(
    "require",
    "module",
    "exports",
    "fixture",
    bundle.outputFiles[0].text,
  )(createRequire(import.meta.url), module, module.exports, fixture);
  return module.exports.createCodexSecurityServer();
}

for (const entry of [
  "completed",
  "run-success",
  "read-error",
  "run-error",
  "permission-error",
]) {
  test(`native ${entry} preserves completion and permission errors`, async () => {
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status: entry === "completed" ? "complete" : "running" },
      reportAvailable: false,
    };
    let runs = 0;
    let validations = 0;
    const server = serverFor({
      async workbench([command, ...args]) {
        if (command === "list-scans") return {};
        if (command === "resolve-scan-root")
          return { scanRoot: "/synthetic/scans" };
        if (command === "begin-deep-scan") return { scan };
        assert.equal(args[args.indexOf("--scan-id") + 1], scan.scanId);
        if (command === "get-scan") {
          if (entry === "read-error")
            throw new Error("synthetic saved metadata unavailable");
          return {
            scan: {
              ...scan,
              progress: { status: "complete" },
              usage: {
                coverage: "unavailable",
                reason: "codex_state_unavailable",
              },
              warnings: ["synthetic completion warning"],
            },
          };
        }
        assert.equal(command, "complete-scan");
        assert.equal(
          args[args.indexOf("--claim-token") + 1],
          scan.handoffClaimToken,
        );
        validations++;
        throw new Error("synthetic sealed artifact mismatch");
      },
      async run() {
        runs++;
        if (entry === "run-error") throw new Error("synthetic transport error");
        if (entry === "permission-error") {
          scan.progress.status = "complete";
          throw new this.ScanPermissionError("synthetic permission rejection");
        }
        return { turnResult: { usage: null }, cost: null };
      },
    });
    const result = await server.tools.get("start_codex_security_deep_scan")(
      {
        scanId: scan.scanId,
        handoffClaimToken: scan.handoffClaimToken,
      },
      {
        _meta: {
          "openai/threadId": "synthetic-owner",
          "codex/sandbox-state-meta": {
            sandboxCwd: pathToFileURL(dirname(entrypoint)).href,
            permissionProfile: {
              type: "managed",
              file_system: { type: "unrestricted" },
              network: "restricted",
            },
          },
        },
      },
    );
    if (entry === "run-success") {
      assert.equal(result.isError, undefined);
      assert.deepEqual(result.structuredContent.usage, {
        coverage: "unavailable",
        reason: "codex_state_unavailable",
      });
      assert.deepEqual(result.structuredContent.warnings, [
        "synthetic completion warning",
      ]);
      assert.equal(validations, 0, "fresh SDK completion must not seal again");
    } else {
      assert.equal(result.isError, true);
      assert.match(
        result.content[0].text,
        entry === "permission-error"
          ? /synthetic permission rejection/
          : entry === "read-error"
            ? /synthetic saved metadata unavailable/
            : /synthetic sealed artifact mismatch/,
      );
      assert.equal(result.structuredContent, undefined);
      assert.equal(
        validations,
        ["permission-error", "read-error"].includes(entry) ? 0 : 1,
      );
    }
    assert.equal(runs, entry === "completed" ? 0 : 1);
    if (entry === "permission-error")
      assert.equal(scan.progress.status, "complete");
  });
}

for (const [operation, owner] of ["cancel", "fail"].flatMap((operation) =>
  ["local", "external"].map((owner) => [operation, owner]),
)) {
  test(`native ${operation} authorizes, drains ${owner} child output, then publishes`, async () => {
    const scanId = "synthetic-parent";
    const claimToken = "synthetic-current-claim";
    const events = [];
    const draining = Promise.withResolvers();
    const release = Promise.withResolvers();
    const lateFindings = [];
    let rejectAuthority = true;
    let interrupted = true;
    let active = true;
    let locked = false;
    const scan = () => ({
      scanId,
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: claimToken,
      findings: [...lateFindings],
    });
    const workspace = () => ({ setup: { submitted: true }, results: scan() });
    const fixture = {
      async workbench(args) {
        const [command] = args;
        events.push(command);
        assert.equal(args[args.indexOf("--scan-id") + 1], scanId);
        if (command === `${operation}-scan`) {
          assert.ok(args.includes("--defer-publication"));
          if (rejectAuthority) throw new Error("Wrong scan owner or claim.");
          return operation === "cancel"
            ? workspace()
            : { scan: scan(), workspace: workspace() };
        }
        if (command === "get-scan")
          return { scan: scan(), workspace: workspace() };
        assert.equal(command, "preserve-scan-results");
        assert.ok(args.includes("--after-stop"));
        assert.equal(args[args.indexOf("--claim-token") + 1], claimToken);
        if (operation === "cancel") {
          assert.equal(
            args[args.indexOf("--thread-id") + 1],
            "synthetic-owner",
          );
        }
        assert.equal(active, false);
        assert.equal(locked, true);
        assert.deepEqual(lateFindings, ["synthetic-child-finding"]);
        if (interrupted)
          throw new Error("Interrupted before result publication.");
        return {
          scan: scan(),
          workspace: workspace(),
          recipe: { private: "host-only" },
        };
      },
      async cancel(id, reason) {
        assert.equal(id, scanId);
        assert.equal(
          reason,
          operation === "fail" ? "Synthetic terminal failure." : undefined,
        );
        events.push("drain");
        if (!active || owner === "external") return;
        draining.resolve();
        await release.promise;
        lateFindings.push("synthetic-child-finding");
        active = false;
        events.push("drained");
      },
      async acquire(state, directory, _pluginRoot, wait) {
        assert.equal(state, "/synthetic/state");
        assert.equal(directory, "/synthetic/scan");
        assert.equal(wait, true);
        events.push("acquire");
        if (active) {
          assert.equal(owner, "external");
          draining.resolve();
          await release.promise;
          lateFindings.push("synthetic-child-finding");
          active = false;
          events.push("drained");
        }
        locked = true;
        return () => {
          locked = false;
          events.push("released");
        };
      },
    };
    const server = serverFor(fixture);
    const handler = server.tools.get(`${operation}_codex_security_scan`);
    const call = () =>
      handler(
        {
          scanId,
          message: "Synthetic terminal failure.",
          handoffClaimToken: claimToken,
        },
        { _meta: { "openai/threadId": "synthetic-owner" } },
      );
    await assert.rejects(call(), /Wrong scan owner or claim/);
    assert.deepEqual(
      events,
      Array(operation === "cancel" ? 2 : 1).fill(`${operation}-scan`),
    );
    assert.equal(active, true);
    rejectAuthority = false;
    events.length = 0;
    const pending = assert.rejects(
      call(),
      /Interrupted before result publication/,
    );
    try {
      await draining.promise;
      assert.deepEqual(events, [
        `${operation}-scan`,
        "drain",
        ...(owner === "external" ? ["get-scan", "acquire"] : []),
      ]);
      assert.deepEqual(lateFindings, []);
    } finally {
      release.resolve();
    }
    await pending;
    assert.deepEqual(events, [
      `${operation}-scan`,
      "drain",
      ...(owner === "local"
        ? ["drained", "get-scan", "acquire"]
        : ["get-scan", "acquire", "drained"]),
      "preserve-scan-results",
      "released",
    ]);
    assert.equal(locked, false);
    interrupted = false;
    const completed = await call();
    const context = completed.structuredContent;
    assert.deepEqual(context.workspace.results.findings, [
      "synthetic-child-finding",
    ]);
    assert.equal(context.recipe, undefined);
  });
}

const nativeMeta = {
  _meta: {
    "openai/threadId": "synthetic-owner",
    "codex/sandbox-state-meta": {
      sandboxCwd: pathToFileURL(dirname(entrypoint)).href,
      permissionProfile: {
        type: "managed",
        file_system: { type: "unrestricted" },
        network: "restricted",
      },
    },
  },
};

for (const status of ["canceled", "failed"]) {
  test(`rejoining a ${status} scan finishes interrupted stop publication`, async () => {
    const events = [];
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status },
      failureMessage: status === "failed" ? "Synthetic scan failure." : null,
      usage: { inputTokens: 100, outputTokens: 10 },
      cost: { estimatedUsd: 0.25 },
      warnings: ["Synthetic retained publication warning"],
    };
    const server = serverFor({
      async workbench([command, ...args]) {
        if (command === "list-scans") return {};
        if (command === "resolve-scan-root")
          return { scanRoot: "/synthetic/scans" };
        events.push(command);
        if (command === "preserve-scan-results") {
          assert.ok(args.includes("--after-stop"));
          assert.equal(
            args[args.indexOf("--claim-token") + 1],
            scan.handoffClaimToken,
          );
          return { scan, workspace: { results: scan } };
        }
        assert.ok(["begin-deep-scan", "get-scan"].includes(command));
        return { scan };
      },
      async run() {
        assert.fail("Terminal scans cannot launch a runner");
      },
      async cancel(id, reason) {
        assert.equal(id, scan.scanId);
        assert.equal(reason, scan.failureMessage ?? undefined);
        events.push("drain");
      },
    });
    // The saved terminal state may predate publication; rejoin must be repeatable.
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await server.tools.get("start_codex_security_deep_scan")(
        { scanId: scan.scanId, handoffClaimToken: scan.handoffClaimToken },
        nativeMeta,
      );
      assert.equal(result.isError === true, status === "failed");
      assert.equal(result.structuredContent.status, status);
      if (status === "failed")
        assert.match(result.content[0].text, /Synthetic scan failure/);
      for (const key of ["usage", "cost", "warnings"])
        assert.deepEqual(result.structuredContent[key], scan[key]);
    }
    assert.deepEqual(
      events,
      Array(2)
        .fill(["begin-deep-scan", "drain", "get-scan", "preserve-scan-results"])
        .flat(),
    );
  });
}

for (const completed of [false, true]) {
  test(`native completion returns sealed accounting (rejoin=${completed})`, async () => {
    const metadata = {
      usage: {
        coverage: "complete",
        source: "codex_rollout",
        threadCount: 2,
        inputTokens: 100,
        outputTokens: 10,
      },
      cost: { estimatedUsd: 0.25 },
      warnings: ["Synthetic incomplete coverage"],
    };
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status: completed ? "complete" : "running" },
    };
    const commands = [];
    const fixture = {
      async workbench([command, ...args]) {
        if (command === "list-scans") return {};
        if (command === "resolve-scan-root")
          return { scanRoot: "/synthetic/scans" };
        commands.push(command);
        if (command === "begin-deep-scan") return { scan };
        assert.ok(["complete-scan", "get-scan"].includes(command));
        assert.equal(args[args.indexOf("--scan-id") + 1], scan.scanId);
        return {
          scan: { ...scan, ...metadata, recipe: { private: "not public" } },
        };
      },
      async run() {
        await this.workbench(["complete-scan", "--scan-id", scan.scanId]);
        return {
          turnResult: { usage: { input_tokens: 99, output_tokens: 9 } },
          cost: null,
        };
      },
    };
    const server = serverFor(fixture);
    const result = await server.tools.get("start_codex_security_deep_scan")(
      { scanId: scan.scanId, handoffClaimToken: scan.handoffClaimToken },
      nativeMeta,
    );
    assert.notEqual(result.isError, true);
    for (const key of Object.keys(metadata))
      assert.deepEqual(result.structuredContent[key], metadata[key]);
    assert.equal(result.structuredContent.recipe, undefined);
    assert.deepEqual(
      commands,
      completed
        ? ["begin-deep-scan", "complete-scan"]
        : ["begin-deep-scan", "complete-scan", "get-scan"],
    );
  });
}

for (const lostAcknowledgment of [false, true]) {
  test(`overlapping native cancels settle retained publication (lost acknowledgment=${lostAcknowledgment})`, async () => {
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status: "running" },
      findings: [],
    };
    const responseLost = new Error(
      "Synthetic committed cancellation response lost",
    );
    const publication = Promise.withResolvers();
    const release = Promise.withResolvers();
    let cancelWrites = 0;
    let published = 0;
    let drained = false;
    const workspace = () => ({
      setup: { submitted: true },
      results: { ...scan, findings: [...scan.findings] },
    });
    const server = serverFor({
      async workbench([command]) {
        if (command === "cancel-scan") {
          cancelWrites++;
          scan.progress.status = "canceled";
          if (lostAcknowledgment && cancelWrites === 1) throw responseLost;
          return workspace();
        }
        if (command === "get-scan") return { scan, workspace: workspace() };
        assert.equal(command, "preserve-scan-results");
        assert.equal(drained, true);
        published++;
        publication.resolve();
        await release.promise;
        scan.findings.push("synthetic-retained-finding");
        return { scan, workspace: workspace() };
      },
      async cancel() {
        drained = true;
      },
    });
    const call = () =>
      server.tools.get("cancel_codex_security_scan_from_app")({
        scanId: scan.scanId,
      });
    let firstSettled = false;
    const first = call()
      .then(
        (value) => ({ value }),
        (error) => ({ error }),
      )
      .finally(() => {
        firstSettled = true;
      });
    await publication.promise;
    const second = call();
    // Framed stdin delivers the second mock request on the next event-loop turn.
    await new Promise(setImmediate);
    assert.equal(firstSettled, false);
    release.resolve();
    const [firstResult, secondResult] = await Promise.all([first, second]);
    if (lostAcknowledgment) assert.equal(firstResult.error, responseLost);
    else
      assert.deepEqual(
        firstResult.value.structuredContent.workspace,
        workspace(),
      );
    assert.deepEqual(secondResult.structuredContent.workspace, workspace());
    assert.equal(published, 1);
    assert.equal(cancelWrites, lostAcknowledgment ? 3 : 2);
  });
}

for (const status of ["failed", "complete", "running"]) {
  test(`native cancel preserves the durable ${status} outcome after local execution ends`, async () => {
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status },
      failureMessage: status === "failed" ? "Synthetic original failure" : null,
    };
    let aborts = 0;
    let waits = 0;
    let publications = 0;
    const workspace = () => ({
      setup: { submitted: true },
      results: { ...scan },
    });
    const server = serverFor({
      async workbench([command]) {
        if (command === "cancel-scan") {
          if (scan.progress.status === "running")
            scan.progress.status = "canceled";
          return workspace();
        }
        if (command === "get-scan") return { scan, workspace: workspace() };
        assert.equal(command, "preserve-scan-results");
        publications++;
        return { scan, workspace: workspace() };
      },
      async cancel() {
        aborts++;
      },
      async wait() {
        waits++;
      },
    });
    const result = await server.tools.get(
      "cancel_codex_security_scan_from_app",
    )({ scanId: scan.scanId });
    assert.deepEqual(result.structuredContent.workspace, workspace());
    assert.equal(
      scan.progress.status,
      status === "running" ? "canceled" : status,
    );
    assert.equal(
      scan.failureMessage,
      status === "failed" ? "Synthetic original failure" : null,
    );
    assert.equal(aborts, status === "running" ? 1 : 0);
    assert.equal(waits, status === "running" ? 0 : 1);
    assert.equal(publications, status === "complete" ? 0 : 1);
  });
}

for (const mode of ["standard", "diff"]) {
  test(`SDK-owned ${mode} failure returns while its model caller holds execution`, async () => {
    const scan = {
      scanId: "synthetic-sdk-scan",
      scanDir: "/synthetic/scan",
      mode,
      handoffClaimToken: "synthetic-claim",
      progress: { status: "failed" },
    };
    let published = false;
    const server = serverFor({
      async workbench([command]) {
        if (command === "preserve-scan-results") published = true;
        else assert.ok(["fail-scan", "get-scan"].includes(command));
        return {
          scan,
          workspace: { setup: { submitted: true }, results: scan },
        };
      },
      async cancel() {},
      async acquire() {
        assert.fail(
          "The awaiting model caller still holds this SDK execution lock.",
        );
      },
    });
    const result = await server.tools.get("fail_codex_security_scan")({
      scanId: scan.scanId,
      message: "Synthetic model-reported failure",
      handoffClaimToken: scan.handoffClaimToken,
    });
    assert.equal(result.structuredContent.scan.progress.status, "failed");
    assert.equal(published, true);
  });
}
