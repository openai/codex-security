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
            async close() {}
          }`,
          "./src/python_command.js": `
          export async function resolvePythonCommand() { return "fixture-python"; }
          export function missingPythonHelperMessage() {}`,
          "../../../sdk/typescript/src/scan-execution.js": `
          export const ScanPermissionError = fixture.ScanPermissionError;`,
          "node:child_process": `
          export function execFile() {}
          execFile[Symbol.for("nodejs.util.promisify.custom")] = (_command, args) =>
            fixture.workbench(args.slice(1)).then(result => ({ stdout: JSON.stringify(result) }));`,
        };
        build.onResolve({ filter: /.*/ }, ({ path }) =>
          Object.hasOwn(modules, path)
            ? { path, namespace: "fixture" }
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
  "run-error",
  "permission-error",
]) {
  test(`native ${entry} preserves completion and permission errors`, async () => {
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
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
          return { scan: { ...scan, progress: { status: "complete" } } };
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
        return {};
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
    assert.equal(result.isError, true);
    assert.match(
      result.content[0].text,
      entry === "permission-error"
        ? /synthetic permission rejection/
        : /synthetic sealed artifact mismatch/,
    );
    assert.equal(result.structuredContent, undefined);
    assert.equal(runs, entry === "completed" ? 0 : 1);
    assert.equal(validations, entry === "permission-error" ? 0 : 1);
    if (entry === "permission-error")
      assert.equal(scan.progress.status, "complete");
  });
}

for (const operation of ["cancel", "fail"]) {
  test(`native ${operation} authorizes, drains late child output, then publishes`, async () => {
    const scanId = "synthetic-parent";
    const claimToken = "synthetic-current-claim";
    const events = [];
    const draining = Promise.withResolvers();
    const release = Promise.withResolvers();
    const lateFindings = [];
    let rejectAuthority = true;
    let interrupted = true;
    let active = true;
    const scan = () => ({
      scanId,
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
        if (!active) return;
        draining.resolve();
        await release.promise;
        lateFindings.push("synthetic-child-finding");
        active = false;
        events.push("drained");
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
    assert.deepEqual(events, [`${operation}-scan`]);
    assert.equal(active, true);
    rejectAuthority = false;
    events.length = 0;
    const pending = assert.rejects(
      call(),
      /Interrupted before result publication/,
    );
    try {
      await draining.promise;
      assert.deepEqual(events, [`${operation}-scan`, "drain"]);
      assert.deepEqual(lateFindings, []);
    } finally {
      release.resolve();
    }
    await pending;
    assert.deepEqual(events, [
      `${operation}-scan`,
      "drain",
      "drained",
      ...(operation === "cancel" ? ["get-scan"] : []),
      "preserve-scan-results",
    ]);
    interrupted = false;
    const completed = await call();
    const context = completed.structuredContent;
    assert.deepEqual(context.workspace.results.findings, [
      "synthetic-child-finding",
    ]);
    assert.equal(context.recipe, undefined);
  });
}
