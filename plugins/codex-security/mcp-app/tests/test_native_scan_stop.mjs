import { captureEnvironment } from "../../../../sdk/typescript/tests-support/process-environment.mjs";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, join, relative } from "node:path";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { once } from "node:events";
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
          export async function readNativeScanSemanticInputs() { throw new Error("explicit scan recovery must not read ambient semantic inputs"); }
          export class NativeScanHost {
            run(...args) { return fixture.run(...args); }
            cancel(...args) { return fixture.cancel(...args); }
            async close() {}
          }`,
          "./src/python_command.js": `
          export async function resolvePythonCommand() { return "fixture-python"; }
          export function missingPythonHelperMessage() {}
          export async function runPythonWithInput() { throw new Error("unexpected artifact Python invocation"); }
          export function workbenchCommandTimeout() { return 30000; }`,
          "../../../sdk/typescript/src/scan-execution.js": `
          export const ScanPermissionError = fixture.ScanPermissionError;
          export async function waitForScanExecution(...args) { return fixture.waitForScanExecution ? fixture.waitForScanExecution(...args) : () => {}; }`,
          "node:child_process": `
          import { PassThrough } from "node:stream";
          import { join } from "node:path";
          export function spawn() { throw new Error("unexpected runtime child invocation"); }
          export function execFile() {}
          execFile[Symbol.for("nodejs.util.promisify.custom")] = (_command, _args, options) => {
            const stdin = new PassThrough();
            let input = "";
            const result = new Promise((resolve, reject) => {
              stdin.on("data", chunk => { input += chunk; });
              stdin.on("end", () => Promise.resolve().then(() => {
                const args = JSON.parse(input.split("\\n")[0]).flatMap(argument => {
                  const split = argument.startsWith("--") ? argument.indexOf("=") : -1;
                  return split < 0 ? [argument] : [argument.slice(0, split), argument.slice(split + 1)];
                });
                const bootstrap = options.env === process.env;
                fixture.workbenchEnvironment?.(options.env, { bootstrap, cwd: options.cwd, args });
                if (bootstrap) {
                  if (args.length !== 1 || args[0] !== "resolve-scan-root")
                    throw new Error("Only state selection may use the raw workbench environment");
                  fixture.stateBootstrapCount++;
                  return { scanRoot: join(fixture.stateDirectory ?? "/synthetic", "scans") };
                }
                return fixture.workbench(args);
              })
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
          resolveDir: dirname(entrypoint),
        }));
      },
    },
  ],
});

function serverFor(fixture) {
  fixture.ScanPermissionError = class ScanPermissionError extends Error {};
  fixture.stateBootstrapCount = 0;
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
        : entry === "read-error"
          ? /synthetic saved metadata unavailable/
          : /synthetic sealed artifact mismatch/,
    );
    assert.equal(result.structuredContent, undefined);
    assert.equal(runs, entry === "completed" ? 0 : 1);
    assert.equal(
      validations,
      ["permission-error", "read-error"].includes(entry) ? 0 : 1,
    );
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
      "get-scan",
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

for (const operation of ["cancel", "fail", "canceled", "failed"]) {
  test(`native ${operation} uses the worker's canonical state directory`, async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-stop-home-")),
    );
    const restore = captureEnvironment([
      "CODEX_HOME",
      "CODEX_SECURITY_STATE_DIR",
      "CODEX_SECURITY_PLUGIN_ROOT",
    ]);
    try {
      const pluginRoot = join(root, "plugin");
      await mkdir(pluginRoot);
      process.env.CODEX_SECURITY_PLUGIN_ROOT = pluginRoot;
      await mkdir(join(root, "physical", "nested"), { recursive: true });
      await symlink(
        join(root, "physical", "nested"),
        join(root, "link"),
        process.platform === "win32" ? "junction" : "dir",
      );
      const configuredHome = `${join(root, "link")}/..`;
      const canonicalHome = await realpath(configuredHome);
      process.env.CODEX_HOME = configuredHome;
      const fallbackState = join(
        canonicalHome,
        "state",
        "plugins",
        "codex-security",
      );
      const variants = [
        { override: undefined, expectedState: fallbackState },
        { override: "", expectedState: fallbackState },
        {
          override: join(root, "selected-state"),
          expectedState: join(root, "selected-state"),
        },
        {
          override: "relative-state",
          expectedState: join(pluginRoot, "relative-state"),
        },
      ];
      if (process.platform !== "win32") {
        const account = userInfo();
        variants.push(
          {
            override: join(root, " selected-state "),
            expectedState: join(root, " selected-state "),
          },
          { override: "   ", expectedState: join(pluginRoot, "   ") },
          {
            override: `~${account.username}/${relative(await realpath(account.homedir), join(root, "named-user-state"))}`,
            expectedState: join(root, "named-user-state"),
          },
        );
      }
      for (const { override, expectedState } of variants) {
        if (override === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
        else process.env.CODEX_SECURITY_STATE_DIR = override;
        const rejoin = operation === "canceled" || operation === "failed";
        const scan = {
          scanId: "synthetic-parent",
          scanDir: join(root, "scan"),
          mode: "deep",
          handoffClaimToken: "synthetic-claim",
          progress: { status: rejoin ? operation : "running" },
        };
        let preserved = false;
        let released = false;
        const fixture = {
          stateDirectory: expectedState,
          workbenchEnvironment(environment, { bootstrap, cwd, args }) {
            assert.equal(cwd, pluginRoot);
            assert.equal(environment.CODEX_HOME, configuredHome);
            assert.equal(
              environment.CODEX_SECURITY_STATE_DIR,
              bootstrap ? override : expectedState,
            );
            if (bootstrap) assert.deepEqual(args, ["resolve-scan-root"]);
          },
          async cancel() {},
          async waitForScanExecution(state, directory) {
            assert.equal(state, expectedState);
            assert.equal(directory, scan.scanDir);
            return () => {
              released = true;
            };
          },
          async workbench([command]) {
            if (command === "list-scans") return {};
            if (command === "resolve-scan-root")
              return { scanRoot: join(expectedState, "scans") };
            if (command === "preserve-scan-results") preserved = true;
            else
              assert.ok(
                [
                  "cancel-scan",
                  "fail-scan",
                  "begin-deep-scan",
                  "get-scan",
                ].includes(command),
              );
            return {
              scan,
              workspace: { setup: { submitted: true }, results: scan },
            };
          },
        };
        const server = serverFor(fixture);
        const result = await server.tools.get(
          rejoin
            ? "start_codex_security_deep_scan"
            : `${operation}_codex_security_scan`,
        )(
          {
            scanId: scan.scanId,
            handoffClaimToken: scan.handoffClaimToken,
            message: "Synthetic stop.",
          },
          nativeMeta,
        );
        assert.equal(preserved, true, JSON.stringify(result));
        assert.equal(released, true);
        assert.equal(fixture.stateBootstrapCount, 1);
        assert.equal(process.env.CODEX_HOME, configuredHome);
        assert.equal(process.env.CODEX_SECURITY_STATE_DIR, override);
      }
    } finally {
      restore();
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const resumed of [false, true]) {
  test(`native ${resumed ? "resume" : "start"} forwards its workbench state to execution`, async () => {
    const restore = captureEnvironment([
      "CODEX_SECURITY_STATE_DIR",
      "CODEX_SECURITY_PLUGIN_ROOT",
    ]);
    const configuredState = "  relative-native-state  ";
    const pluginRoot = dirname(dirname(entrypoint));
    process.env.CODEX_SECURITY_PLUGIN_ROOT = pluginRoot;
    process.env.CODEX_SECURITY_STATE_DIR = configuredState;
    const expectedState = join(pluginRoot, configuredState);
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status: "running" },
    };
    let launches = 0;
    const fixture = {
      stateDirectory: expectedState,
      workbenchEnvironment(environment, { bootstrap, cwd, args }) {
        assert.equal(cwd, pluginRoot);
        assert.equal(
          environment.CODEX_SECURITY_STATE_DIR,
          bootstrap ? configuredState : expectedState,
        );
        if (bootstrap) assert.deepEqual(args, ["resolve-scan-root"]);
      },
      async workbench([command]) {
        if (command === "list-scans") return {};
        if (command === "resolve-scan-root")
          return { scanRoot: "/synthetic/scans" };
        return { scan, ...(resumed ? { recipe: { mode: "deep" } } : {}) };
      },
      async run(input) {
        launches++;
        assert.equal(input.stateDirectory, expectedState);
        assert.equal(input.recipe !== undefined, resumed);
        // Host selection remains stable if unrelated ambient configuration changes.
        process.env.CODEX_SECURITY_STATE_DIR = "different-ambient-state";
        scan.progress.status = "complete";
      },
    };
    const server = serverFor(fixture);
    try {
      const result = await server.tools.get("start_codex_security_deep_scan")(
        resumed
          ? { scanId: scan.scanId, handoffClaimToken: scan.handoffClaimToken }
          : { targetPath: "/synthetic/repository" },
        nativeMeta,
      );
      assert.notEqual(result.isError, true, JSON.stringify(result));
      assert.equal(launches, 1);
      assert.equal(fixture.stateBootstrapCount, 1);
    } finally {
      restore();
      await server.close();
    }
  });
}

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

for (const operation of ["cancel", "fail", "canceled", "failed"]) {
  test(`native ${operation} retains published results when lock release fails`, async (t) => {
    const rejoin = operation === "canceled" || operation === "failed";
    const scan = {
      scanId: "synthetic-parent",
      scanDir: "/synthetic/scan",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status: rejoin ? operation : "running" },
      failureMessage: "Synthetic original failure.",
      findings: ["synthetic-retained-finding"],
      usage: { inputTokens: 100, outputTokens: 10 },
      cost: { estimatedUsd: 0.25 },
      warnings: ["Synthetic retained publication warning"],
    };
    const releaseError = new Error(
      "Cannot close scan execution lock (Windows error 6).",
    );
    const warnings = [];
    t.mock.method(console, "warn", (...args) => warnings.push(args));
    let publications = 0;
    let releases = 0;
    const server = serverFor({
      stateDirectory: "/synthetic/state",
      async cancel() {},
      async waitForScanExecution() {
        return () => {
          releases++;
          throw releaseError;
        };
      },
      async workbench([command]) {
        if (command === "list-scans") return {};
        if (command === "resolve-scan-root")
          return { scanRoot: "/synthetic/scans" };
        if (command === "preserve-scan-results") publications++;
        return {
          scan,
          workspace: { setup: { submitted: true }, results: scan },
        };
      },
      async run() {
        assert.fail("Terminal scans cannot launch a runner");
      },
    });
    const result = await server.tools.get(
      rejoin
        ? "start_codex_security_deep_scan"
        : `${operation}_codex_security_scan`,
    )(
      {
        scanId: scan.scanId,
        handoffClaimToken: scan.handoffClaimToken,
        message: scan.failureMessage,
      },
      nativeMeta,
    );
    assert.equal(result.isError === true, operation === "failed");
    if (rejoin) {
      assert.equal(result.structuredContent.status, operation);
      if (operation === "failed")
        assert.match(result.content[0].text, /Synthetic original failure/);
      for (const key of ["usage", "cost", "warnings"])
        assert.deepEqual(result.structuredContent[key], scan[key]);
    } else {
      assert.deepEqual(
        operation === "cancel"
          ? result.structuredContent.workspace.results
          : result.structuredContent.scan,
        scan,
      );
    }
    assert.equal(publications, 1);
    assert.equal(releases, 1);
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0][1], releaseError);
  });
}

for (const completed of [false, true]) {
  test(`native completion returns sealed accounting (rejoin=${completed})`, async () => {
    const metadata = {
      usage: { inputTokens: 100, outputTokens: 10 },
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
        // A successful SDK run has already completed the scan; saved metadata is authoritative.
        await this.workbench(["complete-scan", "--scan-id", scan.scanId]);
        return { cost: { estimatedUsd: 99 }, turnResult: { usage: null } };
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

for (const [operation, mode] of ["cancel", "fail"].flatMap((operation) =>
  ["deep", "standard", "diff"].map((mode) => [operation, mode]),
)) {
  test(`${mode} ${operation} respects execution ownership before publication`, async () => {
    const root = await mkdtemp(join(tmpdir(), "native-remote-stop-"));
    const scanDir = join(root, "scan");
    await mkdir(scanDir);
    const source = fileURLToPath(
      new URL(
        "../../../../sdk/typescript/src/scan-execution.ts",
        import.meta.url,
      ),
    );
    const built = await build({
      entryPoints: [source],
      format: "esm",
      platform: "node",
      write: false,
    });
    const modulePath = join(root, "scan-execution.mjs");
    await writeFile(modulePath, built.outputFiles[0].text);
    const { acquireScanExecution, waitForScanExecution } = await import(
      pathToFileURL(modulePath)
    );
    const plugin = fileURLToPath(
      new URL("../../../../sdk/typescript/_bundled_plugin", import.meta.url),
    );
    const receipt = join(scanDir, "evidence.txt");
    await writeFile(receipt, "Before drain");
    const child = spawn(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `
      import { acquireScanExecution } from ${JSON.stringify(pathToFileURL(modulePath).href)};
      import { writeFile } from "node:fs/promises";
      import { createInterface } from "node:readline";
      const release = await acquireScanExecution(${JSON.stringify(root)}, ${JSON.stringify(scanDir)}, ${JSON.stringify(plugin)});
      console.log("owned");
      for await (const line of createInterface({ input: process.stdin })) {
        if (line === "drain") { await writeFile(${JSON.stringify(receipt)}, "Accepted late evidence"); release(); console.log("drained"); break; }
      }
    `,
      ],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    const exited = once(child, "exit");
    const lines = createInterface({ input: child.stdout });
    const output = lines[Symbol.asyncIterator]();
    let pending;
    try {
      assert.equal((await output.next()).value, "owned");
      const barrier = Promise.withResolvers();
      let preserved = false;
      const scan = {
        scanId: "synthetic-parent",
        scanDir,
        mode,
        handoffClaimToken: "synthetic-claim",
      };
      const fixture = {
        stateDirectory: root,
        async cancel() {}, // This process owns no active scan.
        async waitForScanExecution(state, directory) {
          assert.equal(state, root);
          assert.equal(directory, scanDir);
          barrier.resolve();
          return waitForScanExecution(state, directory, plugin);
        },
        async workbench([command]) {
          const workspace = { setup: { submitted: true }, results: scan };
          if (command === operation + "-scan" || command === "get-scan")
            return { scan, workspace };
          assert.equal(command, "preserve-scan-results");
          assert.equal(
            await readFile(receipt, "utf8"),
            mode === "deep" ? "Accepted late evidence" : "Before drain",
          );
          await assert.rejects(
            acquireScanExecution(root, scanDir, plugin),
            /already running/,
          );
          preserved = true;
          return { scan, workspace };
        },
      };
      pending = serverFor(fixture).tools.get(
        operation + "_codex_security_scan",
      )(
        {
          scanId: scan.scanId,
          message: "Synthetic terminal failure.",
          handoffClaimToken: scan.handoffClaimToken,
        },
        { _meta: { "openai/threadId": "synthetic-owner" } },
      );
      const early = await Promise.race([
        barrier.promise.then(() => "waiting"),
        pending.then(
          () => "returned",
          (error) => error,
        ),
      ]);
      assert.equal(early, mode === "deep" ? "waiting" : "returned");
      assert.equal(preserved, mode !== "deep");
      if (mode !== "deep")
        await assert.rejects(
          acquireScanExecution(root, scanDir, plugin),
          /already running/,
        );
      child.stdin.end("drain\n");
      await pending;
      assert.equal(preserved, true);
      assert.equal((await output.next()).value, "drained");
      (await acquireScanExecution(root, scanDir, plugin))();
    } finally {
      child.kill("SIGKILL");
      await exited;
      await pending?.catch(() => {});
      lines.close();
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const status of ["running", "failed"]) {
  test(`native permission rejection retains ${status} scan state`, async () => {
    const commands = [];
    const scan = {
      scanId: "synthetic-permission-parent",
      scanDir: "/synthetic/permission-scan",
      targetPath: "/synthetic/target",
      mode: "deep",
      handoffClaimToken: "synthetic-claim",
      progress: { status: "running" },
      failureMessage: "synthetic permission rejection",
    };
    const server = serverFor({
      async workbench([command]) {
        commands.push(command);
        if (command === "resolve-scan-root")
          return { scanRoot: "/synthetic/scans" };
        if (command === "list-scans") return {};
        if (["begin-deep-scan", "get-scan"].includes(command)) return { scan };
        assert.equal(command, "preserve-scan-results");
        return {
          scan: { ...scan, warnings: ["Retained synthetic evidence."] },
        };
      },
      async run() {
        scan.progress.status = status;
        throw new this.ScanPermissionError(
          "synthetic permission rejection with full diagnostic",
        );
      },
      async cancel() {},
      async waitForScanExecution() {
        return () => {};
      },
    });
    const result = await server.tools.get("start_codex_security_deep_scan")(
      { targetPath: scan.targetPath },
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
      /synthetic permission rejection with full diagnostic/,
    );
    if (status === "failed") {
      assert.equal(result.structuredContent.scanId, scan.scanId);
      assert.equal(result.structuredContent.status, "failed");
      assert.deepEqual(result.structuredContent.warnings, [
        "Retained synthetic evidence.",
      ]);
      assert.ok(commands.includes("preserve-scan-results"));
    } else {
      assert.equal(result.structuredContent, undefined);
      assert.ok(!commands.includes("preserve-scan-results"));
    }
  });
}
