import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";

interface FixtureScanResults {
  progress: { status: string };
}

interface FixtureWorkspace {
  setup: { submitted: boolean };
  results: FixtureScanResults;
}

interface WorkbenchScanRecord {
  workspace: FixtureWorkspace;
  scan: FixtureScanResults;
}

interface CancelResponseFixture {
  registry: {
    cancelAndWait(
      scanId: string,
      reason: string,
      persist: () => Promise<void>,
    ): Promise<boolean>;
    shutdown(): void;
  };
  workbench(args: string[]): Promise<FixtureWorkspace | WorkbenchScanRecord>;
}

declare global {
  var cancelResponseFixture: CancelResponseFixture | undefined;
}

interface CancelResponseModule {
  createCodexSecurityServer(): {
    _registeredTools: {
      cancel_codex_security_scan_from_app: {
        handler(args: { scanId: string }): Promise<{
          structuredContent: { workspace: FixtureWorkspace };
        }>;
      };
    };
    close(): Promise<void>;
  };
}

const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");
const calls: string[][] = [];
let workspace: FixtureWorkspace;
let fixtureRoot: string | undefined;
let joining = false;
let persisted: PromiseWithResolvers<void>;
let release: PromiseWithResolvers<void>;
const fixture: CancelResponseFixture = {
  registry: {
    async cancelAndWait(_scanId, _reason, persist) {
      if (!joining) {
        joining = true;
        await persist();
        persisted.resolve();
      }
      await release.promise;
      return true;
    },
    shutdown() {},
  },
  async workbench(args) {
    calls.push(args);
    if (args[0] === "cancel-scan")
      workspace.results.progress.status = "canceled";
    return args[0] === "get-scan"
      ? { workspace, scan: workspace.results }
      : workspace;
  },
};
globalThis.cancelResponseFixture = fixture;
try {
  const { createCodexSecurityServer } = (await importModule({
    stdin: {
      contents: source
        .replace(
          "const deepScanCoordinators = new DeepScanCoordinatorRegistry();",
          "const deepScanCoordinators = globalThis.cancelResponseFixture.registry;",
        )
        .replace(
          "async function runWorkbench(",
          "const runWorkbench = (...args) => globalThis.cancelResponseFixture.workbench(...args);\nasync function unusedRunWorkbench(",
        ),
      loader: "ts",
      resolveDir: applicationRoot,
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(
        new URL("../server.ts", import.meta.url).href,
      ),
    },
    loader: { ".md": "text" },
  })) as CancelResponseModule;
  const server = createCodexSecurityServer();
  const cancel =
    server._registeredTools.cancel_codex_security_scan_from_app.handler;
  workspace = {
    setup: { submitted: true },
    results: { progress: { status: "canceled" } },
  };
  persisted = Promise.withResolvers<void>();
  release = Promise.withResolvers<void>();
  const first = cancel({ scanId: "fixture-scan" });
  await persisted.promise;
  const second = cancel({ scanId: "fixture-scan" });
  release.resolve();
  for (const result of await Promise.all([first, second])) {
    assert.deepEqual(result.structuredContent.workspace, workspace);
  }
  assert.deepEqual(
    calls.map(([command]) => command),
    ["cancel-scan", "get-scan"],
  );
  workspace = {
    setup: { submitted: true },
    results: { progress: { status: "failed" } },
  };
  assert.deepEqual(
    (await cancel({ scanId: "fixture-scan" })).structuredContent.workspace,
    workspace,
  );
  assert.equal(
    calls.at(-1)![0],
    "get-scan",
    "late cancellation must not overwrite a saved failure",
  );
  fixtureRoot = await temporaryDirectory("cancel-saved-parent-", true);
  const target = join(fixtureRoot, "repository");
  const output = join(fixtureRoot, "output");
  await mkdir(target);
  await mkdir(output, { mode: 0o700 });
  await writeFile(join(target, "fixture.py"), "value = 1\n");
  const workbenchPath = fileURLToPath(
    new URL("../../scripts/workbench_db.py", import.meta.url),
  );
  const run = (args: string[]): WorkbenchScanRecord & { scanId: string } =>
    JSON.parse(
      execFileSync(
        process.env.PYTHON || "python3",
        ["-I", "-B", workbenchPath, ...args],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: join(fixtureRoot!, "state"),
          },
        },
      ),
    );
  const registered = run([
    "register-cli-scan",
    "--repository",
    target,
    "--scan-dir",
    output,
    "--recipe-json",
    JSON.stringify({
      repository: target,
      target: { kind: "repository", paths: [] },
      mode: "standard",
      config: {},
    }),
  ]);
  assert.equal(
    run(["get-scan", "--scan-id", registered.scanId]).workspace.results.progress
      .status,
    "running",
  );
  // Local completion can leave the durable parent running after discovery or a rejected failure write.
  fixture.registry.cancelAndWait = async () => true;
  fixture.workbench = async (args) => {
    calls.push(args);
    return run(args);
  };
  const parentCanceled = await cancel({ scanId: registered.scanId });
  assert.equal(
    parentCanceled.structuredContent.workspace.results.progress.status,
    "canceled",
  );
  assert.equal(
    run(["get-scan", "--scan-id", registered.scanId]).scan.progress.status,
    "canceled",
  );
  assert.equal(
    calls.at(-1)![0],
    "cancel-scan",
    "completed discovery still permits cancellation of its running parent",
  );
  await server.close();
} finally {
  delete globalThis.cancelResponseFixture;
  if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
}
