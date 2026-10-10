import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { DeepScanRunState } from "../src/deep-scan/types.js";
import { importModule } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { FakeExecutor } from "./deep_scan_coordinator_fixture.ts";

const execFileAsync = promisify(execFile);
const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const {
  WorkbenchDeepScanStore,
  DeepScanCoordinatorRegistry,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = await importModule({
  stdin: {
    contents: `export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";
export { DeepScanCoordinatorRegistry } from "./src/deep-scan/registry.ts";
export { createScanArtifactContext } from "./src/artifact-context.ts";
export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";`,
    resolveDir: applicationRoot,
  },
  loader: { ".md": "text" },
});
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");

for (const ordering of [
  "failure response first",
  "failure response last",
  "lost cancellation response",
  "cancellation before admission",
  "cancellation before admission with active worker",
  "failure before admission with active worker",
  "cancellation before failure",
  "lost cancellation before failure",
  "cancellation before failure during publication",
  "lost cancellation before failure during publication",
]) {
  await test(ordering, { timeout: 30_000 }, async () => {
    const canceledBeforeAdmission = ordering.startsWith(
      "cancellation before admission",
    );
    const failedBeforeAdmission =
      ordering === "failure before admission with active worker";
    const activeBeforeAdmission = ordering.endsWith("active worker");
    const canceledBeforeFailure = ordering.includes(
      "cancellation before failure",
    );
    const lostCancellation = ordering.startsWith("lost cancellation");
    const failureDuringPublication = ordering.endsWith("during publication");
    const root = await temporaryDirectory("deep-scan-terminal-race-");
    const registry = new DeepScanCoordinatorRegistry();
    const cleanupEntered = Promise.withResolvers<void>();
    const cleanupRelease = Promise.withResolvers<void>();
    const cancelEntered = Promise.withResolvers<void>();
    const cancelRelease = Promise.withResolvers<void>();
    const failureCommitted = Promise.withResolvers<void>();
    const failureResponse = Promise.withResolvers<void>();
    const finishCommitted = Promise.withResolvers<void>();
    const finishResponse = Promise.withResolvers<void>();
    const admissionRead = Promise.withResolvers<void>();
    const publicationEntered = Promise.withResolvers<void>();
    const publicationRelease = Promise.withResolvers<void>();
    let server:
      | ReturnType<(typeof import("../server.ts"))["createCodexSecurityServer"]>
      | undefined;
    let terminal: Promise<DeepScanRunState> | undefined;
    let cancellation: Promise<unknown> | undefined;
    let failure: Promise<unknown> | undefined;
    try {
      const target = join(root, "target");
      const environment = {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        CODEX_HOME: join(root, "home"),
      };
      await mkdir(target);
      await writeFile(join(target, "fixture.py"), "value = 1\n");
      await mkdir(join(environment.CODEX_HOME, "codex-security"), {
        recursive: true,
      });
      await writeFile(
        join(environment.CODEX_HOME, "codex-security", "config.toml"),
        "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n" +
          (canceledBeforeFailure || activeBeforeAdmission
            ? ""
            : "max_time_hours = 1e-12\n"),
        { mode: 0o600 },
      );
      const runWorkbench = async (args: string[]) => {
        const { stdout } = await execFileAsync(
          process.env.PYTHON || "python3",
          [join(pluginRoot, "scripts", "workbench_db.py"), ...args],
          { cwd: pluginRoot, env: environment },
        );
        return JSON.parse(stdout);
      };
      const workbench = async (args: string[]) => {
        if (args[0] === "cancel-scan" && !canceledBeforeFailure) {
          cancelEntered.resolve();
          await cancelRelease.promise;
        }
        const result = await runWorkbench(args);
        if (
          args[0] === "finish-deep-scan" &&
          canceledBeforeAdmission &&
          !activeBeforeAdmission
        ) {
          finishCommitted.resolve();
          await finishResponse.promise;
        }
        if (args[0] === "get-scan") admissionRead.resolve();
        if (args[0] === "cancel-scan" && canceledBeforeFailure) {
          cancelEntered.resolve();
          await cancelRelease.promise;
        }
        if (args[0] === "fail-scan") {
          failureCommitted.resolve();
          await failureResponse.promise;
        }
        if (args[0] === "cancel-scan" && lostCancellation)
          throw new Error("synthetic committed cancellation response lost");
        return result;
      };
      Object.assign(globalThis, {
        terminalRaceFixture: { registry, workbench },
      });
      const { createCodexSecurityServer } = await importModule({
        stdin: {
          contents: source
            .replace(
              "const deepScanCoordinators = new DeepScanCoordinatorRegistry();",
              "const deepScanCoordinators = globalThis.terminalRaceFixture.registry;",
            )
            .replace(
              "async function runWorkbench(",
              "const runWorkbench = (...args) => globalThis.terminalRaceFixture.workbench(...args);\nasync function unusedRunWorkbench(",
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
      });
      const application = createCodexSecurityServer();
      server = application;
      const cancel =
        application._registeredTools.cancel_codex_security_scan_from_app
          .handler;
      const fail =
        application._registeredTools.fail_codex_security_scan.handler;
      const store = new WorkbenchDeepScanStore(workbench);
      const run = await store.begin({
        targetPath: target,
        scope: ".",
        threadId: "fixture-owner",
        scanRoot: join(root, "scans"),
      });
      const claim = await store.claimCoordinator({
        scanId: run.scanId,
        threadId: "fixture-owner",
      });
      const get = store.get.bind(store);
      let held = false;
      store.get = async (...args: [string, string]) => {
        const result = await get(...args);
        if (
          !held &&
          result.status === "succeeded" &&
          !canceledBeforeAdmission
        ) {
          held = true;
          cleanupEntered.resolve();
          await cleanupRelease.promise;
        }
        return result;
      };
      const executor = new FakeExecutor({ blockDiscoveryAfterCalls: 0 });
      const coordinator = registry.start({
        run: claim.run,
        store,
        executor:
          canceledBeforeFailure || activeBeforeAdmission
            ? executor
            : {
                async run() {
                  throw new Error("expired deadline must not launch a worker");
                },
              },
        pluginRoot,
        threadId: "fixture-owner",
        heartbeatIntervalMs: 60_000,
        onComplete: async (draft: ScanDraftInput) => {
          const context = await createScanArtifactContext(
            run.scanId,
            runWorkbench,
            { requireRunning: true },
          );
          await recordCodexSecurityScanDraftViaWorkbench(
            context,
            draft,
            runWorkbench,
          );
        },
        onStopped: async (stopped: DeepScanRunState) => {
          if (failureDuringPublication) {
            publicationEntered.resolve();
            await publicationRelease.promise;
          }
          await runWorkbench([
            "preserve-scan-results",
            "--scan-id",
            stopped.scanId,
            "--thread-id",
            "fixture-owner",
            "--coordinator-generation",
            String(stopped.coordinatorGeneration),
          ]);
        },
      });
      terminal = coordinator.settled();
      void terminal!.catch(() => {});
      if (canceledBeforeAdmission || failedBeforeAdmission) {
        if (activeBeforeAdmission) await executor.discoveryStarted.promise;
        else await finishCommitted.promise;
        await runWorkbench([
          failedBeforeAdmission ? "fail-scan" : "cancel-scan",
          "--scan-id",
          run.scanId,
          ...(failedBeforeAdmission
            ? ["--message", "synthetic externally persisted failure"]
            : []),
        ]);
        cancelRelease.resolve();
        const cancellationResult = cancel({ scanId: run.scanId });
        cancellation = cancellationResult;
        void cancellation!.catch(() => {});
        await Promise.race([admissionRead.promise, cancellation]);
        if (activeBeforeAdmission) {
          await new Promise(setImmediate);
          assert.equal(
            executor.runningDiscovery,
            0,
            "accepted cancellation stops the worker before the next heartbeat",
          );
        }
        finishResponse.resolve();
        const result = await terminal!;
        assert.equal(
          result.status,
          failedBeforeAdmission ? "failed" : "canceled",
        );
        if (!activeBeforeAdmission) assert.equal(result.error, undefined);
        const canceled = await cancellationResult;
        if (failedBeforeAdmission) {
          assert.equal(result.error, "synthetic externally persisted failure");
          assert.equal(
            canceled.structuredContent.workspace.results.failureMessage,
            "synthetic externally persisted failure",
          );
          assert.equal(
            canceled.structuredContent.workspace.results.progress.status,
            "failed",
          );
        }
        return;
      }
      if (canceledBeforeFailure) {
        await executor.discoveryStarted.promise;
        cancellation = cancel({ scanId: run.scanId });
        void cancellation!.catch(() => {});
        await cancelEntered.promise;
        if (failureDuringPublication) {
          cancelRelease.resolve();
          await publicationEntered.promise;
        }
        failureResponse.resolve();
        await fail(
          { scanId: run.scanId, message: "synthetic no-op failure" },
          {},
        );
        assert.equal(
          (await runWorkbench(["get-scan", "--scan-id", run.scanId])).workspace
            .results.progress.status,
          "canceled",
        );
        assert.equal(
          (await store.get(run.scanId, "fixture-owner")).status,
          "canceled",
        );
        cancelRelease.resolve();
        publicationRelease.resolve();
        if (lostCancellation) {
          await assert.rejects(
            cancellation!,
            /synthetic committed cancellation response lost/,
          );
          await assert.rejects(
            terminal!,
            /synthetic committed cancellation response lost/,
          );
        } else {
          await cancellation;
          const result = await terminal!;
          assert.equal(result.status, "canceled");
          assert.equal(
            result.error,
            (await store.get(run.scanId, "fixture-owner")).error,
          );
          assert.doesNotMatch(result.error ?? "", /synthetic no-op failure/);
        }
        return;
      }
      await cleanupEntered.promise;
      cancellation = cancel({ scanId: run.scanId });
      void cancellation!.catch(() => {});
      await cancelEntered.promise;
      if (ordering !== "lost cancellation response") {
        failure = fail(
          { scanId: run.scanId, message: "synthetic committed parent failure" },
          {},
        );
        void failure!.catch(() => {});
        await failureCommitted.promise;
        assert.equal(
          (
            await runWorkbench([
              "get-deep-scan",
              "--scan-id",
              run.scanId,
              "--thread-id",
              "fixture-owner",
            ])
          ).deepScan.status,
          "succeeded",
        );
        assert.equal(
          (await runWorkbench(["get-scan", "--scan-id", run.scanId])).workspace
            .results.progress.status,
          "failed",
        );
        if (ordering === "failure response first") {
          failureResponse.resolve();
          await failure;
        }
      }
      cancelRelease.resolve();
      cleanupRelease.resolve();
      if (ordering === "lost cancellation response") {
        await assert.rejects(
          cancellation!,
          /synthetic committed cancellation response lost/,
        );
        await assert.rejects(
          terminal!,
          /synthetic committed cancellation response lost/,
        );
        assert.equal(
          (await runWorkbench(["get-scan", "--scan-id", run.scanId])).workspace
            .results.progress.status,
          "canceled",
        );
      } else {
        await assert.rejects(
          cancellation!,
          /Only a running scan can be canceled/,
        );
        const stopped = await terminal!;
        assert.equal(
          stopped.status,
          ordering === "failure response first" ? "failed" : "succeeded",
        );
        if (ordering === "failure response first")
          assert.match(stopped.error!, /synthetic committed parent failure/);
        failureResponse.resolve();
        await failure;
      }
    } finally {
      cleanupRelease.resolve();
      cancelRelease.resolve();
      failureResponse.resolve();
      finishResponse.resolve();
      publicationRelease.resolve();
      registry.shutdown("fixture cleanup");
      await Promise.allSettled([terminal, cancellation, failure]);
      await server?.close();
      Reflect.deleteProperty(globalThis, "terminalRaceFixture");
      await rm(root, { recursive: true, force: true });
    }
  });
}
