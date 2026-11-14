import { fixturePython } from "./support/python.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type {
  DeepScanPublication,
  ScanDraftInput,
} from "../src/artifact-scan-draft.js";
import type { DeepScanRunState } from "../src/deep-scan/types.js";
import { importCoordinatorServer, importModule } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { FakeExecutor, pausePoint } from "./deep_scan_coordinator_fixture.ts";

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

for (const ordering of [
  "cancellation after checkout replacement",
  "failed cleanup with running replacement scan",
  "failed cleanup with terminal replacement scan",
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
    const replacedCheckout =
      ordering === "cancellation after checkout replacement";
    const replacementScan = ordering.endsWith("replacement scan");
    const activeBeforeAdmission =
      replacedCheckout || replacementScan || ordering.endsWith("active worker");
    const canceledBeforeFailure = ordering.includes(
      "cancellation before failure",
    );
    const lostCancellation = ordering.startsWith("lost cancellation");
    const failureDuringPublication = ordering.endsWith("during publication");
    const root = await temporaryDirectory("deep-scan-terminal-race-");
    const registry = new DeepScanCoordinatorRegistry();
    const cleanup = pausePoint();
    const cancelPersistence = pausePoint();
    const failureCommit = pausePoint();
    const finishCommit = pausePoint();
    const admissionRead = Promise.withResolvers<void>();
    const publication = pausePoint();
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
          fixturePython,
          [join(pluginRoot, "scripts", "workbench_db.py"), ...args],
          { cwd: pluginRoot, env: environment },
        );
        return JSON.parse(stdout);
      };
      const workbench = async (args: string[]) => {
        if (args[0] === "cancel-scan" && !canceledBeforeFailure) {
          await cancelPersistence.pause();
        }
        const result = await runWorkbench(args);
        if (
          args[0] === "finish-deep-scan" &&
          canceledBeforeAdmission &&
          !activeBeforeAdmission
        ) {
          await finishCommit.pause();
        }
        if (args[0] === "get-scan" || args[0] === "get-deep-scan")
          admissionRead.resolve();
        if (args[0] === "cancel-scan" && canceledBeforeFailure) {
          await cancelPersistence.pause();
        }
        if (args[0] === "fail-scan") {
          await failureCommit.pause();
        }
        if (args[0] === "cancel-scan" && lostCancellation)
          throw new Error("synthetic committed cancellation response lost");
        return result;
      };
      Object.assign(globalThis, {
        terminalRaceFixture: { registry, workbench },
      });
      const { createCodexSecurityServer } = await importCoordinatorServer(
        "terminalRaceFixture",
      );
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
          await cleanup.pause();
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
        onComplete: async (
          draft: ScanDraftInput,
          signal: AbortSignal,
          publication: DeepScanPublication,
        ) => {
          const context = await createScanArtifactContext(
            run.scanId,
            runWorkbench,
            { requireRunning: true },
          );
          await recordCodexSecurityScanDraftViaWorkbench(
            context,
            draft,
            runWorkbench,
            signal,
            publication,
          );
        },
        onStopped: async (stopped: DeepScanRunState) => {
          if (replacementScan) {
            await cleanup.pause();
          }
          if (failureDuringPublication) {
            await publication.pause();
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
      if (replacementScan) {
        await executor.discoveryStarted.promise;
        const running = await runWorkbench([
          "get-deep-scan",
          "--scan-id",
          run.scanId,
          "--thread-id",
          "fixture-owner",
        ]);
        assert.equal(running.parentScan.status, "running");
        assert.equal(running.workspace, undefined);
        failureCommit.release();
        await fail(
          { scanId: run.scanId, message: "synthetic old failure" },
          { _meta: { "openai/threadId": "fixture-owner" } },
        );
        await cleanup.entered;
        const replacementWorkspace = await runWorkbench([
          "start-scan",
          "--workspace-id",
          running.parentScan.workspaceId,
          "--scan-root",
          join(root, "scans"),
        ]);
        const replacement = { scanId: replacementWorkspace.results.scanId };
        assert.equal(replacementWorkspace.id, running.parentScan.workspaceId);
        assert.notEqual(replacement.scanId, run.scanId);
        if (ordering.includes("terminal replacement"))
          await runWorkbench(["cancel-scan", "--scan-id", replacement.scanId]);
        const replacementBefore = await runWorkbench([
          "get-scan",
          "--scan-id",
          replacement.scanId,
        ]);
        cancelPersistence.release();
        const lateCancellation = cancel({ scanId: run.scanId });
        cancellation = lateCancellation;
        void lateCancellation.catch(() => {});
        cleanup.release();
        const response = await lateCancellation;
        assert.equal(
          response.structuredContent.workspace.results.scanId,
          run.scanId,
        );
        assert.equal(
          response.structuredContent.workspace.results.progress.status,
          "failed",
        );
        assert.equal(
          response.structuredContent.workspace.results.failureMessage,
          "synthetic old failure",
        );
        assert.equal((await terminal!).status, "failed");
        const replacementAfter = await runWorkbench([
          "get-scan",
          "--scan-id",
          replacement.scanId,
        ]);
        assert.deepEqual(
          replacementAfter.workspace.results,
          replacementBefore.workspace.results,
        );
        return;
      }
      if (replacedCheckout) {
        await executor.discoveryStarted.promise;
        await rename(target, `${target}-previous`);
        await mkdir(target);
        await writeFile(join(target, "replacement.py"), "value = 2\n");
        await assert.rejects(
          () => runWorkbench(["get-scan", "--scan-id", run.scanId]),
          /unavailable for the current checkout owner/,
        );
        await assert.rejects(
          () => store.get(run.scanId, "other-owner"),
          /owning Codex thread/,
        );
        cancelPersistence.release();
        const first = cancel({ scanId: run.scanId });
        cancellation = first;
        const joined = cancel({ scanId: run.scanId });
        const responses = await Promise.all([first, joined]);
        assert.equal((await terminal!).status, "canceled");
        assert.equal(executor.runningDiscovery, 0);
        for (const response of responses)
          assert.equal(
            response.structuredContent.workspace.results.progress.status,
            "canceled",
          );
        const after = await runWorkbench([
          "get-deep-scan",
          "--scan-id",
          run.scanId,
          "--thread-id",
          "fixture-owner",
        ]);
        assert.equal(after.parentScan.status, "canceled");
        assert.equal(after.deepScan.status, "canceled");
        return;
      }
      if (canceledBeforeAdmission || failedBeforeAdmission) {
        if (activeBeforeAdmission) await executor.discoveryStarted.promise;
        else await finishCommit.entered;
        await runWorkbench([
          failedBeforeAdmission ? "fail-scan" : "cancel-scan",
          "--scan-id",
          run.scanId,
          ...(failedBeforeAdmission
            ? ["--message", "synthetic externally persisted failure"]
            : []),
        ]);
        cancelPersistence.release();
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
        finishCommit.release();
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
        await cancelPersistence.entered;
        if (failureDuringPublication) {
          cancelPersistence.release();
          await publication.entered;
        }
        failureCommit.release();
        await fail(
          { scanId: run.scanId, message: "synthetic no-op failure" },
          { _meta: { "openai/threadId": "fixture-owner" } },
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
        cancelPersistence.release();
        publication.release();
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
      await cleanup.entered;
      cancellation = cancel({ scanId: run.scanId });
      void cancellation!.catch(() => {});
      await cancelPersistence.entered;
      if (ordering !== "lost cancellation response") {
        failure = fail(
          { scanId: run.scanId, message: "synthetic committed parent failure" },
          { _meta: { "openai/threadId": "fixture-owner" } },
        );
        void failure!.catch(() => {});
        await failureCommit.entered;
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
          failureCommit.release();
          await failure;
        }
      }
      cancelPersistence.release();
      cleanup.release();
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
        failureCommit.release();
        await failure;
      }
    } finally {
      cleanup.release();
      cancelPersistence.release();
      failureCommit.release();
      finishCommit.release();
      publication.release();
      registry.shutdown("fixture cleanup");
      await Promise.allSettled([terminal, cancellation, failure]);
      await server?.close();
      Reflect.deleteProperty(globalThis, "terminalRaceFixture");
      await rm(root, { recursive: true, force: true });
    }
  });
}
