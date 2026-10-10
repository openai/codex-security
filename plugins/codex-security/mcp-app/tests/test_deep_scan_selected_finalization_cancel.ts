import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { importModule } from "./import-module.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.ts";
import type { DeepScanRunState } from "../src/deep-scan/types.ts";
import type { DeepScanPublication } from "../src/artifact-scan-draft.ts";
const appRoot = path.resolve(import.meta.dirname, "..");
const pluginRoot = path.resolve(appRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts/workbench_db.py");
const {
  DeepScanCoordinatorRegistry,
  WorkbenchDeepScanStore,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
  readSelectedDeepScanDraft,
  createDeepScanArtifacts,
  captureDeepScanExecutionSettings,
} = await importModule({
  stdin: {
    contents: `export { captureDeepScanExecutionSettings } from "./src/deep-scan/recovery-settings.ts";
      export { readSelectedDeepScanDraft } from "./src/deep-scan/finalization.ts";
      export { createDeepScanArtifacts } from "./src/deep-scan/artifacts.ts";
      export { DeepScanCoordinatorRegistry } from "./src/deep-scan/registry.ts";
      export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";
      export { createScanArtifactContext } from "./src/artifact-context.ts";
      export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";`,
    resolveDir: appRoot,
  },
  loader: { ".md": "text" },
});
for (const phase of [
  "draft",
  "parent",
  "resumed-parent",
  "completed",
] as const) {
  test(`real saved native scan cancellation during selected ${phase}`, async () => {
    const root = await temporaryDirectory("real-detached-cancel-", true);
    const home = path.join(root, "codex-home");
    const target = path.join(root, "target");
    const environment = {
      ...process.env,
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
    };
    await mkdir(target, { recursive: true });
    await writeFile(path.join(target, "fixture.py"), "print('fixture')\n");
    await mkdir(path.join(home, "codex-security"), { recursive: true });
    await writeFile(
      path.join(home, "codex-security/config.toml"),
      "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = 1e-12\n",
    );
    const runWorkbench = async (
      args: string[],
      input?: string,
      selection = false,
      withSettings = false,
      signal?: AbortSignal,
      releaseCoordinator = false,
    ) => {
      const invocation = releaseCoordinator
        ? "release_coordinator=True"
        : selection
          ? "select_finalization=True"
          : withSettings
            ? "with_execution_settings=True"
            : undefined;
      const pythonArgs = invocation
        ? [
            "-c",
            `import runpy, sys; script = sys.argv.pop(1); runpy.run_path(script)['main'](${invocation})`,
            workbenchPath,
            ...args,
          ]
        : [workbenchPath, ...args];
      return await new Promise<any>((resolve, reject) => {
        const child = spawn(process.env.PYTHON || "python3", pythonArgs, {
          cwd: pluginRoot,
          env: environment,
          signal,
        });
        const stdout: Buffer[] = [],
          stderr: Buffer[] = [];
        child.stdout.on("data", (data: Buffer) => stdout.push(data));
        child.stderr.on("data", (data: Buffer) => stderr.push(data));
        child.on("error", reject);
        child.on("close", (code) =>
          code === 0
            ? resolve(JSON.parse(Buffer.concat(stdout).toString()))
            : reject(new Error(Buffer.concat(stderr).toString())),
        );
        child.stdin.end(input);
      });
    };
    try {
      let store = new WorkbenchDeepScanStore(runWorkbench);
      const threadId = "real-selected-owner";
      const executionSettings = await captureDeepScanExecutionSettings(
        {},
        { filesystemDenies: [] },
        environment,
      );
      const begun = await store.begin({
        targetPath: target,
        scope: ".",
        threadId,
        scanRoot: path.join(root, "scans"),
        executionSettings,
      });
      const claimed = await store.claimCoordinator({
        scanId: begun.scanId,
        threadId,
      });
      assert.equal(claimed.acquired, true);
      let selected = await store.selectFinalization({
        scanId: begun.scanId,
        coordinatorGeneration: claimed.run.coordinatorGeneration,
        reason: "capped",
        manifestPath: path.join(begun.scanDir, "scan-manifest.json"),
        omittedWorkerIds: [],
      });
      assert.equal(selected.status, "running");
      assert.equal(selected.finalizationInput.resultPath, null);
      if (phase === "resumed-parent") {
        const context = await createScanArtifactContext(
          begun.scanId,
          runWorkbench,
          { requireRunning: true, pluginRoot },
        );
        const draft = await readSelectedDeepScanDraft(
          createDeepScanArtifacts(begun.scanDir),
          begun.scanId,
          selected.finalizationInput,
        );
        await recordCodexSecurityScanDraftViaWorkbench(
          context,
          draft,
          runWorkbench,
          undefined,
          {
            coordinatorGeneration: selected.coordinatorGeneration,
            resultPath: null,
          },
        );
        await store.finish({
          scanId: begun.scanId,
          reason: "capped",
          manifestPath: path.join(begun.scanDir, "scan-manifest.json"),
          omittedWorkerIds: [],
        });
        await store.releaseCoordinator(begun.scanId);
        store = new WorkbenchDeepScanStore(runWorkbench);
        const resumed = await store.claimCoordinator({
          scanId: begun.scanId,
          threadId,
        });
        assert.equal(resumed.acquired, true);
        selected = resumed.run;
        assert.equal(
          selected.status,
          "succeeded",
          "the resumed Deep result is committed while its parent is still running",
        );
      }
      const blocked = Promise.withResolvers<void>(),
        release = Promise.withResolvers<void>();
      const observer = new AbortController();
      let writes = 0,
        seals = 0;
      let publicationSignal: AbortSignal | undefined;
      const pause = async (signal: AbortSignal) => {
        publicationSignal = signal;
        blocked.resolve();
        await release.promise;
        signal.throwIfAborted();
      };
      const registry = new DeepScanCoordinatorRegistry();
      const coordinator = registry.start({
        run: selected,
        store,
        pluginRoot,
        threadId,
        executor: {
          run: async () =>
            assert.fail("Accepted selection cannot launch new model work"),
        },
        onComplete: async (
          draft: ScanDraftInput,
          signal: AbortSignal,
          publication: DeepScanPublication,
        ) => {
          if (phase === "draft") await pause(signal);
          const context = await createScanArtifactContext(
            begun.scanId,
            runWorkbench,
            { requireRunning: true, requireClaim: true, pluginRoot },
          );
          await recordCodexSecurityScanDraftViaWorkbench(
            context,
            draft,
            runWorkbench,
            signal,
            publication,
          );
        },
        onFinalized: async (run: DeepScanRunState, signal: AbortSignal) => {
          if (!observer.signal.aborted) return;
          if (phase === "parent" || phase === "resumed-parent")
            await pause(signal);
          await runWorkbench(
            ["complete-scan", "--scan-id", run.scanId, "--thread-id", threadId],
            undefined,
            false,
            false,
            signal,
          );
          seals++;
        },
      });
      const settled = coordinator.settled();
      settled.catch(() => {});
      const detached = coordinator.wait(observer.signal);
      observer.abort();
      await assert.rejects(detached, { name: "AbortError" });
      const persist = async () => {
        writes++;
        await runWorkbench([
          "cancel-scan",
          "--scan-id",
          begun.scanId,
          "--thread-id",
          threadId,
        ]);
      };
      if (phase === "completed") {
        await settled;
        const before = await readFile(
          path.join(begun.scanDir, "scan-manifest.json"),
        );
        assert.equal(
          await registry.cancelAndWait(
            begun.scanId,
            "user_canceled_scan",
            persist,
          ),
          false,
        );
        await assert.rejects(persist(), /Only a running scan can be canceled/);
        const saved = await runWorkbench([
          "get-scan",
          "--scan-id",
          begun.scanId,
        ]);
        assert.equal(saved.scan.progress.status, "complete");
        assert.deepEqual(
          await readFile(path.join(begun.scanDir, "scan-manifest.json")),
          before,
        );
        assert.equal(seals, 1);
        return;
      }
      await blocked.promise;
      const cancellation = registry.cancelAndWait(
        begun.scanId,
        "user_canceled_scan",
        persist,
      );
      const aborted = publicationSignal?.aborted;
      release.resolve();
      assert.equal(await cancellation, true);
      await settled;
      // Match cancelSecurityScan: closed parents are observed; running ones cancel directly.
      const saved = await runWorkbench(["get-scan", "--scan-id", begun.scanId]);
      if (saved.scan.progress.status === "running") await persist();
      const final = await runWorkbench(["get-scan", "--scan-id", begun.scanId]);
      assert.equal(
        aborted,
        true,
        "cancel must reach the active parent publication signal",
      );
      assert.equal(final.scan.progress.status, "canceled");
      assert.equal(writes, 1);
      assert.equal(seals, 0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
